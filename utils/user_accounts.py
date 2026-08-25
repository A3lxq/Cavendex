"""Real per-tenant user accounts and server-side dashboard sessions —
closing the gap README's Known Gaps has stated plainly since the
dashboard shipped: "no per-user accounts... the dashboard's auth is one
shared key for everyone using it." A tenant's `SENTINELOS_API_KEY`/
`SENTINELOS_TENANT_API_KEYS` credential still works exactly as before
(unchanged, and still treated as an implicit admin credential — see
api.py's `require_admin`) — this is an *additional*, opt-in identity
layer specifically for a human logging into the dashboard, replacing
the freely-typed, unauthenticated "Analyst name" field with a real
login when an operator chooses to set one up.

"Small file, not a system" — the same philosophy as
utils/incident_index.py and utils/incident_notes.py: one small SQLite
file per tenant (`user_accounts.db`), two tables (`users`, `sessions`),
no separate service.

Passwords are hashed with PBKDF2-HMAC-SHA256 (stdlib `hashlib`, no new
dependency for something the standard library already does correctly) —
a random per-user salt, a high iteration count
(SENTINELOS_PASSWORD_HASH_ITERATIONS, default 600,000, roughly OWASP's
2023 PBKDF2-SHA256 guidance), stored in a self-describing
`pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>` format so a future
iteration-count bump never invalidates hashes created under the old one.

Session tokens are high-entropy random strings (`secrets.token_urlsafe`)
that exist in plaintext only once — the moment they're issued to the
caller. The database only ever stores a SHA-256 hash of the token, the
same reasoning passwords are never stored in plaintext: a leaked
sessions table alone can't be replayed as working credentials.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from graph import tenant_data_dir
from utils.tenancy import sanitize_tenant_id

_lock = threading.Lock()
_connections: dict = {}

_VALID_ROLES = ("analyst", "admin")
_MIN_PASSWORD_LENGTH = 8
_MAX_USERNAME_LENGTH = 100


def _get_connection(tenant_id: str) -> sqlite3.Connection:
    tenant_id = sanitize_tenant_id(tenant_id)

    if tenant_id in _connections:
        return _connections[tenant_id]

    with _lock:
        if tenant_id in _connections:
            return _connections[tenant_id]

        tenant_dir = tenant_data_dir(tenant_id)
        os.makedirs(tenant_dir, exist_ok=True)
        db_path = os.path.join(tenant_dir, "user_accounts.db")

        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
        _connections[tenant_id] = conn
        return conn


def _iterations() -> int:
    try:
        return int(os.getenv("SENTINELOS_PASSWORD_HASH_ITERATIONS", "600000"))
    except ValueError:
        return 600000


def _hash_password(password: str, iterations: Optional[int] = None) -> str:
    iterations = _iterations() if iterations is None else iterations
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations_str, salt_hex, digest_hex = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, AttributeError):
        return False

    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations_str))
    return hmac.compare_digest(candidate, expected)


# A fixed, precomputed hash checked when a username doesn't exist at all —
# so verify_password() spends roughly the same PBKDF2 work either way,
# narrowing (not eliminating; network/scheduling jitter dwarfs this) the
# timing gap between "wrong password" and "no such user" that a real
# attacker could otherwise use to enumerate valid usernames.
_DUMMY_HASH = _hash_password(secrets.token_urlsafe(32), iterations=600000)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_user(tenant_id: str, username: str, password: str, role: str = "analyst") -> dict:
    """Creates a new user for this tenant. Raises ValueError for an
    empty/oversized username, too-short a password, an unrecognized
    role, or a username that already exists — a caller (the API/CLI)
    turns that into the appropriate 400/409, not a 500.
    """
    username = (username or "").strip()
    if not username or len(username) > _MAX_USERNAME_LENGTH:
        raise ValueError(f"username must be 1-{_MAX_USERNAME_LENGTH} characters")
    if role not in _VALID_ROLES:
        raise ValueError(f"role must be one of {_VALID_ROLES}")
    if len(password or "") < _MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {_MIN_PASSWORD_LENGTH} characters")

    conn = _get_connection(tenant_id)
    now = datetime.now(timezone.utc).isoformat()
    password_hash = _hash_password(password)

    with _lock:
        existing = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            raise ValueError(f"user {username!r} already exists")
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, now),
        )
        conn.commit()

    return {"username": username, "role": role, "created_at": now}


def verify_password(tenant_id: str, username: str, password: str) -> Optional[dict]:
    """Returns {"username", "role"} if `password` is correct for
    `username` in this tenant, else None — never raises, and never
    distinguishes "no such user" from "wrong password" in its return
    value (both are just None), the same "don't tell an attacker which
    half was wrong" principle as any real login form.
    """
    conn = _get_connection(tenant_id)
    row = conn.execute(
        "SELECT password_hash, role FROM users WHERE username = ?", (username,)
    ).fetchone()

    if row is None:
        _verify_password(password, _DUMMY_HASH)  # spend comparable time; see _DUMMY_HASH above
        return None

    password_hash, role = row
    if not _verify_password(password, password_hash):
        return None
    return {"username": username, "role": role}


def list_users(tenant_id: str) -> List[dict]:
    conn = _get_connection(tenant_id)
    cursor = conn.execute("SELECT username, role, created_at FROM users ORDER BY username ASC")
    columns = [d[0] for d in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def has_any_users(tenant_id: str) -> bool:
    conn = _get_connection(tenant_id)
    return conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def delete_user(tenant_id: str, username: str) -> bool:
    """Deletes the user and every one of their active sessions. Returns
    False if no such user existed (not an error — deleting something
    already gone is idempotent)."""
    conn = _get_connection(tenant_id)
    with _lock:
        cursor = conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
        conn.commit()
    return cursor.rowcount > 0


def change_role(tenant_id: str, username: str, role: str) -> bool:
    if role not in _VALID_ROLES:
        raise ValueError(f"role must be one of {_VALID_ROLES}")
    conn = _get_connection(tenant_id)
    with _lock:
        cursor = conn.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
        conn.execute("UPDATE sessions SET role = ? WHERE username = ?", (role, username))
        conn.commit()
    return cursor.rowcount > 0


def _session_ttl_seconds() -> float:
    try:
        return float(os.getenv("SENTINELOS_SESSION_TTL_SECONDS", "28800"))  # 8 hours
    except ValueError:
        return 28800.0


def create_session(tenant_id: str, username: str, role: str) -> dict:
    """Issues a new session token — the raw value is returned here and
    only here; only its SHA-256 hash is ever persisted. Returns
    {"token", "expires_at"}.
    """
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=_session_ttl_seconds())

    conn = _get_connection(tenant_id)
    with _lock:
        conn.execute(
            "INSERT INTO sessions (token_hash, username, role, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (_hash_token(token), username, role, now.isoformat(), expires_at.isoformat()),
        )
        conn.commit()

    return {"token": token, "expires_at": expires_at.isoformat()}


def validate_session(tenant_id: str, token: str) -> Optional[dict]:
    """Returns {"username", "role"} for a real, non-expired session, or
    None for anything else (unknown token, expired token, or `token`
    that's actually this tenant's static API key rather than a real
    session — the two are visually indistinguishable bearer strings, so
    this simply won't find a match in the sessions table for one). Never
    raises — a lookup miss is an ordinary, expected outcome for most
    callers (most bearer tokens presented to this function are the
    static API key, not a session).
    """
    if not token:
        return None
    conn = _get_connection(tenant_id)
    row = conn.execute(
        "SELECT username, role, expires_at FROM sessions WHERE token_hash = ?", (_hash_token(token),)
    ).fetchone()
    if row is None:
        return None

    username, role, expires_at = row
    if datetime.fromisoformat(expires_at) < datetime.now(timezone.utc):
        with _lock:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(token),))
            conn.commit()
        return None

    return {"username": username, "role": role}


def invalidate_session(tenant_id: str, token: str) -> None:
    """Logout — deletes this one session. Idempotent: invalidating an
    already-invalid/unknown token is a no-op, not an error.
    """
    if not token:
        return
    conn = _get_connection(tenant_id)
    with _lock:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(token),))
        conn.commit()


def reset_for_tests() -> None:
    with _lock:
        for conn in _connections.values():
            conn.close()
        _connections.clear()
