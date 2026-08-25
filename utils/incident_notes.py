"""Freeform analyst notes on an incident — separate from `audit_log`
(agent/system-generated, append-only, part of the actual incident
record) and separate from `state.py`'s `Incident`/`SentinelState`
entirely. A note is commentary an analyst adds ("checked with the user,
this login was expected"), not part of the pipeline's own decision
trail — keeping it in its own small per-tenant SQLite table (the same
"small file, not a system" pattern as `utils/incident_index.py`) means
adding this never touches the core state schema, every agent file, or
the checkpoint LangGraph itself relies on.

Like `approved_by`, the author here is an analyst-typed label, not an
authenticated identity — see README Known Gaps: no per-user accounts.
"""

import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import List, Optional

from graph import tenant_data_dir
from utils.tenancy import DEFAULT_TENANT, sanitize_tenant_id

_lock = threading.Lock()
_connections: dict = {}

_MAX_NOTES_PER_INCIDENT = 200
_MAX_NOTE_LENGTH = 2000


def _get_connection(tenant_id: str) -> sqlite3.Connection:
    tenant_id = sanitize_tenant_id(tenant_id)

    if tenant_id in _connections:
        return _connections[tenant_id]

    with _lock:
        if tenant_id in _connections:
            return _connections[tenant_id]

        tenant_dir = tenant_data_dir(tenant_id)
        os.makedirs(tenant_dir, exist_ok=True)
        db_path = os.path.join(tenant_dir, "incident_notes.db")

        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                thread_id TEXT NOT NULL,
                author TEXT,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notes_thread_id ON notes(thread_id)")
        conn.commit()
        _connections[tenant_id] = conn
        return conn


def add_note(tenant_id: str, thread_id: str, text: str, author: Optional[str] = None) -> dict:
    """Adds one note. `text` is truncated to a sane length and `author`
    recorded honestly as None (rendered "unspecified" by callers) rather
    than a generic placeholder if not given — the same pattern
    `approved_by` already established.
    """
    text = (text or "").strip()[:_MAX_NOTE_LENGTH]
    if not text:
        raise ValueError("Note text cannot be empty")

    conn = _get_connection(tenant_id)
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        cursor = conn.execute(
            "INSERT INTO notes (thread_id, author, text, created_at) VALUES (?, ?, ?, ?)",
            (thread_id, author, text, now),
        )
        conn.commit()
        note_id = cursor.lastrowid
    return {"id": note_id, "thread_id": thread_id, "author": author, "text": text, "created_at": now}


def list_notes(tenant_id: str, thread_id: str) -> List[dict]:
    conn = _get_connection(tenant_id)
    cursor = conn.execute(
        "SELECT id, thread_id, author, text, created_at FROM notes WHERE thread_id = ? "
        "ORDER BY created_at ASC LIMIT ?",
        (thread_id, _MAX_NOTES_PER_INCIDENT),
    )
    columns = [d[0] for d in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def reset_for_tests() -> None:
    with _lock:
        for conn in _connections.values():
            conn.close()
        _connections.clear()
