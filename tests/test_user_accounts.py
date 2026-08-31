"""Tests utils/user_accounts.py's user/session store directly — password
hashing/verification correctness, session issuance/validation/expiry,
and per-tenant isolation, independent of the API routes that will wire
this in."""

import itertools

import pytest

from utils.user_accounts import (
    change_role,
    create_session,
    create_user,
    delete_user,
    has_any_users,
    invalidate_session,
    list_users,
    reset_for_tests,
    validate_session,
    verify_password,
)

_tenant_counter = itertools.count()


@pytest.fixture
def tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    # A real PBKDF2-SHA256 hash at the production default (600,000
    # iterations) takes ~0.3-0.4s -- correct and deliberate for a real
    # login, but unnecessary cost across dozens of test cases that only
    # care about correctness, not the actual security margin. A
    # dedicated test below (test_production_default_iteration_count)
    # covers the real default explicitly.
    monkeypatch.setenv("CAVENDEX_PASSWORD_HASH_ITERATIONS", "1000")
    reset_for_tests()
    yield f"accounts-test-{next(_tenant_counter)}"
    reset_for_tests()


def test_production_default_iteration_count(monkeypatch):
    monkeypatch.delenv("CAVENDEX_PASSWORD_HASH_ITERATIONS", raising=False)
    import utils.user_accounts as ua

    assert ua._iterations() == 600000


# ---------- create_user / validation ----------


def test_create_user_defaults_to_analyst_role(tenant):
    user = create_user(tenant, "alice", "correct-horse-battery")
    assert user == {"username": "alice", "role": "analyst", "created_at": user["created_at"]}


def test_create_user_accepts_admin_role(tenant):
    user = create_user(tenant, "bob", "correct-horse-battery", role="admin")
    assert user["role"] == "admin"


def test_create_user_rejects_duplicate_username(tenant):
    create_user(tenant, "alice", "correct-horse-battery")
    with pytest.raises(ValueError, match="already exists"):
        create_user(tenant, "alice", "another-password")


def test_create_user_rejects_short_password(tenant):
    with pytest.raises(ValueError, match="at least"):
        create_user(tenant, "alice", "short")


def test_create_user_rejects_empty_username(tenant):
    with pytest.raises(ValueError):
        create_user(tenant, "", "correct-horse-battery")


def test_create_user_rejects_invalid_role(tenant):
    with pytest.raises(ValueError, match="role"):
        create_user(tenant, "alice", "correct-horse-battery", role="superuser")


# ---------- verify_password ----------


def test_verify_password_succeeds_with_correct_password(tenant):
    create_user(tenant, "alice", "correct-horse-battery")
    result = verify_password(tenant, "alice", "correct-horse-battery")
    assert result == {"username": "alice", "role": "analyst"}


def test_verify_password_fails_with_wrong_password(tenant):
    create_user(tenant, "alice", "correct-horse-battery")
    assert verify_password(tenant, "alice", "wrong-password") is None


def test_verify_password_fails_for_unknown_username(tenant):
    assert verify_password(tenant, "nobody", "whatever-password") is None


def test_password_hash_is_never_stored_in_plaintext(tenant, monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    create_user(tenant, "alice", "correct-horse-battery")

    import utils.user_accounts as ua

    conn = ua._get_connection(tenant)
    stored = conn.execute("SELECT password_hash FROM users WHERE username = ?", ("alice",)).fetchone()[0]
    assert "correct-horse-battery" not in stored
    assert stored.startswith("pbkdf2_sha256$")


# ---------- list_users / has_any_users / delete_user / change_role ----------


def test_has_any_users_false_when_empty(tenant):
    assert has_any_users(tenant) is False


def test_has_any_users_true_after_creating_one(tenant):
    create_user(tenant, "alice", "correct-horse-battery")
    assert has_any_users(tenant) is True


def test_list_users_never_includes_password_hash(tenant):
    create_user(tenant, "alice", "correct-horse-battery")
    users = list_users(tenant)
    assert users == [{"username": "alice", "role": "analyst", "created_at": users[0]["created_at"]}]
    assert "password_hash" not in users[0]
    assert "password" not in users[0]


def test_delete_user_removes_them_and_returns_true(tenant):
    create_user(tenant, "alice", "correct-horse-battery")
    assert delete_user(tenant, "alice") is True
    assert has_any_users(tenant) is False


def test_delete_unknown_user_returns_false(tenant):
    assert delete_user(tenant, "nobody") is False


def test_delete_user_also_invalidates_their_sessions(tenant):
    create_user(tenant, "alice", "correct-horse-battery")
    session = create_session(tenant, "alice", "analyst")
    delete_user(tenant, "alice")
    assert validate_session(tenant, session["token"]) is None


def test_change_role_updates_the_stored_role(tenant):
    create_user(tenant, "alice", "correct-horse-battery")
    assert change_role(tenant, "alice", "admin") is True
    assert verify_password(tenant, "alice", "correct-horse-battery")["role"] == "admin"


def test_change_role_rejects_invalid_role(tenant):
    create_user(tenant, "alice", "correct-horse-battery")
    with pytest.raises(ValueError):
        change_role(tenant, "alice", "superuser")


def test_change_role_updates_existing_sessions_too(tenant):
    """A role change should apply to an already-issued session, not just
    future logins -- otherwise revoking admin access wouldn't actually
    take effect until the user's session expired on its own."""
    create_user(tenant, "alice", "correct-horse-battery", role="admin")
    session = create_session(tenant, "alice", "admin")
    change_role(tenant, "alice", "analyst")
    assert validate_session(tenant, session["token"])["role"] == "analyst"


# ---------- sessions ----------


def test_create_and_validate_session(tenant):
    session = create_session(tenant, "alice", "analyst")
    assert "token" in session and len(session["token"]) > 20
    result = validate_session(tenant, session["token"])
    assert result == {"username": "alice", "role": "analyst"}


def test_validate_session_rejects_unknown_token(tenant):
    assert validate_session(tenant, "not-a-real-token") is None


def test_validate_session_rejects_empty_token(tenant):
    assert validate_session(tenant, "") is None


def test_session_token_is_never_stored_in_plaintext(tenant, monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    session = create_session(tenant, "alice", "analyst")

    import utils.user_accounts as ua

    conn = ua._get_connection(tenant)
    stored = conn.execute("SELECT token_hash FROM sessions").fetchall()
    assert all(session["token"] != row[0] for row in stored)


def test_expired_session_is_rejected(tenant, monkeypatch):
    monkeypatch.setenv("CAVENDEX_SESSION_TTL_SECONDS", "0")
    session = create_session(tenant, "alice", "analyst")
    assert validate_session(tenant, session["token"]) is None


def test_invalidate_session_logs_out(tenant):
    session = create_session(tenant, "alice", "analyst")
    invalidate_session(tenant, session["token"])
    assert validate_session(tenant, session["token"]) is None


def test_invalidate_unknown_session_is_a_safe_no_op(tenant):
    invalidate_session(tenant, "not-a-real-token")  # must not raise


# ---------- per-tenant isolation ----------


def test_users_are_isolated_per_tenant(tenant, monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    other_tenant = f"{tenant}-other"
    create_user(tenant, "alice", "correct-horse-battery")
    assert has_any_users(other_tenant) is False
    assert verify_password(other_tenant, "alice", "correct-horse-battery") is None


def test_sessions_are_isolated_per_tenant(tenant, monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    other_tenant = f"{tenant}-other"
    session = create_session(tenant, "alice", "analyst")
    assert validate_session(other_tenant, session["token"]) is None
