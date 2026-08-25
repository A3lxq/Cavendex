"""Tests the /auth/* routes (login, logout, me, user management) against
a real HTTP request/response cycle via TestClient, and their integration
with the existing require_api_key/require_tenant_api_key auth gates and
approve/deny's approved_by auto-fill. Real PBKDF2 hashing throughout
(SENTINELOS_PASSWORD_HASH_ITERATIONS lowered for test speed, the same
"correctness over the real security margin" tradeoff test_user_accounts.py
makes)."""

import itertools

import pytest
from fastapi.testclient import TestClient

from api import api
from graph import get_app
from state import Incident, ProposedAction
from utils.auth_monitor import reset_for_tests as reset_auth_monitor
from utils.rate_limit import reset_for_tests as reset_rate_limit
from utils.tenancy import DEFAULT_TENANT
from utils.user_accounts import delete_user, list_users, reset_for_tests as reset_user_accounts

client = TestClient(api)
_tenant_counter = itertools.count()


def _tenant():
    return f"accounts-api-test-{next(_tenant_counter)}"


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setenv("SENTINELOS_PASSWORD_HASH_ITERATIONS", "1000")
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.delenv("SENTINELOS_TENANT_API_KEYS", raising=False)
    reset_auth_monitor()
    reset_rate_limit()
    reset_user_accounts()
    yield
    # DEFAULT_TENANT's user_accounts.db is a real file shared across the
    # whole test session (see conftest.py) -- explicitly delete anything
    # created against it so later tests (e.g. test_api_auth.py's "no key
    # configured -> unauthenticated" case) see a clean, user-free default
    # tenant regardless of test order. Tenant-scoped tests below use a
    # unique tenant name instead and don't need this.
    for user in list_users(DEFAULT_TENANT):
        delete_user(DEFAULT_TENANT, user["username"])
    reset_auth_monitor()
    reset_rate_limit()
    reset_user_accounts()


def _seed_pending_incident(tenant_id, thread_id="inc-1"):
    app = get_app(tenant_id)
    config = {"configurable": {"thread_id": thread_id}}
    app.update_state(
        config,
        {
            "messages": [],
            "incident": Incident(id=thread_id, description="x", severity="high", status="pending_approval"),
            "long_term_summary": "",
            "audit_log": [],
            "next_agent": None,
            "proposed_actions": [ProposedAction(action="block", target="1.2.3.4", rationale="r")],
            "token_usage": {},
            "tenant_id": tenant_id,
            "threat_intel": [],
            "attack_technique": None,
        },
    )


# ---------- login (default tenant) ----------


def test_login_bootstraps_via_api_key_then_succeeds():
    """No API key configured, no users yet -> create the first user via
    the (currently wide-open) admin-gated route, then log in as them."""
    response = client.post("/auth/users", json={"username": "alice", "password": "correct-horse-battery"})
    assert response.status_code == 200

    response = client.post("/auth/login", json={"username": "alice", "password": "correct-horse-battery"})
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "alice"
    assert body["role"] == "analyst"
    assert len(body["token"]) > 20


def test_login_rejects_wrong_password():
    client.post("/auth/users", json={"username": "alice", "password": "correct-horse-battery"})
    response = client.post("/auth/login", json={"username": "alice", "password": "wrong-password"})
    assert response.status_code == 401


def test_login_rejects_unknown_user():
    response = client.post("/auth/login", json={"username": "nobody", "password": "whatever-password"})
    assert response.status_code == 401


def test_login_is_rate_limited(monkeypatch):
    monkeypatch.setenv("SENTINELOS_LOGIN_RATE_LIMIT_PER_MINUTE", "2")
    client.post("/auth/users", json={"username": "alice", "password": "correct-horse-battery"})

    client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    response = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert response.status_code == 429


# ---------- session used as a bearer credential ----------


def test_session_token_authenticates_a_protected_route():
    client.post("/auth/users", json={"username": "alice", "password": "correct-horse-battery"})
    login = client.post("/auth/login", json={"username": "alice", "password": "correct-horse-battery"})
    token = login.json()["token"]

    response = client.get("/incidents/does-not-exist", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404  # authenticated, just no such incident -- not 401


def test_creating_a_user_does_not_lock_out_unauthenticated_access_by_default():
    """Creating a user account must never, by itself, flip a tenant from
    open to auth-required for everyone else -- that would silently
    change the tenant's security posture the moment one analyst sets up
    a login purely for its accountability benefit (a real identity
    auto-filling approved_by), the exact "surprise" every other opt-in
    feature in this project goes out of its way to avoid."""
    client.post("/auth/users", json={"username": "alice", "password": "correct-horse-battery"})

    response = client.get("/incidents/does-not-exist")
    assert response.status_code == 404  # still open -- not 401


def test_require_login_opts_into_enforcement_once_a_user_exists(monkeypatch):
    """SENTINELOS_REQUIRE_LOGIN=true is the explicit opt-in for an
    operator who *does* want account creation itself to gate access."""
    monkeypatch.setenv("SENTINELOS_REQUIRE_LOGIN", "true")
    client.post("/auth/users", json={"username": "alice", "password": "correct-horse-battery"})

    response = client.get("/incidents/does-not-exist")
    assert response.status_code == 401


def test_require_login_has_no_effect_without_any_users(monkeypatch):
    monkeypatch.setenv("SENTINELOS_REQUIRE_LOGIN", "true")
    response = client.get("/incidents/does-not-exist")
    assert response.status_code == 404


def test_me_reports_session_identity():
    client.post("/auth/users", json={"username": "alice", "password": "correct-horse-battery"})
    login = client.post("/auth/login", json={"username": "alice", "password": "correct-horse-battery"})
    token = login.json()["token"]

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.json() == {"authenticated_via": "session", "username": "alice", "role": "analyst"}


def test_me_reports_api_key_when_not_a_session(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    response = client.get("/auth/me", headers={"Authorization": "Bearer secret-key-123"})
    assert response.json() == {"authenticated_via": "api_key", "username": None, "role": None}


def test_logout_invalidates_the_session(monkeypatch):
    # SENTINELOS_REQUIRE_LOGIN so an invalidated token is actually
    # rejected rather than the request just falling through to this
    # (otherwise open-by-default) tenant's unauthenticated access.
    monkeypatch.setenv("SENTINELOS_REQUIRE_LOGIN", "true")
    client.post("/auth/users", json={"username": "alice", "password": "correct-horse-battery"})
    login = client.post("/auth/login", json={"username": "alice", "password": "correct-horse-battery"})
    token = login.json()["token"]

    logout = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout.status_code == 200

    response = client.get("/incidents/does-not-exist", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


# ---------- admin gating ----------


def test_non_admin_session_cannot_create_users():
    client.post("/auth/users", json={"username": "alice", "password": "correct-horse-battery", "role": "analyst"})
    login = client.post("/auth/login", json={"username": "alice", "password": "correct-horse-battery"})
    token = login.json()["token"]

    response = client.post(
        "/auth/users",
        json={"username": "bob", "password": "another-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_admin_session_can_create_users():
    client.post("/auth/users", json={"username": "root", "password": "correct-horse-battery", "role": "admin"})
    login = client.post("/auth/login", json={"username": "root", "password": "correct-horse-battery"})
    token = login.json()["token"]

    response = client.post(
        "/auth/users",
        json={"username": "bob", "password": "another-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200


def test_api_key_can_manage_users_even_with_no_session(monkeypatch):
    """The static API key is an implicit superuser, consistent with the
    fact that it already authorizes every other route -- and is the
    only way to bootstrap a tenant's very first admin account."""
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    response = client.post(
        "/auth/users",
        json={"username": "alice", "password": "correct-horse-battery"},
        headers={"Authorization": "Bearer secret-key-123"},
    )
    assert response.status_code == 200


def _bootstrap_admin_token():
    """Creates the tenant's first user as admin (allowed unauthenticated
    -- see test_creating_any_user_requires_auth_even_without_an_api_key_configured
    for why that's only true for the very first one) and logs them in,
    since every call after that first one requires real credentials."""
    client.post("/auth/users", json={"username": "root", "password": "correct-horse-battery", "role": "admin"})
    login = client.post("/auth/login", json={"username": "root", "password": "correct-horse-battery"})
    return login.json()["token"]


def test_list_users_never_leaks_password_hash():
    token = _bootstrap_admin_token()
    response = client.get("/auth/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    users = response.json()
    assert users == [{"username": "root", "role": "admin", "created_at": users[0]["created_at"]}]


def test_delete_user_route():
    token = _bootstrap_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/auth/users", json={"username": "alice", "password": "correct-horse-battery"}, headers=headers)
    response = client.delete("/auth/users/alice", headers=headers)
    assert response.status_code == 200
    assert {u["username"] for u in client.get("/auth/users", headers=headers).json()} == {"root"}


def test_delete_unknown_user_returns_404():
    token = _bootstrap_admin_token()
    response = client.delete("/auth/users/nobody", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404


def test_change_role_route():
    token = _bootstrap_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/auth/users", json={"username": "alice", "password": "correct-horse-battery"}, headers=headers)
    response = client.patch("/auth/users/alice/role", json={"role": "admin"}, headers=headers)
    assert response.status_code == 200
    roles = {u["username"]: u["role"] for u in client.get("/auth/users", headers=headers).json()}
    assert roles["alice"] == "admin"


def test_create_user_rejects_short_password():
    response = client.post("/auth/users", json={"username": "alice", "password": "short"})
    assert response.status_code == 400


def test_create_duplicate_user_returns_400():
    token = _bootstrap_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/auth/users", json={"username": "alice", "password": "correct-horse-battery"}, headers=headers)
    response = client.post("/auth/users", json={"username": "alice", "password": "another-one"}, headers=headers)
    assert response.status_code == 400


# ---------- approved_by auto-fill from a real session ----------


def test_approve_auto_fills_approved_by_from_session():
    tenant = _tenant()
    client.post(f"/tenants/{tenant}/auth/users", json={"username": "alice", "password": "correct-horse-battery"})
    login = client.post(f"/tenants/{tenant}/auth/login", json={"username": "alice", "password": "correct-horse-battery"})
    token = login.json()["token"]

    _seed_pending_incident(tenant)
    response = client.post(
        f"/tenants/{tenant}/incidents/inc-1/approve", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["proposed_actions"][0]["approved_by"] == "alice"


def test_approve_explicit_approved_by_overrides_session_identity():
    tenant = _tenant()
    client.post(f"/tenants/{tenant}/auth/users", json={"username": "alice", "password": "correct-horse-battery"})
    login = client.post(f"/tenants/{tenant}/auth/login", json={"username": "alice", "password": "correct-horse-battery"})
    token = login.json()["token"]

    _seed_pending_incident(tenant)
    response = client.post(
        f"/tenants/{tenant}/incidents/inc-1/approve",
        json={"approved_by": "someone-else"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.json()["proposed_actions"][0]["approved_by"] == "someone-else"


def test_approve_without_a_session_still_defaults_to_unspecified():
    tenant = _tenant()
    _seed_pending_incident(tenant)
    response = client.post(f"/tenants/{tenant}/incidents/inc-1/approve")
    assert response.json()["proposed_actions"][0]["approved_by"] is None


# ---------- tenant isolation ----------


def test_login_is_scoped_to_its_own_tenant():
    tenant_a = _tenant()
    tenant_b = _tenant()
    client.post(f"/tenants/{tenant_a}/auth/users", json={"username": "alice", "password": "correct-horse-battery"})

    response = client.post(f"/tenants/{tenant_b}/auth/login", json={"username": "alice", "password": "correct-horse-battery"})
    assert response.status_code == 401


def test_session_from_one_tenant_does_not_authenticate_another(monkeypatch):
    tenant_a = _tenant()
    tenant_b = _tenant()
    client.post(f"/tenants/{tenant_a}/auth/users", json={"username": "alice", "password": "correct-horse-battery"})
    login = client.post(f"/tenants/{tenant_a}/auth/login", json={"username": "alice", "password": "correct-horse-battery"})
    token = login.json()["token"]

    # tenant_b must have its own auth requirement (a user account plus
    # SENTINELOS_REQUIRE_LOGIN here) for this to actually test anything
    # -- an unconfigured tenant accepts any credentials (or none), by
    # design, regardless of a session token failing to validate against
    # it.
    monkeypatch.setenv("SENTINELOS_REQUIRE_LOGIN", "true")
    client.post(f"/tenants/{tenant_b}/auth/users", json={"username": "someone-else", "password": "a-different-password"})

    response = client.get(f"/tenants/{tenant_b}/incidents/does-not-exist", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
