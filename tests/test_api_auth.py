"""API key auth regression tests. No live LLM calls: we only ever hit
GET /incidents/{id} for a nonexistent incident, which is a pure read that
fails with 404 before touching any agent — auth is checked first."""

import pytest
from fastapi.testclient import TestClient

from api import api
from utils.auth_monitor import reset_for_tests

client = TestClient(api)


@pytest.fixture(autouse=True)
def _isolate_auth_monitor():
    reset_for_tests()
    yield
    reset_for_tests()


def test_health_never_requires_auth(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    assert client.get("/health").status_code == 200


def test_unauthenticated_when_no_key_configured(monkeypatch):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    response = client.get("/incidents/does-not-exist")
    assert response.status_code == 404  # not 401 — auth is off


def test_rejects_missing_auth_header_when_key_configured(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    response = client.get("/incidents/does-not-exist")
    assert response.status_code == 401


def test_rejects_wrong_key(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    response = client.get(
        "/incidents/does-not-exist", headers={"Authorization": "Bearer wrong-key"}
    )
    assert response.status_code == 401


def test_accepts_correct_key(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    response = client.get(
        "/incidents/does-not-exist", headers={"Authorization": "Bearer secret-key-123"}
    )
    assert response.status_code == 404  # auth passed, incident just doesn't exist


# ---------- Per-tenant API keys (SENTINELOS_TENANT_API_KEYS) ----------
#
# These close a real gap: the global SENTINELOS_API_KEY used to authorize
# a caller for EVERY tenant, so tenancy isolated storage but not who
# could read/act on it. A tenant configured in SENTINELOS_TENANT_API_KEYS
# now only ever accepts its own key.


def test_global_key_no_longer_works_for_a_tenant_with_its_own_key(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "global-key")
    monkeypatch.setenv("SENTINELOS_TENANT_API_KEYS", '{"acme": "acme-key"}')

    response = client.get(
        "/tenants/acme/incidents/does-not-exist", headers={"Authorization": "Bearer global-key"}
    )

    assert response.status_code == 401


def test_correct_per_tenant_key_is_accepted(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "global-key")
    monkeypatch.setenv("SENTINELOS_TENANT_API_KEYS", '{"acme": "acme-key"}')

    response = client.get(
        "/tenants/acme/incidents/does-not-exist", headers={"Authorization": "Bearer acme-key"}
    )

    assert response.status_code == 404  # auth passed, incident just doesn't exist


def test_one_tenants_key_does_not_work_for_another_tenant(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "global-key")
    monkeypatch.setenv("SENTINELOS_TENANT_API_KEYS", '{"acme": "acme-key", "globex": "globex-key"}')

    response = client.get(
        "/tenants/globex/incidents/does-not-exist", headers={"Authorization": "Bearer acme-key"}
    )

    assert response.status_code == 401


def test_tenant_with_no_override_falls_back_to_the_global_key(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "global-key")
    monkeypatch.setenv("SENTINELOS_TENANT_API_KEYS", '{"acme": "acme-key"}')

    response = client.get(
        "/tenants/some-other-tenant/incidents/does-not-exist",
        headers={"Authorization": "Bearer global-key"},
    )

    assert response.status_code == 404  # backward-compatible: no override configured


def test_malformed_tenant_api_keys_falls_back_to_global_key_not_a_crash(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "global-key")
    monkeypatch.setenv("SENTINELOS_TENANT_API_KEYS", "not valid json{{{")

    response = client.get(
        "/tenants/acme/incidents/does-not-exist", headers={"Authorization": "Bearer global-key"}
    )

    assert response.status_code == 404


def test_tenant_api_keys_ignored_when_not_a_json_object(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "global-key")
    monkeypatch.setenv("SENTINELOS_TENANT_API_KEYS", '["not", "an", "object"]')

    response = client.get(
        "/tenants/acme/incidents/does-not-exist", headers={"Authorization": "Bearer global-key"}
    )

    assert response.status_code == 404


def test_unprefixed_routes_unaffected_by_tenant_api_keys(monkeypatch):
    """The default-tenant (unprefixed) routes only ever check the global
    key — SENTINELOS_TENANT_API_KEYS has no effect on them."""
    monkeypatch.setenv("SENTINELOS_API_KEY", "global-key")
    monkeypatch.setenv("SENTINELOS_TENANT_API_KEYS", '{"default": "should-not-apply-here"}')

    response = client.get(
        "/incidents/does-not-exist", headers={"Authorization": "Bearer global-key"}
    )

    assert response.status_code == 404


# ---------- API docs (/docs, /redoc, /openapi.json) require auth too ----------
#
# FastAPI's default versions of these routes bypass any router-level auth
# dependency entirely, since they're registered on the app object, not
# the router — this closes that gap by disabling the defaults and
# defining authenticated equivalents instead.


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_require_auth_when_key_configured(monkeypatch, path):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    assert client.get(path).status_code == 401


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_accessible_with_correct_key(monkeypatch, path):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    response = client.get(path, headers={"Authorization": "Bearer secret-key-123"})
    assert response.status_code == 200


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_open_when_no_key_configured(monkeypatch, path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    assert client.get(path).status_code == 200


# ---------- Security response headers ----------


def test_security_headers_present_on_every_response():
    response = client.get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_security_headers_present_on_error_responses(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    response = client.get("/incidents/does-not-exist")  # 401, no key sent
    assert response.status_code == 401
    assert response.headers["x-frame-options"] == "DENY"
