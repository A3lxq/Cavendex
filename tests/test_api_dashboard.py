"""Dashboard-serving and list-endpoint tests. No LLM provider needed."""

from fastapi.testclient import TestClient

from api import api
from state import Incident
from utils.incident_index import reset_for_tests, upsert_incident_summary

client = TestClient(api)


def setup_function():
    reset_for_tests()


def test_dashboard_shell_is_served_unauthenticated(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "SentinelOS" in response.text


def test_static_assets_are_served_unauthenticated(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    js = client.get("/static/app.js")
    css = client.get("/static/style.css")
    assert js.status_code == 200
    assert "javascript" in js.headers["content-type"]
    assert css.status_code == 200
    assert "css" in css.headers["content-type"]


def test_list_incidents_requires_auth_when_configured(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    response = client.get("/tenants/dash-test/incidents")
    assert response.status_code == 401


def test_list_incidents_returns_seeded_summaries(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))

    upsert_incident_summary(
        "dash-test",
        {"incident": Incident(id="inc-1", description="test", severity="high", status="pending_approval"),
         "tenant_id": "dash-test"},
    )

    response = client.get("/tenants/dash-test/incidents")
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 1
    assert rows[0]["thread_id"] == "inc-1"
    assert rows[0]["has_pending_actions"] == 1


def test_list_incidents_empty_for_unknown_tenant(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    response = client.get("/tenants/never-used-tenant/incidents")
    assert response.status_code == 200
    assert response.json() == []
