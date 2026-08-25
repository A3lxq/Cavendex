"""Tests the /notes and /assign API routes against a real LangGraph
checkpoint + the real incident_notes.db / incident_index.db, via
TestClient (real HTTP request/response cycle)."""

import itertools

from fastapi.testclient import TestClient

from api import api
from graph import get_app
from state import Incident
from utils.incident_index import upsert_incident_summary

client = TestClient(api)
_tenant_counter = itertools.count()


def _tenant():
    return f"notes-test-{next(_tenant_counter)}"


def _seed_incident(tenant_id, thread_id="inc-1"):
    app = get_app(tenant_id)
    config = {"configurable": {"thread_id": thread_id}}
    state = {
        "messages": [], "incident": Incident(id=thread_id, description="x", status="open"),
        "long_term_summary": "", "audit_log": [], "next_agent": None, "proposed_actions": [],
        "token_usage": {}, "tenant_id": tenant_id, "threat_intel": [], "attack_technique": None,
    }
    app.update_state(config, state)
    upsert_incident_summary(tenant_id, {**state, "incident": state["incident"]})


def test_notes_empty_for_a_fresh_incident(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()
    _seed_incident(tenant)

    response = client.get(f"/tenants/{tenant}/incidents/inc-1/notes")
    assert response.status_code == 200
    assert response.json() == []


def test_add_note_then_list_returns_it(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()
    _seed_incident(tenant)

    add_response = client.post(
        f"/tenants/{tenant}/incidents/inc-1/notes", json={"text": "Checked with the user.", "author": "j.smith"}
    )
    assert add_response.status_code == 200
    assert add_response.json()["author"] == "j.smith"

    list_response = client.get(f"/tenants/{tenant}/incidents/inc-1/notes")
    assert list_response.status_code == 200
    notes = list_response.json()
    assert len(notes) == 1
    assert notes[0]["text"] == "Checked with the user."


def test_add_note_to_unknown_incident_returns_404(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()

    response = client.post(f"/tenants/{tenant}/incidents/never-existed/notes", json={"text": "x"})
    assert response.status_code == 404


def test_add_empty_note_returns_400(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()
    _seed_incident(tenant)

    response = client.post(f"/tenants/{tenant}/incidents/inc-1/notes", json={"text": "   "})
    assert response.status_code == 400


def test_default_tenant_notes_routes_also_work(monkeypatch, tmp_path):
    from utils.tenancy import DEFAULT_TENANT

    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed_incident(DEFAULT_TENANT, thread_id="inc-default-1")

    client.post("/incidents/inc-default-1/notes", json={"text": "a default-tenant note"})
    response = client.get("/incidents/inc-default-1/notes")
    assert response.status_code == 200
    assert response.json()[0]["text"] == "a default-tenant note"


def test_assign_incident_reflects_in_the_list(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()
    _seed_incident(tenant)

    assign_response = client.post(f"/tenants/{tenant}/incidents/inc-1/assign", json={"assigned_to": "j.smith"})
    assert assign_response.status_code == 200
    assert assign_response.json()["assigned_to"] == "j.smith"

    list_response = client.get(f"/tenants/{tenant}/incidents")
    assert list_response.json()[0]["assigned_to"] == "j.smith"


def test_unassign_with_no_body_clears_it(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()
    _seed_incident(tenant)
    client.post(f"/tenants/{tenant}/incidents/inc-1/assign", json={"assigned_to": "j.smith"})

    response = client.post(f"/tenants/{tenant}/incidents/inc-1/assign")
    assert response.status_code == 200
    assert response.json()["assigned_to"] is None

    list_response = client.get(f"/tenants/{tenant}/incidents")
    assert list_response.json()[0]["assigned_to"] is None


def test_assign_unknown_incident_returns_404(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()

    response = client.post(f"/tenants/{tenant}/incidents/never-existed/assign", json={"assigned_to": "j.smith"})
    assert response.status_code == 404


def test_notes_and_assign_require_auth_when_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()

    assert client.get(f"/tenants/{tenant}/incidents/inc-1/notes").status_code == 401
    assert client.post(f"/tenants/{tenant}/incidents/inc-1/assign").status_code == 401
