"""Tests the /incidents/attack-overview API route against a real
LangGraph checkpoint + the real incident_index.db, via TestClient (real
HTTP request/response cycle)."""

import itertools

from fastapi.testclient import TestClient

from api import api
from graph import get_app
from state import Incident
from utils.incident_index import reset_for_tests, upsert_incident_summary

client = TestClient(api)
_tenant_counter = itertools.count()


def setup_function():
    reset_for_tests()


def _tenant():
    return f"attack-overview-test-{next(_tenant_counter)}"


def _seed_incident(tenant_id, thread_id, attack_technique=None):
    app = get_app(tenant_id)
    config = {"configurable": {"thread_id": thread_id}}
    state = {
        "messages": [], "incident": Incident(id=thread_id, description="x", status="open"),
        "long_term_summary": "", "audit_log": [], "next_agent": None, "proposed_actions": [],
        "token_usage": {}, "tenant_id": tenant_id, "threat_intel": [], "attack_technique": attack_technique,
    }
    app.update_state(config, state)
    upsert_incident_summary(tenant_id, {**state, "incident": state["incident"]})


def test_empty_tenant_returns_no_tactics(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()

    response = client.get(f"/tenants/{tenant}/incidents/attack-overview")
    assert response.status_code == 200
    assert response.json() == {"tactics": []}


def test_verified_techniques_grouped_by_tactic_in_kill_chain_order(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()

    # T1566 (Phishing / Initial Access) comes after T1595 (Active Scanning /
    # Reconnaissance) in kill-chain order, so seeding it first checks the
    # route actually re-orders rather than just echoing insertion order.
    _seed_incident(tenant, "inc-1", {"id": "T1566", "name": "Phishing", "verified": True})
    _seed_incident(tenant, "inc-2", {"id": "T1595", "name": "Active Scanning", "verified": True})
    _seed_incident(tenant, "inc-3", {"id": "T1595", "name": "Active Scanning", "verified": True})

    response = client.get(f"/tenants/{tenant}/incidents/attack-overview")
    assert response.status_code == 200
    tactics = response.json()["tactics"]
    assert [t["tactic"] for t in tactics] == ["Reconnaissance", "Initial Access"]

    recon = tactics[0]["techniques"]
    assert recon == [{"id": "T1595", "name": "Active Scanning", "count": 2}]

    initial_access = tactics[1]["techniques"]
    assert initial_access == [{"id": "T1566", "name": "Phishing", "count": 1}]


def test_unverified_and_uncited_incidents_excluded(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()

    _seed_incident(tenant, "inc-1", {"id": "T1566", "name": "Phishing", "verified": False})
    _seed_incident(tenant, "inc-2", None)

    response = client.get(f"/tenants/{tenant}/incidents/attack-overview")
    assert response.status_code == 200
    assert response.json() == {"tactics": []}


def test_default_tenant_route_matches_tenant_scoped_route(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed_incident("default", "inc-default-1", {"id": "T1078", "name": "Valid Accounts", "verified": True})

    default_response = client.get("/incidents/attack-overview")
    tenant_response = client.get("/tenants/default/incidents/attack-overview")
    assert default_response.status_code == 200
    assert default_response.json() == tenant_response.json()
