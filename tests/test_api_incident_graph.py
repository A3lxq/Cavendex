"""Tests the /incidents/graph API route (the data behind the dashboard's
"Strand Map" canvas view) against a real LangGraph checkpoint + the real
incident_index.db, via TestClient (real HTTP request/response cycle)."""

import itertools

from fastapi.testclient import TestClient

from api import api
from graph import get_app
from state import Incident
from utils.incident_index import upsert_incident_summary

client = TestClient(api)
_tenant_counter = itertools.count()


def _tenant():
    return f"incident-graph-test-{next(_tenant_counter)}"


def _seed_incident(tenant_id, thread_id, iocs=None, affected_assets=None):
    app = get_app(tenant_id)
    config = {"configurable": {"thread_id": thread_id}}
    state = {
        "messages": [],
        "incident": Incident(id=thread_id, description="x", status="open", iocs=iocs or [], affected_assets=affected_assets or []),
        "long_term_summary": "", "audit_log": [], "next_agent": None, "proposed_actions": [],
        "token_usage": {}, "tenant_id": tenant_id, "threat_intel": [], "attack_technique": None,
    }
    app.update_state(config, state)
    upsert_incident_summary(tenant_id, {**state, "incident": state["incident"]})


def test_empty_tenant_returns_an_empty_graph(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()

    response = client.get(f"/tenants/{tenant}/incidents/graph")
    assert response.status_code == 200
    assert response.json() == {"nodes": [], "edges": [], "incidents_included": 0, "incidents_total": 0}


def test_two_incidents_sharing_an_ioc_are_linked_by_one_shared_node(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()
    _seed_incident(tenant, "inc-1", iocs=["1.2.3.4"])
    _seed_incident(tenant, "inc-2", iocs=["1.2.3.4"])

    response = client.get(f"/tenants/{tenant}/incidents/graph")
    assert response.status_code == 200
    body = response.json()

    node_ids = {n["id"] for n in body["nodes"]}
    assert node_ids == {"incident:inc-1", "incident:inc-2", "ioc:1.2.3.4"}
    edge_pairs = {(e["source"], e["target"]) for e in body["edges"]}
    assert edge_pairs == {("incident:inc-1", "ioc:1.2.3.4"), ("incident:inc-2", "ioc:1.2.3.4")}


def test_default_tenant_route_matches_tenant_scoped_route(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed_incident("default", "inc-default-1", iocs=["9.9.9.9"])

    default_response = client.get("/incidents/graph")
    tenant_response = client.get("/tenants/default/incidents/graph")
    assert default_response.status_code == 200
    assert default_response.json() == tenant_response.json()


def test_route_requires_auth_when_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    response = client.get(f"/tenants/{_tenant()}/incidents/graph")
    assert response.status_code == 401
