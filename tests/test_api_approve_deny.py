"""Tests the /approve and /deny API routes against a real LangGraph
checkpoint (via TestClient, real HTTP request/response cycle) — including
the approved_by accountability field, which had zero API-level coverage
before this."""

import itertools

from fastapi.testclient import TestClient

from api import api
from graph import get_app
from state import Incident, ProposedAction

client = TestClient(api)
_tenant_counter = itertools.count()


def _tenant():
    return f"api-approve-test-{next(_tenant_counter)}"


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


def test_approve_with_no_body_records_approved_by_none(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()
    _seed_pending_incident(tenant)

    response = client.post(f"/tenants/{tenant}/incidents/inc-1/approve")

    assert response.status_code == 200
    action = response.json()["proposed_actions"][0]
    assert action["approved"] is True
    assert action["approved_by"] is None


def test_approve_with_approved_by_in_body(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()
    _seed_pending_incident(tenant)

    response = client.post(f"/tenants/{tenant}/incidents/inc-1/approve", json={"approved_by": "j.smith"})

    assert response.status_code == 200
    action = response.json()["proposed_actions"][0]
    assert action["approved"] is True
    assert action["approved_by"] == "j.smith"
    assert any("j.smith" in entry for entry in response.json()["audit_log"])


def test_deny_with_approved_by_in_body(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()
    _seed_pending_incident(tenant)

    response = client.post(f"/tenants/{tenant}/incidents/inc-1/deny", json={"approved_by": "a.jones"})

    assert response.status_code == 200
    action = response.json()["proposed_actions"][0]
    assert action["approved"] is False
    assert action["approved_by"] == "a.jones"


def test_default_tenant_approve_route_also_accepts_approved_by(monkeypatch, tmp_path):
    from utils.tenancy import DEFAULT_TENANT

    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed_pending_incident(DEFAULT_TENANT, thread_id="inc-default-1")

    response = client.post("/incidents/inc-default-1/approve", json={"approved_by": "j.smith"})

    assert response.status_code == 200
    assert response.json()["proposed_actions"][0]["approved_by"] == "j.smith"


def test_approve_unknown_thread_returns_400(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()

    response = client.post(f"/tenants/{tenant}/incidents/never-existed/approve")

    assert response.status_code == 400


def test_approve_rejects_missing_approved_by_when_required(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REQUIRE_APPROVED_BY", "true")
    tenant = _tenant()
    _seed_pending_incident(tenant)

    response = client.post(f"/tenants/{tenant}/incidents/inc-1/approve")

    assert response.status_code == 400


def test_approve_succeeds_with_approved_by_when_required(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REQUIRE_APPROVED_BY", "true")
    tenant = _tenant()
    _seed_pending_incident(tenant)

    response = client.post(f"/tenants/{tenant}/incidents/inc-1/approve", json={"approved_by": "j.smith"})

    assert response.status_code == 200


def test_approve_requires_api_key_when_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    tenant = _tenant()
    _seed_pending_incident(tenant)

    response = client.post(f"/tenants/{tenant}/incidents/inc-1/approve")

    assert response.status_code == 401
