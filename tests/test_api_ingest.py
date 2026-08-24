"""API-level ingest endpoint tests. No LLM provider configured — a
promoted alert still runs the pipeline (Triage fails cleanly, as tested
elsewhere), which is enough to prove the endpoint wires through to
ingest_alert() correctly."""

from fastapi.testclient import TestClient

from api import api
from utils.dedup import reset_for_tests as reset_dedup
from utils.rate_limit import reset_for_tests as reset_rate_limit

client = TestClient(api)


def setup_function():
    reset_dedup()
    reset_rate_limit()


def test_ingest_unknown_source_returns_200_with_outcome():
    response = client.post("/ingest/not-a-real-source", json={})
    assert response.status_code == 200
    assert response.json()["outcome"] == "unknown_source"


def test_ingest_suricata_non_alert_event_is_not_promoted():
    response = client.post("/ingest/suricata", json={"event_type": "flow"})
    assert response.status_code == 200
    assert response.json()["outcome"] == "not_an_alert"


def test_ingest_low_severity_generic_alert_is_suppressed():
    response = client.post(
        "/ingest/generic", json={"description": "minor thing", "severity": "low", "source": "test"}
    )
    assert response.status_code == 200
    assert response.json()["outcome"] == "suppressed_low_severity"


def test_ingest_oversized_payload_is_rejected(monkeypatch):
    monkeypatch.setenv("SENTINELOS_RATE_LIMIT_PER_MINUTE", "1000")
    huge_payload = {"description": "A" * 200_000, "severity": "high", "source": "test"}
    response = client.post("/ingest/generic", json=huge_payload)
    assert response.status_code == 413


def test_ingest_for_tenant_scopes_correctly():
    response = client.post(
        "/tenants/ingest-test-tenant/ingest/generic",
        json={"description": "minor thing", "severity": "low", "source": "test"},
    )
    assert response.status_code == 200
    assert response.json()["outcome"] == "suppressed_low_severity"
