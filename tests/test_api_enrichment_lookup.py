"""Tests the POST /enrichment/lookup route -- real threat-intel lookups
on demand, with no incident created. The underlying provider lookups
themselves are already covered by test_enrichment_pipeline.py and
test_enrichment_providers.py; these tests are about the route's own
plumbing (auth, validation, serialization)."""

from fastapi.testclient import TestClient

from api import api
from enrichment.schemas import EnrichmentResult

client = TestClient(api)


def test_lookup_requires_auth_when_configured(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    response = client.post("/enrichment/lookup", json={"iocs": ["1.2.3.4"]})
    assert response.status_code == 401


def test_lookup_with_unclassifiable_indicator_returns_empty_list(monkeypatch):
    """A free-text 'indicator' that isn't a real IP/domain/hash never
    reaches a provider at all -- this proves the route is wired to the
    real enrich_iocs() end to end without needing network access or a
    configured API key."""
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    response = client.post("/enrichment/lookup", json={"iocs": ["not a real indicator, just prose"]})
    assert response.status_code == 200
    assert response.json() == []


def test_lookup_returns_serialized_results(monkeypatch):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)

    def fake_enrich_iocs(iocs):
        return [
            EnrichmentResult(
                indicator="1.2.3.4", indicator_type="ip", source="abuseipdb",
                verdict="malicious", detail="Reported 42 times", link="https://example.com",
            )
        ]

    import enrichment.pipeline

    monkeypatch.setattr(enrichment.pipeline, "enrich_iocs", fake_enrich_iocs)

    response = client.post("/enrichment/lookup", json={"iocs": ["1.2.3.4"]})
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 1
    assert results[0]["indicator"] == "1.2.3.4"
    assert results[0]["verdict"] == "malicious"
    assert results[0]["source"] == "abuseipdb"


def test_lookup_rejects_more_than_fifty_iocs(monkeypatch):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    response = client.post("/enrichment/lookup", json={"iocs": [f"1.2.3.{i}" for i in range(51)]})
    assert response.status_code == 422


def test_tenant_scoped_lookup_route_also_works(monkeypatch):
    monkeypatch.delenv("SENTINELOS_API_KEY", raising=False)
    response = client.post("/tenants/acme/enrichment/lookup", json={"iocs": ["not a real indicator"]})
    assert response.status_code == 200
    assert response.json() == []
