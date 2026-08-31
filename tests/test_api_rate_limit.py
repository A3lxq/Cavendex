"""API-level rate limit test. No LLM provider needs to be configured —
rate limiting is enforced as a dependency before the route body runs, so
even a request that will fail deeper in the pipeline (no provider
configured) still counts against the limit and still gets rejected with
429 once the limit is hit."""

import pytest
from fastapi.testclient import TestClient

from api import api
from utils.rate_limit import reset_for_tests

client = TestClient(api)


@pytest.fixture(autouse=True)
def _clean_rate_limit_state():
    reset_for_tests()
    yield
    reset_for_tests()


def test_incident_creation_is_rate_limited(monkeypatch):
    for key in ["GROQ_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "OLLAMA_MODEL"]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CAVENDEX_RATE_LIMIT_PER_MINUTE", "2")

    payload = {"description": "test incident for rate limiting", "severity": "low"}

    r1 = client.post("/incidents", json=payload)
    r2 = client.post("/incidents", json=payload)
    r3 = client.post("/incidents", json=payload)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers


def test_tenant_global_limit_catches_what_per_ip_limit_cannot(monkeypatch):
    """Security regression: the per-(tenant, client IP) limit alone does
    nothing to stop the SAME tenant being hit from many different source
    IPs at once (each individually staying under its own per-IP limit
    while collectively exceeding what the tenant's LLM pipeline budget
    was ever meant to absorb). Simulated directly against
    _enforce_tenant_rate_limit rather than through TestClient, since
    TestClient doesn't offer a supported way to vary the simulated
    client IP per request -- this is the same function every real
    request (regardless of source IP) funnels through."""
    from fastapi import HTTPException

    from api import _enforce_tenant_rate_limit

    monkeypatch.setenv("CAVENDEX_TENANT_RATE_LIMIT_PER_MINUTE", "3")

    # Three calls succeed (simulating three different client IPs, each
    # well under its own per-IP limit) -- the fourth is rejected because
    # the tenant-wide ceiling, not any single IP's, has been reached.
    for _ in range(3):
        _enforce_tenant_rate_limit("global-limit-test-tenant")

    with pytest.raises(HTTPException) as exc_info:
        _enforce_tenant_rate_limit("global-limit-test-tenant")
    assert exc_info.value.status_code == 429
    assert "Tenant-wide" in exc_info.value.detail


def test_tenant_global_limit_is_scoped_per_tenant(monkeypatch):
    from api import _enforce_tenant_rate_limit

    monkeypatch.setenv("CAVENDEX_TENANT_RATE_LIMIT_PER_MINUTE", "1")

    _enforce_tenant_rate_limit("tenant-a-global-test")
    # A different tenant's own budget is untouched by tenant-a's usage.
    _enforce_tenant_rate_limit("tenant-b-global-test")


def test_reads_are_never_rate_limited(monkeypatch):
    monkeypatch.setenv("CAVENDEX_RATE_LIMIT_PER_MINUTE", "1")
    # Burn through the limit on a *different* key namespace (tenant "reads-test")
    # by hitting reads repeatedly — reads have no rate_limit dependency at all.
    for _ in range(10):
        response = client.get("/tenants/reads-test/incidents/does-not-exist")
        assert response.status_code == 404  # never 429
