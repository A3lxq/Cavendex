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
    monkeypatch.setenv("SENTINELOS_RATE_LIMIT_PER_MINUTE", "2")

    payload = {"description": "test incident for rate limiting", "severity": "low"}

    r1 = client.post("/incidents", json=payload)
    r2 = client.post("/incidents", json=payload)
    r3 = client.post("/incidents", json=payload)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers


def test_reads_are_never_rate_limited(monkeypatch):
    monkeypatch.setenv("SENTINELOS_RATE_LIMIT_PER_MINUTE", "1")
    # Burn through the limit on a *different* key namespace (tenant "reads-test")
    # by hitting reads repeatedly — reads have no rate_limit dependency at all.
    for _ in range(10):
        response = client.get("/tenants/reads-test/incidents/does-not-exist")
        assert response.status_code == 404  # never 429
