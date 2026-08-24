"""Optional live integration test — only runs when an LLM provider is
actually configured, since it makes real calls (including to a local
Ollama server, if OLLAMA_MODEL is set)."""

import os

import pytest

_LIVE_PROVIDER_SET = any(
    os.getenv(k)
    for k in ["GROQ_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "OLLAMA_MODEL"]
)


@pytest.mark.skipif(not _LIVE_PROVIDER_SET, reason="No LLM provider configured")
def test_full_pipeline_runs_end_to_end():
    from workflows.incident_pipeline import run_new_incident

    state = run_new_incident(
        description="Test incident: multiple failed logins from 10.0.0.1",
        severity="medium",
        affected_assets=["TEST-HOST"],
        iocs=["10.0.0.1"],
        source="unit-test",
    )

    incident = state["incident"]
    assert incident.status in {"closed", "investigating", "pending_approval", "contained"}
    assert len(state["messages"]) >= 1
    assert len(state["audit_log"]) >= 1
