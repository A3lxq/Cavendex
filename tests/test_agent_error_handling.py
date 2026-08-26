"""Regression tests: every agent must degrade gracefully (return an
in-band error in state) when no LLM provider is configured, rather than
raising — a missing get_llm() call outside the try/except previously let
this crash the whole graph run (and, via the API, the whole HTTP request)
with an unhandled exception instead."""

import pytest

from agents.investigator_agent import investigator_agent
from agents.responder_agent import responder_agent
from agents.threat_hunter_agent import threat_hunter_agent
from agents.triage_agent import triage_agent
from state import Incident

_ALL_KEYS = ["GROQ_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "OLLAMA_MODEL"]


def _clear_all(monkeypatch):
    for key in _ALL_KEYS:
        monkeypatch.delenv(key, raising=False)


def _state():
    return {
        "messages": [],
        "incident": Incident(id="agent-error-test", description="test", severity="high"),
        "long_term_summary": "",
        "audit_log": [],
        "next_agent": "triage",
        "proposed_actions": [],
        "token_usage": {},
    }


@pytest.mark.parametrize(
    "agent_fn", [triage_agent, investigator_agent, threat_hunter_agent, responder_agent]
)
def test_agent_degrades_gracefully_without_provider(monkeypatch, agent_fn):
    _clear_all(monkeypatch)
    result = agent_fn(_state())  # must not raise
    assert result["next_agent"] is None
    assert any("ERROR" in entry for entry in result["audit_log"])


@pytest.mark.parametrize(
    "agent_fn", [triage_agent, investigator_agent, threat_hunter_agent, responder_agent]
)
def test_provider_exception_text_never_reaches_audit_log_or_messages(monkeypatch, agent_fn):
    """Security regression: a raw LLM SDK exception (which can embed a
    truncated form of the API key itself -- a real, documented OpenAI
    "Incorrect API key provided: sk-..." error shape) must never be
    interpolated verbatim into state["audit_log"]/state["messages"],
    which are durable, widely-visible records (vault report, dashboard,
    API responses) -- unlike server-side logs, which are the appropriate
    place for the full detail. See utils.llm.safe_error_message."""
    _clear_all(monkeypatch)
    monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-this-test")
    secret_looking_text = "Incorrect API key provided: gsk_ABCDEF1234567890SECRETSUFFIX"

    def _raise(*a, **kw):
        raise RuntimeError(secret_looking_text)

    # get_llm is imported by name into each agent module (`from utils.llm
    # import ... get_llm ...`), so it must be patched on that module, not
    # on utils.llm itself, to actually take effect.
    monkeypatch.setattr(f"{agent_fn.__module__}.get_llm", _raise)

    result = agent_fn(_state())

    all_text = " ".join(result["audit_log"]) + " ".join(
        m.get("content", "") if isinstance(m, dict) else str(m) for m in result["messages"]
    )
    assert secret_looking_text not in all_text
    assert "SECRETSUFFIX" not in all_text
    assert "RuntimeError" in all_text  # the exception TYPE is fine to surface, just not its text
