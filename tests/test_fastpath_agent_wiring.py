"""Regression tests: each agent must pass prefer_fast=True to get_llm() for
a high/critical-severity incident and prefer_fast=False otherwise -- the
seam Phase 1's fast-path mode (utils.llm.get_llm's prefer_fast param) relies
on. These tests never touch a real provider; they replace get_llm with a
recorder and let the agent's own try/except turn the resulting fake LLM's
absence of real behavior into a normal in-band error, which is fine -- only
the prefer_fast value passed in is under test here."""

import pytest

from agents.investigator_agent import investigator_agent
from agents.responder_agent import responder_agent
from agents.threat_hunter_agent import threat_hunter_agent
from agents.triage_agent import triage_agent
from state import Incident

_AGENTS = [triage_agent, investigator_agent, threat_hunter_agent, responder_agent]


def _state(severity):
    return {
        "messages": [],
        "incident": Incident(id="fastpath-wiring-test", description="test", severity=severity),
        "long_term_summary": "",
        "audit_log": [],
        "next_agent": "triage",
        "proposed_actions": [],
        "token_usage": {},
    }


def _recording_get_llm(monkeypatch, agent_fn):
    calls = []

    def _fake(*args, **kwargs):
        calls.append(kwargs.get("prefer_fast", False))
        raise RuntimeError("stop here -- only recording the call, not actually invoking a provider")

    # get_llm is imported by name into each agent module, so it must be
    # patched there, not on utils.llm itself -- see test_agent_error_handling.py.
    monkeypatch.setattr(f"{agent_fn.__module__}.get_llm", _fake)
    return calls


@pytest.mark.parametrize("agent_fn", _AGENTS)
@pytest.mark.parametrize("severity", ["high", "critical"])
def test_high_and_critical_severity_requests_fast_path(monkeypatch, agent_fn, severity):
    calls = _recording_get_llm(monkeypatch, agent_fn)
    agent_fn(_state(severity))
    assert calls == [True]


@pytest.mark.parametrize("agent_fn", _AGENTS)
@pytest.mark.parametrize("severity", ["low", "medium"])
def test_low_and_medium_severity_does_not_request_fast_path(monkeypatch, agent_fn, severity):
    calls = _recording_get_llm(monkeypatch, agent_fn)
    agent_fn(_state(severity))
    assert calls == [False]


@pytest.mark.parametrize("agent_fn", _AGENTS)
def test_no_incident_never_requests_fast_path(monkeypatch, agent_fn):
    calls = _recording_get_llm(monkeypatch, agent_fn)
    state = _state("critical")
    state["incident"] = None
    agent_fn(state)
    assert calls == [False]
