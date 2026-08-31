"""Tests ingestion/semantic_correlation.py's gating and validation logic
via a mocked LLM judge (_invoke_judge) — no real LLM call needed to test
the guardrails around one. Live-verified separately against a real model
(see README's Testing section)."""

import pytest

import ingestion.semantic_correlation as sc
from ingestion.schemas import NormalizedAlert
from utils.llm import StructuredOutputError

_USAGE = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}


def _alert(description="A brute-force pattern against host X", severity="high"):
    return NormalizedAlert(description=description, severity=severity, source="test", dedup_key="k")


def _candidate(thread_id="inc-1", **overrides):
    base = {
        "thread_id": thread_id,
        "description": "seeded incident",
        "severity": "high",
        "iocs": [],
        "affected_assets": [],
        "attack_technique_id": None,
        "attack_technique_name": None,
        "updated_at": "2026-01-01T00:00:00+00:00",
    }
    base.update(overrides)
    return base


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.delenv("CAVENDEX_CORRELATION_SEMANTIC_ENABLED", raising=False)
    monkeypatch.delenv("CAVENDEX_CORRELATION_SEMANTIC_MAX_CANDIDATES", raising=False)
    monkeypatch.delenv("CAVENDEX_CORRELATION_SEMANTIC_MIN_CONFIDENCE", raising=False)


def test_disabled_by_default_never_calls_the_judge(monkeypatch):
    def _fail(*a, **kw):
        raise AssertionError("must not call the LLM when disabled")

    monkeypatch.setattr(sc, "_invoke_judge", _fail)
    match, usage = sc.find_semantic_correlation("t1", _alert(), candidates=[_candidate()])
    assert match is None
    assert usage == {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}


def test_no_candidates_never_calls_the_judge(monkeypatch):
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_ENABLED", "true")

    def _fail(*a, **kw):
        raise AssertionError("must not call the LLM with no candidates")

    monkeypatch.setattr(sc, "_invoke_judge", _fail)
    match, usage = sc.find_semantic_correlation("t1", _alert(), candidates=[])
    assert match is None
    assert usage["total_tokens"] == 0


def test_a_confident_correlating_match_is_returned(monkeypatch):
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_ENABLED", "true")
    candidates = [_candidate("inc-1")]

    def _fake(alert_summary, candidates_summary):
        return sc.CampaignMatch(correlates=True, thread_id="inc-1", confidence="high", reason="same TTP"), _USAGE

    monkeypatch.setattr(sc, "_invoke_judge", _fake)
    match, usage = sc.find_semantic_correlation("t1", _alert(), candidates=candidates)
    assert match == {"thread_id": "inc-1", "match_type": "semantic", "reason": "same TTP", "confidence": "high"}
    assert usage == _USAGE


def test_correlates_false_returns_no_match_but_preserves_usage(monkeypatch):
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_ENABLED", "true")

    def _fake(alert_summary, candidates_summary):
        return sc.CampaignMatch(correlates=False, thread_id=None, confidence="low", reason="unrelated"), _USAGE

    monkeypatch.setattr(sc, "_invoke_judge", _fake)
    match, usage = sc.find_semantic_correlation("t1", _alert(), candidates=[_candidate("inc-1")])
    assert match is None
    assert usage == _USAGE


def test_hallucinated_thread_id_is_rejected(monkeypatch):
    """A thread_id the model invented (not in the candidate list) must
    never be trusted enough to merge into a real incident."""
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_ENABLED", "true")

    def _fake(alert_summary, candidates_summary):
        return (
            sc.CampaignMatch(correlates=True, thread_id="inc-does-not-exist", confidence="high", reason="x"),
            _USAGE,
        )

    monkeypatch.setattr(sc, "_invoke_judge", _fake)
    match, usage = sc.find_semantic_correlation("t1", _alert(), candidates=[_candidate("inc-1")])
    assert match is None
    assert usage == _USAGE  # the call still happened and cost tokens


def test_low_confidence_below_threshold_is_rejected(monkeypatch):
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_ENABLED", "true")
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_MIN_CONFIDENCE", "medium")

    def _fake(alert_summary, candidates_summary):
        return sc.CampaignMatch(correlates=True, thread_id="inc-1", confidence="low", reason="x"), _USAGE

    monkeypatch.setattr(sc, "_invoke_judge", _fake)
    match, usage = sc.find_semantic_correlation("t1", _alert(), candidates=[_candidate("inc-1")])
    assert match is None
    assert usage == _USAGE


def test_confidence_threshold_is_configurable(monkeypatch):
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_ENABLED", "true")
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_MIN_CONFIDENCE", "low")

    def _fake(alert_summary, candidates_summary):
        return sc.CampaignMatch(correlates=True, thread_id="inc-1", confidence="low", reason="x"), _USAGE

    monkeypatch.setattr(sc, "_invoke_judge", _fake)
    match, usage = sc.find_semantic_correlation("t1", _alert(), candidates=[_candidate("inc-1")])
    assert match is not None
    assert match["confidence"] == "low"


def test_candidates_are_capped_at_max_candidates(monkeypatch):
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_ENABLED", "true")
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_MAX_CANDIDATES", "2")
    candidates = [_candidate(f"inc-{i}") for i in range(5)]

    seen = {}

    def _fake(alert_summary, candidates_summary):
        seen["candidates_summary"] = candidates_summary
        return sc.CampaignMatch(correlates=False, confidence="low", reason="x"), _USAGE

    monkeypatch.setattr(sc, "_invoke_judge", _fake)
    sc.find_semantic_correlation("t1", _alert(), candidates=candidates)
    assert seen["candidates_summary"].count("thread_id:") == 2


def test_total_llm_failure_falls_through_to_no_match_preserving_partial_usage(monkeypatch):
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_ENABLED", "true")

    def _fake(alert_summary, candidates_summary):
        raise StructuredOutputError(RuntimeError("malformed response"), _USAGE)

    monkeypatch.setattr(sc, "_invoke_judge", _fake)
    match, usage = sc.find_semantic_correlation("t1", _alert(), candidates=[_candidate("inc-1")])
    assert match is None
    assert usage == _USAGE


def test_no_provider_configured_fails_open_with_zero_usage(monkeypatch):
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_ENABLED", "true")
    for key in ["GROQ_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "OLLAMA_MODEL"]:
        monkeypatch.delenv(key, raising=False)

    match, usage = sc.find_semantic_correlation("t1", _alert(), candidates=[_candidate("inc-1")])
    assert match is None
    assert usage["total_tokens"] == 0


def test_a_verified_technique_is_shown_to_the_judge(monkeypatch):
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_ENABLED", "true")
    candidate = _candidate("inc-1", attack_technique_id="T1110", attack_technique_name="Brute Force")

    seen = {}

    def _fake(alert_summary, candidates_summary):
        seen["candidates_summary"] = candidates_summary
        return sc.CampaignMatch(correlates=False, confidence="low", reason="x"), _USAGE

    monkeypatch.setattr(sc, "_invoke_judge", _fake)
    sc.find_semantic_correlation("t1", _alert(), candidates=[candidate])
    assert "T1110" in seen["candidates_summary"]
    assert "Brute Force" in seen["candidates_summary"]


def test_no_technique_shows_as_none_cited(monkeypatch):
    monkeypatch.setenv("CAVENDEX_CORRELATION_SEMANTIC_ENABLED", "true")

    seen = {}

    def _fake(alert_summary, candidates_summary):
        seen["candidates_summary"] = candidates_summary
        return sc.CampaignMatch(correlates=False, confidence="low", reason="x"), _USAGE

    monkeypatch.setattr(sc, "_invoke_judge", _fake)
    sc.find_semantic_correlation("t1", _alert(), candidates=[_candidate("inc-1")])
    assert "none cited" in seen["candidates_summary"]
