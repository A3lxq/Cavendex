"""Tests playbooks/matcher.py's match_playbook: a pure function, no I/O,
no LLM call — same incident + same playbooks always match the same
way."""

from playbooks.matcher import match_playbook
from playbooks.schema import MatchRule, Playbook, PlaybookStep
from state import Incident


def _step(**overrides):
    defaults = dict(action_type="block_ip", action="Block IP", target_template="{ioc}", rationale="r")
    defaults.update(overrides)
    return PlaybookStep(**defaults)


def _playbook(**overrides):
    defaults = dict(id="pb", name="Playbook", match=MatchRule(severities=["critical"]), steps=[_step()])
    defaults.update(overrides)
    return Playbook(**defaults)


def _incident(**overrides):
    defaults = dict(id="inc-1", description="x", severity="critical")
    defaults.update(overrides)
    return Incident(**defaults)


def test_no_playbooks_returns_none():
    assert match_playbook(_incident(), []) is None


def test_no_matching_playbook_returns_none():
    playbook = _playbook(match=MatchRule(severities=["low"]))
    assert match_playbook(_incident(severity="critical"), [playbook]) is None


def test_severity_match():
    playbook = _playbook(match=MatchRule(severities=["high", "critical"]))
    assert match_playbook(_incident(severity="high"), [playbook]) is playbook


def test_source_match():
    playbook = _playbook(match=MatchRule(sources=["wazuh"]))
    assert match_playbook(_incident(source="wazuh"), [playbook]) is playbook
    assert match_playbook(_incident(source="splunk"), [playbook]) is None


def test_source_match_none_when_incident_has_no_source():
    playbook = _playbook(match=MatchRule(sources=["wazuh"]))
    assert match_playbook(_incident(source=None), [playbook]) is None


def test_ioc_contains_match_is_case_insensitive_substring():
    playbook = _playbook(match=MatchRule(ioc_contains=["mimikatz"]))
    incident = _incident(iocs=["hash:MIMIKATZ-variant-1"])
    assert match_playbook(incident, [playbook]) is playbook


def test_ioc_contains_no_match_when_no_ioc_has_the_substring():
    playbook = _playbook(match=MatchRule(ioc_contains=["mimikatz"]))
    incident = _incident(iocs=["1.2.3.4"])
    assert match_playbook(incident, [playbook]) is None


def test_all_conditions_are_anded():
    playbook = _playbook(match=MatchRule(severities=["critical"], sources=["wazuh"]))
    assert match_playbook(_incident(severity="critical", source="splunk"), [playbook]) is None
    assert match_playbook(_incident(severity="high", source="wazuh"), [playbook]) is None
    assert match_playbook(_incident(severity="critical", source="wazuh"), [playbook]) is playbook


def test_priority_tie_break_higher_wins():
    low = _playbook(id="low-priority", priority=0)
    high = _playbook(id="high-priority", priority=10)
    assert match_playbook(_incident(), [low, high]) is high


def test_alphabetical_id_tie_break_when_priority_equal():
    b = _playbook(id="b-playbook", priority=5)
    a = _playbook(id="a-playbook", priority=5)
    assert match_playbook(_incident(), [b, a]) is a
