"""Tests playbooks/schema.py's Pydantic validation — a malformed
operator-authored playbook file must be rejected at load time with a
clear reason (see playbooks/loader.py), not produce a broken match or a
half-rendered action later."""

import pytest
from pydantic import ValidationError

from playbooks.schema import MatchRule, Playbook, PlaybookStep


def _step(**overrides):
    defaults = dict(action_type="block_ip", action="Block IP", target_template="{ioc}", rationale="r")
    defaults.update(overrides)
    return PlaybookStep(**defaults)


def _playbook(**overrides):
    defaults = dict(
        id="ransomware-response",
        name="Ransomware Response",
        match=MatchRule(severities=["critical"]),
        steps=[_step()],
    )
    defaults.update(overrides)
    return Playbook(**defaults)


def test_valid_playbook_constructs():
    p = _playbook()
    assert p.id == "ransomware-response"
    assert p.on_failure == "halt"
    assert len(p.steps) == 1


def test_match_rule_with_no_conditions_is_rejected():
    with pytest.raises(ValidationError):
        MatchRule()


def test_match_rule_accepts_a_single_condition():
    assert MatchRule(sources=["wazuh"]).sources == ["wazuh"]


def test_playbook_with_empty_steps_is_rejected():
    with pytest.raises(ValidationError):
        _playbook(steps=[])


def test_playbook_rejects_invalid_action_type():
    with pytest.raises(ValidationError):
        _step(action_type="not_a_real_action_type")


def test_playbook_rejects_invalid_severity_in_match():
    with pytest.raises(ValidationError):
        MatchRule(severities=["catastrophic"])


def test_playbook_rejects_invalid_on_failure_value():
    with pytest.raises(ValidationError):
        _playbook(on_failure="retry")


def test_playbook_priority_and_on_failure_defaults():
    p = _playbook()
    assert p.priority == 0
    assert p.on_failure == "halt"


def test_match_rule_list_fields_are_length_bounded():
    with pytest.raises(ValidationError):
        MatchRule(ioc_contains=[f"ioc-{i}" for i in range(51)])
    with pytest.raises(ValidationError):
        MatchRule(sources=[f"source-{i}" for i in range(51)])
    with pytest.raises(ValidationError):
        MatchRule(severities=["low"] * 51)


def test_playbook_steps_list_is_length_bounded():
    with pytest.raises(ValidationError):
        _playbook(steps=[_step() for _ in range(51)])


def test_rationale_actually_allows_up_to_1000_chars():
    """Regression: rationale was declared ShortStr = Field(max_length=1000),
    but Pydantic merges an Annotated type's own constraint with a
    field-level override by taking the STRICTER of the two -- since
    ShortStr already carries max_length=300, the 1000 override was
    silently ineffective and anything over 300 chars was incorrectly
    rejected."""
    step = _step(rationale="y" * 500)
    assert len(step.rationale) == 500


def test_rationale_still_rejects_over_1000_chars():
    with pytest.raises(ValidationError):
        _step(rationale="y" * 1001)


def test_playbook_multi_step_preserves_order():
    p = _playbook(steps=[_step(action="s1"), _step(action="s2"), _step(action="s3")])
    assert [s.action for s in p.steps] == ["s1", "s2", "s3"]
