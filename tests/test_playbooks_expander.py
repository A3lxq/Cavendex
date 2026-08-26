"""Tests playbooks/expander.py's expand_playbook_actions: template
substitution against real incident data, order preservation, and that a
step referencing a field the incident doesn't have is skipped rather
than rendered broken."""

from playbooks.expander import expand_playbook_actions
from playbooks.schema import MatchRule, Playbook, PlaybookStep
from state import Incident


def _step(**overrides):
    defaults = dict(action_type="block_ip", action="Block IP", target_template="{ioc}", rationale="r")
    defaults.update(overrides)
    return PlaybookStep(**defaults)


def _playbook(**overrides):
    defaults = dict(id="pb-1", name="Playbook", match=MatchRule(severities=["critical"]), steps=[_step()])
    defaults.update(overrides)
    return Playbook(**defaults)


def _incident(**overrides):
    defaults = dict(id="inc-1", description="x", severity="critical")
    defaults.update(overrides)
    return Incident(**defaults)


def test_ioc_template_renders_the_first_ioc():
    playbook = _playbook(steps=[_step(target_template="{ioc}")])
    incident = _incident(iocs=["1.2.3.4", "5.6.7.8"])

    actions, skipped = expand_playbook_actions(playbook, incident)

    assert not skipped
    assert actions[0].target == "1.2.3.4"


def test_asset_template_renders_the_first_asset():
    playbook = _playbook(steps=[_step(target_template="{asset}")])
    incident = _incident(affected_assets=["WEB-01", "DB-01"])

    actions, skipped = expand_playbook_actions(playbook, incident)

    assert not skipped
    assert actions[0].target == "WEB-01"


def test_literal_target_passes_through_unchanged():
    playbook = _playbook(steps=[_step(target_template="quarantine-vlan-99")])
    actions, skipped = expand_playbook_actions(playbook, _incident())

    assert not skipped
    assert actions[0].target == "quarantine-vlan-99"


def test_ioc_template_skipped_when_incident_has_no_iocs():
    playbook = _playbook(steps=[_step(target_template="{ioc}")])
    actions, skipped = expand_playbook_actions(playbook, _incident(iocs=[]))

    assert actions == []
    assert len(skipped) == 1


def test_asset_template_skipped_when_incident_has_no_assets():
    playbook = _playbook(steps=[_step(target_template="{asset}")])
    actions, skipped = expand_playbook_actions(playbook, _incident(affected_assets=[]))

    assert actions == []
    assert len(skipped) == 1


def test_multi_step_actions_stamped_with_playbook_id_and_chain_step_in_order():
    playbook = _playbook(
        id="ransomware-response",
        steps=[
            _step(action="Isolate host", action_type="isolate_host", target_template="{asset}"),
            _step(action="Disable account", action_type="disable_account", target_template="compromised-user"),
            _step(action="Block IP", action_type="block_ip", target_template="{ioc}"),
        ],
    )
    incident = _incident(iocs=["9.9.9.9"], affected_assets=["WEB-01"])

    actions, skipped = expand_playbook_actions(playbook, incident)

    assert not skipped
    assert [a.chain_step for a in actions] == [1, 2, 3]
    assert all(a.playbook_id == "ransomware-response" for a in actions)
    assert [a.action_type for a in actions] == ["isolate_host", "disable_account", "block_ip"]


def test_skipped_step_preserves_original_chain_step_numbering_for_later_steps():
    playbook = _playbook(
        steps=[
            _step(action="s1", target_template="{asset}"),  # skipped: no assets
            _step(action="s2", target_template="literal-target"),
        ]
    )
    incident = _incident(affected_assets=[])

    actions, skipped = expand_playbook_actions(playbook, incident)

    assert len(skipped) == 1
    assert len(actions) == 1
    assert actions[0].chain_step == 2  # not renumbered to 1


def test_on_failure_is_pinned_onto_each_action(monkeypatch=None):
    playbook = _playbook(on_failure="continue", steps=[_step(target_template="{ioc}")])
    incident = _incident(iocs=["1.2.3.4"])

    actions, _ = expand_playbook_actions(playbook, incident)

    assert actions[0].on_failure == "continue"


def test_positional_target_selection_is_noted_in_rationale():
    """Security-adjacent UX fix: a reviewer approving an action rendered
    from {ioc}/{asset} should see that the target was picked by list
    position, not by relevance -- a beaconing incident's first-reported
    IOC can be the victim's own address, not the actual malicious one."""
    playbook = _playbook(steps=[_step(target_template="{ioc}", action="Block IP")])
    incident = _incident(iocs=["1.2.3.4", "5.6.7.8"])

    actions, _ = expand_playbook_actions(playbook, incident)

    assert "first reported" in actions[0].rationale


def test_literal_target_is_not_flagged_as_positional():
    playbook = _playbook(steps=[_step(target_template="quarantine-vlan-99", action="Isolate")])

    actions, _ = expand_playbook_actions(playbook, _incident())

    assert "first reported" not in actions[0].rationale


def test_no_renderable_steps_returns_empty_actions():
    playbook = _playbook(steps=[_step(target_template="{ioc}")])
    actions, skipped = expand_playbook_actions(playbook, _incident(iocs=[]))
    assert actions == []
    assert len(skipped) == 1
