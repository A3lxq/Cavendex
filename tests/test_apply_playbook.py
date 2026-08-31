"""Tests workflows.incident_pipeline._apply_playbook directly against a
real LangGraph app/checkpoint (no LLM call needed — the same reasoning
tests/test_resolve_proposed_actions.py uses for resolve_proposed_actions
itself): matching, append vs. replace mode, the pending_approval status
transition, the audit log entry, and that an unconfigured/no-match case
leaves state completely untouched."""

import itertools
import json

from graph import get_app
from state import Incident, ProposedAction
from workflows.incident_pipeline import _apply_playbook

_tenant_counter = itertools.count()


def _tenant():
    return f"apply-playbook-test-{next(_tenant_counter)}"


def _state(thread_id="inc-1", tenant_id="t", proposed_actions=None, **incident_overrides):
    incident_defaults = dict(id=thread_id, description="ransomware detected", severity="critical")
    incident_defaults.update(incident_overrides)
    return {
        "messages": [],
        "incident": Incident(**incident_defaults),
        "long_term_summary": "",
        "audit_log": [],
        "next_agent": None,
        "proposed_actions": proposed_actions or [],
        "token_usage": {},
        "tenant_id": tenant_id,
        "threat_intel": [],
        "attack_technique": None,
    }


def _write_playbook(path, **overrides):
    defaults = dict(
        id="ransomware-response",
        name="Ransomware Response",
        match={"severities": ["critical"]},
        steps=[
            {"action_type": "isolate_host", "action": "Isolate host", "target_template": "{asset}", "rationale": "r"},
            {"action_type": "block_ip", "action": "Block IP", "target_template": "{ioc}", "rationale": "r"},
        ],
    )
    defaults.update(overrides)
    path.write_text(json.dumps(defaults))


def test_no_playbooks_configured_leaves_state_untouched(monkeypatch):
    monkeypatch.delenv("CAVENDEX_PLAYBOOKS_DIR", raising=False)
    tenant_id = _tenant()
    app = get_app(tenant_id)
    config = {"configurable": {"thread_id": "inc-1"}}
    state = _state(tenant_id=tenant_id)

    result = _apply_playbook(app, config, state)

    assert result is state


def test_no_matching_playbook_leaves_state_untouched(monkeypatch, tmp_path):
    _write_playbook(tmp_path / "pb.json", match={"severities": ["low"]})
    monkeypatch.setenv("CAVENDEX_PLAYBOOKS_DIR", str(tmp_path))
    tenant_id = _tenant()
    app = get_app(tenant_id)
    config = {"configurable": {"thread_id": "inc-1"}}
    state = _state(tenant_id=tenant_id, severity="critical")

    result = _apply_playbook(app, config, state)

    assert result is state


def test_matching_playbook_appends_actions_by_default(monkeypatch, tmp_path):
    _write_playbook(tmp_path / "pb.json")
    monkeypatch.setenv("CAVENDEX_PLAYBOOKS_DIR", str(tmp_path))
    monkeypatch.delenv("CAVENDEX_PLAYBOOKS_MODE", raising=False)
    tenant_id = _tenant()
    app = get_app(tenant_id)
    config = {"configurable": {"thread_id": "inc-1"}}
    existing = [ProposedAction(action="Existing action", target="x", rationale="r")]
    state = _state(tenant_id=tenant_id, proposed_actions=existing, iocs=["1.2.3.4"], affected_assets=["WEB-01"])

    result = _apply_playbook(app, config, state)

    actions = result["proposed_actions"]
    assert len(actions) == 3
    assert actions[0].action == "Existing action"
    playbook_actions = [a for a in actions if a.playbook_id == "ransomware-response"]
    assert [a.chain_step for a in playbook_actions] == [1, 2]
    assert result["incident"].status == "pending_approval"
    assert any("Playbook" in entry for entry in result["audit_log"])


def test_matching_playbook_replaces_actions_when_mode_is_replace(monkeypatch, tmp_path):
    _write_playbook(tmp_path / "pb.json")
    monkeypatch.setenv("CAVENDEX_PLAYBOOKS_DIR", str(tmp_path))
    monkeypatch.setenv("CAVENDEX_PLAYBOOKS_MODE", "replace")
    tenant_id = _tenant()
    app = get_app(tenant_id)
    config = {"configurable": {"thread_id": "inc-1"}}
    existing = [ProposedAction(action="Existing action", target="x", rationale="r")]
    state = _state(tenant_id=tenant_id, proposed_actions=existing, iocs=["1.2.3.4"], affected_assets=["WEB-01"])

    result = _apply_playbook(app, config, state)

    actions = result["proposed_actions"]
    assert len(actions) == 2
    assert all(a.playbook_id == "ransomware-response" for a in actions)


def test_persisted_state_is_retrievable_from_the_real_checkpoint(monkeypatch, tmp_path):
    _write_playbook(tmp_path / "pb.json")
    monkeypatch.setenv("CAVENDEX_PLAYBOOKS_DIR", str(tmp_path))
    tenant_id = _tenant()
    app = get_app(tenant_id)
    config = {"configurable": {"thread_id": "inc-1"}}
    state = _state(tenant_id=tenant_id, iocs=["1.2.3.4"], affected_assets=["WEB-01"])

    _apply_playbook(app, config, state)

    reloaded = app.get_state(config).values
    assert len(reloaded["proposed_actions"]) == 2
    assert reloaded["incident"].status == "pending_approval"
