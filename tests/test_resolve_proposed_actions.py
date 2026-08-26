"""Tests workflows.incident_pipeline.resolve_proposed_actions directly
against a real LangGraph checkpoint (seeded via app.update_state, same
technique as test_merge_correlated_alert.py) — this is the human-in-the-
loop gate the entire project is built around, and until now it had zero
dedicated tests, unit or otherwise. Also covers the approved_by
accountability field added after a live review found that the audit
trail could never say *who* approved a proposed action."""

import itertools
import threading
import time

import pytest

from graph import get_app
from state import Incident, ProposedAction
from workflows.incident_pipeline import resolve_proposed_actions

_tenant_counter = itertools.count()


@pytest.fixture
def tenant():
    return f"resolve-test-{next(_tenant_counter)}"


def _seed_pending_incident(tenant_id, thread_id="inc-1", n_actions=1, actions=None):
    app = get_app(tenant_id)
    config = {"configurable": {"thread_id": thread_id}}
    app.update_state(
        config,
        {
            "messages": [],
            "incident": Incident(id=thread_id, description="x", severity="high", status="pending_approval"),
            "long_term_summary": "",
            "audit_log": ["Responder Agent -> proposed action(s), awaiting human approval"],
            "next_agent": None,
            "proposed_actions": actions
            if actions is not None
            else [ProposedAction(action=f"block-{i}", target=f"1.2.3.{i}", rationale="r") for i in range(n_actions)],
            "token_usage": {},
            "tenant_id": tenant_id,
            "threat_intel": [],
            "attack_technique": None,
        },
    )


def test_approve_sets_status_contained_and_marks_all_actions_approved(tenant):
    _seed_pending_incident(tenant, n_actions=2)

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant, approved_by="j.smith")

    assert result["incident"].status == "contained"
    assert all(a.approved is True for a in result["proposed_actions"])


def test_deny_sets_status_closed_and_marks_all_actions_denied(tenant):
    _seed_pending_incident(tenant)

    result = resolve_proposed_actions("inc-1", approve=False, tenant_id=tenant, approved_by="j.smith")

    assert result["incident"].status == "closed"
    assert all(a.approved is False for a in result["proposed_actions"])


def test_approved_by_is_recorded_on_every_action(tenant):
    _seed_pending_incident(tenant, n_actions=3)

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant, approved_by="j.smith")

    assert all(a.approved_by == "j.smith" for a in result["proposed_actions"])


def test_approved_by_appears_in_audit_log_and_message(tenant):
    _seed_pending_incident(tenant)

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant, approved_by="j.smith")

    assert any("j.smith" in entry for entry in result["audit_log"])
    message = result["messages"][-1]
    name = message.get("name") if isinstance(message, dict) else getattr(message, "name", None)
    assert "j.smith" in name


def test_missing_approved_by_is_recorded_as_unspecified_not_silently_generic(tenant):
    """Before this fix, every decision was attributed to the same generic
    'Human Reviewer' string regardless of who made it — indistinguishable
    from a real identity. Now, omitting approved_by must be visibly
    different from providing one, not silently identical."""
    _seed_pending_incident(tenant)

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)

    assert all(a.approved_by is None for a in result["proposed_actions"])
    assert any("unspecified" in entry for entry in result["audit_log"])


def test_require_approved_by_rejects_a_missing_name_when_enabled(tenant, monkeypatch):
    monkeypatch.setenv("SENTINELOS_REQUIRE_APPROVED_BY", "true")
    _seed_pending_incident(tenant)

    with pytest.raises(ValueError, match="SENTINELOS_REQUIRE_APPROVED_BY"):
        resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)


def test_require_approved_by_accepts_a_real_name_when_enabled(tenant, monkeypatch):
    monkeypatch.setenv("SENTINELOS_REQUIRE_APPROVED_BY", "true")
    _seed_pending_incident(tenant)

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant, approved_by="j.smith")

    assert all(a.approved_by == "j.smith" for a in result["proposed_actions"])


def test_missing_approved_by_still_allowed_when_flag_not_set(tenant, monkeypatch):
    monkeypatch.delenv("SENTINELOS_REQUIRE_APPROVED_BY", raising=False)
    _seed_pending_incident(tenant)

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)

    assert result["incident"].status == "contained"


def test_concurrent_approve_calls_on_same_incident_never_overlap(tenant, monkeypatch, tmp_path):
    """Security regression: resolve_proposed_actions' read-modify-write
    cycle against a single incident's checkpoint must be serialized --
    two concurrent calls (a double-submitted click, two analysts, a
    retried request) must never actually execute their critical
    sections at the same time, or the loser's app.update_state would
    silently overwrite the winner's already-committed decision/audit
    entries (LangGraph's SqliteSaver has no compare-and-swap). Proven
    directly by instrumenting app.update_state to record how many
    threads are ever inside it concurrently, with an artificial delay
    long enough that an actual race would reliably be caught."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed_pending_incident(tenant, n_actions=1)

    app = get_app(tenant)
    original_update_state = app.update_state
    concurrency = {"current": 0, "max_seen": 0}
    counter_lock = threading.Lock()

    def _instrumented_update_state(*args, **kwargs):
        with counter_lock:
            concurrency["current"] += 1
            concurrency["max_seen"] = max(concurrency["max_seen"], concurrency["current"])
        time.sleep(0.05)  # long enough that a real race would overlap
        try:
            return original_update_state(*args, **kwargs)
        finally:
            with counter_lock:
                concurrency["current"] -= 1

    monkeypatch.setattr(app, "update_state", _instrumented_update_state)

    errors = []

    def _call(name):
        try:
            resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant, approved_by=name)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=_call, args=(f"analyst-{i}",)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert not errors
    assert concurrency["max_seen"] == 1


def test_raises_for_unknown_thread(tenant):
    with pytest.raises(ValueError):
        resolve_proposed_actions("never-existed", approve=True, tenant_id=tenant)


def test_raises_when_no_pending_actions(tenant):
    app = get_app(tenant)
    config = {"configurable": {"thread_id": "inc-no-actions"}}
    app.update_state(
        config,
        {
            "messages": [],
            "incident": Incident(id="inc-no-actions", description="x", status="investigating"),
            "long_term_summary": "",
            "audit_log": [],
            "next_agent": None,
            "proposed_actions": [],
            "token_usage": {},
            "tenant_id": tenant,
            "threat_intel": [],
            "attack_technique": None,
        },
    )

    with pytest.raises(ValueError):
        resolve_proposed_actions("inc-no-actions", approve=True, tenant_id=tenant)


def test_deny_does_not_mark_actions_approved_by_accident(tenant):
    """Regression guard for the obvious swap bug: denying must never
    leave approved=True on anything."""
    _seed_pending_incident(tenant, n_actions=2)

    result = resolve_proposed_actions("inc-1", approve=False, tenant_id=tenant, approved_by="j.smith")

    assert not any(a.approved is True for a in result["proposed_actions"])
    assert all(a.approved_by == "j.smith" for a in result["proposed_actions"])


# ---------- Remediation execution on approval ----------


def test_default_action_type_is_never_executed(tenant, monkeypatch, tmp_path):
    """A plain ProposedAction() defaults to action_type='other' -- must
    never be executed even with remediation fully enabled, since 'other'
    carries no machine-actionable shape."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    _seed_pending_incident(tenant)

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)

    assert all(a.executed is None for a in result["proposed_actions"])


def test_remediation_disabled_by_default_leaves_executed_none(tenant, monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SENTINELOS_REMEDIATION_ENABLED", raising=False)
    _seed_pending_incident(
        tenant, actions=[ProposedAction(action="Block IP", target="1.2.3.4", rationale="r", action_type="block_ip")]
    )

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)

    assert result["proposed_actions"][0].executed is None


def test_eligible_action_type_executed_true_under_dry_run_when_approved(tenant, monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    monkeypatch.delenv("SENTINELOS_REMEDIATION_DRY_RUN", raising=False)  # defaults to true
    _seed_pending_incident(
        tenant, actions=[ProposedAction(action="Block IP", target="1.2.3.4", rationale="r", action_type="block_ip")]
    )

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant, approved_by="j.smith")

    action = result["proposed_actions"][0]
    assert action.executed is True
    assert "dry_run" in action.execution_detail
    assert any("Remediation" in entry for entry in result["audit_log"])


def test_denial_never_attempts_remediation(tenant, monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    _seed_pending_incident(
        tenant, actions=[ProposedAction(action="Block IP", target="1.2.3.4", rationale="r", action_type="block_ip")]
    )

    result = resolve_proposed_actions("inc-1", approve=False, tenant_id=tenant)

    assert result["proposed_actions"][0].executed is None
    assert not any("Remediation" in entry for entry in result["audit_log"])


def test_mixed_batch_only_executes_the_eligible_action(tenant, monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    _seed_pending_incident(
        tenant,
        actions=[
            ProposedAction(action="Block IP", target="1.2.3.4", rationale="r", action_type="block_ip"),
            ProposedAction(action="Reset password", target="alice", rationale="r", action_type="reset_credentials"),
        ],
    )

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)

    by_target = {a.target: a for a in result["proposed_actions"]}
    assert by_target["1.2.3.4"].executed is True
    assert by_target["alice"].executed is None


# ---------- Playbook chain execution (roadmap #104) ----------


def _chain_actions(playbook_id="pb-1", on_failure=None):
    return [
        ProposedAction(
            action="Isolate host", target="WEB-01", rationale="r", action_type="isolate_host",
            playbook_id=playbook_id, chain_step=1, on_failure=on_failure,
        ),
        ProposedAction(
            action="Disable account", target="alice", rationale="r", action_type="disable_account",
            playbook_id=playbook_id, chain_step=2, on_failure=on_failure,
        ),
        ProposedAction(
            action="Block IP", target="1.2.3.4", rationale="r", action_type="block_ip",
            playbook_id=playbook_id, chain_step=3, on_failure=on_failure,
        ),
    ]


def test_playbook_chain_halts_remaining_steps_after_a_real_failure_by_default(tenant, monkeypatch, tmp_path):
    """No playbook file on disk for this playbook_id -> the halt policy
    defaults to "halt" (the safer default), same as an unrecognized/
    since-deleted playbook file would."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_DRY_RUN", "false")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ACTION_TYPES", "isolate_host,disable_account,block_ip")
    monkeypatch.delenv("SENTINELOS_PLAYBOOKS_DIR", raising=False)

    def _send(payload):
        if payload["target"] == "alice":  # step 2 fails
            return {"outcome": "http_error", "detail": "HTTP 500"}
        return {"outcome": "sent", "detail": "HTTP 200"}

    monkeypatch.setattr("remediation.pipeline.send_remediation_request", _send)
    _seed_pending_incident(tenant, actions=_chain_actions())

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)

    by_target = {a.target: a for a in result["proposed_actions"]}
    assert by_target["WEB-01"].executed is True
    assert by_target["alice"].executed is False
    assert by_target["1.2.3.4"].executed is None
    assert "skipped" in by_target["1.2.3.4"].execution_detail


def test_playbook_chain_continues_after_failure_when_policy_says_so(tenant, monkeypatch, tmp_path):
    """on_failure is pinned onto each ProposedAction at expansion time
    (playbooks/expander.py), not re-resolved from a playbook file on
    disk at approval time -- see the TOCTOU this closes in
    ProposedAction.on_failure's docstring. So this test sets on_failure
    directly on the seeded actions rather than writing a playbook file
    SENTINELOS_PLAYBOOKS_DIR would need to point at."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_DRY_RUN", "false")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ACTION_TYPES", "isolate_host,disable_account,block_ip")
    monkeypatch.delenv("SENTINELOS_PLAYBOOKS_DIR", raising=False)

    def _send(payload):
        if payload["target"] == "alice":  # step 2 fails
            return {"outcome": "http_error", "detail": "HTTP 500"}
        return {"outcome": "sent", "detail": "HTTP 200"}

    monkeypatch.setattr("remediation.pipeline.send_remediation_request", _send)
    _seed_pending_incident(tenant, actions=_chain_actions(on_failure="continue"))

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)

    by_target = {a.target: a for a in result["proposed_actions"]}
    assert by_target["WEB-01"].executed is True
    assert by_target["alice"].executed is False
    assert by_target["1.2.3.4"].executed is True  # not skipped -- policy is "continue"


def test_playbook_chain_policy_edit_on_disk_after_generation_has_no_effect(tenant, monkeypatch, tmp_path):
    """Security regression: editing (or deleting/recreating with a
    colliding id) the playbook file on disk after a chain was already
    generated must NOT change which policy governs that chain at
    approval time -- the policy pinned at generation time (here,
    "halt", via ProposedAction.on_failure) always wins, even if a file
    named the same playbook_id and declaring "continue" exists on disk
    when resolve_proposed_actions actually runs."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_DRY_RUN", "false")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ACTION_TYPES", "isolate_host,disable_account,block_ip")

    playbooks_dir = tmp_path / "playbooks"
    playbooks_dir.mkdir()
    import json

    (playbooks_dir / "pb.json").write_text(
        json.dumps(
            {
                "id": "pb-1", "name": "Test", "on_failure": "continue",
                "match": {"severities": ["high"]},
                "steps": [{"action_type": "block_ip", "action": "x", "target_template": "{ioc}", "rationale": "r"}],
            }
        )
    )
    monkeypatch.setenv("SENTINELOS_PLAYBOOKS_DIR", str(playbooks_dir))

    def _send(payload):
        if payload["target"] == "alice":
            return {"outcome": "http_error", "detail": "HTTP 500"}
        return {"outcome": "sent", "detail": "HTTP 200"}

    monkeypatch.setattr("remediation.pipeline.send_remediation_request", _send)
    # The chain was generated with on_failure="halt" pinned (e.g. from an
    # earlier version of the file, before it was edited to "continue").
    _seed_pending_incident(tenant, actions=_chain_actions(on_failure="halt"))

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)

    by_target = {a.target: a for a in result["proposed_actions"]}
    assert by_target["alice"].executed is False
    assert by_target["1.2.3.4"].executed is None  # halted, per the PINNED policy -- disk says "continue" and is ignored
    assert "skipped" in by_target["1.2.3.4"].execution_detail


def test_playbook_chain_failure_never_affects_an_independent_non_chain_action(tenant, monkeypatch, tmp_path):
    """Regression guard: a mixed incident with one failing playbook chain
    and one unrelated, non-playbook action must still execute the
    independent action normally."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_DRY_RUN", "false")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ACTION_TYPES", "isolate_host,disable_account,block_ip")
    monkeypatch.delenv("SENTINELOS_PLAYBOOKS_DIR", raising=False)

    def _send(payload):
        if payload["target"] == "WEB-01":  # the only chain step fails
            return {"outcome": "http_error", "detail": "HTTP 500"}
        return {"outcome": "sent", "detail": "HTTP 200"}

    monkeypatch.setattr("remediation.pipeline.send_remediation_request", _send)
    _seed_pending_incident(
        tenant,
        actions=[
            ProposedAction(
                action="Isolate host", target="WEB-01", rationale="r", action_type="isolate_host",
                playbook_id="pb-1", chain_step=1,
            ),
            ProposedAction(action="Block IP", target="9.9.9.9", rationale="r", action_type="block_ip"),
        ],
    )

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)

    by_target = {a.target: a for a in result["proposed_actions"]}
    assert by_target["WEB-01"].executed is False
    assert by_target["9.9.9.9"].executed is True


def test_not_automatable_step_in_a_chain_never_halts_it(tenant, monkeypatch, tmp_path):
    """executed is None ("not automatable") must never be confused with a
    real failure -- only an actual attempted-and-failed send halts a
    chain."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ACTION_TYPES", "isolate_host,block_ip")  # disable_account not eligible
    monkeypatch.delenv("SENTINELOS_PLAYBOOKS_DIR", raising=False)
    _seed_pending_incident(tenant, actions=_chain_actions())

    result = resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)

    by_target = {a.target: a for a in result["proposed_actions"]}
    assert by_target["WEB-01"].executed is True
    assert by_target["alice"].executed is None  # not automatable, not a failure
    assert by_target["1.2.3.4"].executed is True  # step 3 still ran -- chain wasn't halted
