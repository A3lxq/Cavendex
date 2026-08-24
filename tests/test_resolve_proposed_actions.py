"""Tests workflows.incident_pipeline.resolve_proposed_actions directly
against a real LangGraph checkpoint (seeded via app.update_state, same
technique as test_merge_correlated_alert.py) — this is the human-in-the-
loop gate the entire project is built around, and until now it had zero
dedicated tests, unit or otherwise. Also covers the approved_by
accountability field added after a live review found that the audit
trail could never say *who* approved a proposed action."""

import itertools

import pytest

from graph import get_app
from state import Incident, ProposedAction
from workflows.incident_pipeline import resolve_proposed_actions

_tenant_counter = itertools.count()


@pytest.fixture
def tenant():
    return f"resolve-test-{next(_tenant_counter)}"


def _seed_pending_incident(tenant_id, thread_id="inc-1", n_actions=1):
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
            "proposed_actions": [
                ProposedAction(action=f"block-{i}", target=f"1.2.3.{i}", rationale="r") for i in range(n_actions)
            ],
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
