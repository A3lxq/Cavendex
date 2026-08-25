"""Confirms workflows.incident_pipeline._persist() actually publishes to
utils.incident_events on every call site that matters for the
dashboard's live push — approve/deny being the one an analyst is most
likely to be watching happen from another open tab."""

import itertools

from graph import get_app
from state import Incident, ProposedAction
from utils.incident_events import reset_for_tests, subscribe
from workflows.incident_pipeline import resolve_proposed_actions

_tenant_counter = itertools.count()


def setup_function():
    reset_for_tests()


def _tenant():
    return f"persist-events-test-{next(_tenant_counter)}"


def _seed_pending_incident(tenant_id, thread_id="inc-1"):
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
            "proposed_actions": [ProposedAction(action="block", target="1.2.3.4", rationale="r")],
            "token_usage": {},
            "tenant_id": tenant_id,
            "threat_intel": [],
            "attack_technique": None,
        },
    )


def test_resolving_a_proposed_action_publishes_an_incident_updated_event():
    tenant = _tenant()
    _seed_pending_incident(tenant)
    q = subscribe(tenant)

    resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)

    event = q.get_nowait()
    assert event == {"type": "incident_updated", "thread_id": "inc-1"}


def test_a_subscriber_on_a_different_tenant_sees_nothing():
    tenant = _tenant()
    other_tenant = _tenant()
    _seed_pending_incident(tenant)
    q = subscribe(other_tenant)

    resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)

    assert q.empty()
