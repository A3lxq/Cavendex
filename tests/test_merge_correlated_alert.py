"""Tests workflows.incident_pipeline.merge_correlated_alert directly against
a real (LLM-free) LangGraph checkpoint — seeded via app.update_state rather
than a real agent run, since merging a correlated alert never invokes an
agent. Confirms the merge itself (IOCs/assets union, severity escalation,
audit trail) independent of how ingestion/correlation.py decided which
incident to merge into.

graph.py caches one compiled app per tenant_id for the life of the process
(and utils.incident_index caches one connection per tenant_id the same
way), so tests share process-wide state keyed by tenant — same reasoning
as test_tenancy.py/test_incident_index.py's per-tenant isolation. Each
test here uses its own tenant_id (via the `tenant` fixture) rather than a
fixed one, so no test can see another test's checkpoint or index rows.
"""

import itertools

import pytest

from graph import get_app
from state import Incident
from workflows.incident_pipeline import merge_correlated_alert

_tenant_counter = itertools.count()


@pytest.fixture
def tenant():
    return f"merge-test-{next(_tenant_counter)}"


def _seed_incident(tenant_id, thread_id="inc-1", **overrides):
    app = get_app(tenant_id)
    config = {"configurable": {"thread_id": thread_id}}
    defaults = dict(
        id=thread_id,
        description="original incident",
        severity="medium",
        status="investigating",
        iocs=["1.2.3.4"],
        affected_assets=["FIN-SRV-02"],
    )
    defaults.update(overrides)
    app.update_state(
        config,
        {
            "messages": [],
            "incident": Incident(**defaults),
            "long_term_summary": "",
            "audit_log": ["Triage -> escalated"],
            "next_agent": None,
            "proposed_actions": [],
            "token_usage": {},
            "tenant_id": tenant_id,
            "threat_intel": [],
            "attack_technique": None,
        },
    )


def test_merge_unions_new_iocs_and_assets_without_duplicating(tenant):
    _seed_incident(tenant)

    result = merge_correlated_alert(
        thread_id="inc-1",
        description="second alert, same campaign",
        severity="medium",
        affected_assets=["FIN-SRV-02", "FIN-SRV-03"],
        iocs=["1.2.3.4", "5.6.7.8"],
        source="ingestion:suricata",
        tenant_id=tenant,
    )

    incident = result["incident"]
    assert sorted(incident.iocs) == ["1.2.3.4", "5.6.7.8"]
    assert sorted(incident.affected_assets) == ["FIN-SRV-02", "FIN-SRV-03"]


def test_merge_escalates_severity_but_never_downgrades(tenant):
    _seed_incident(tenant, severity="medium")

    escalated = merge_correlated_alert(
        thread_id="inc-1",
        description="worse alert",
        severity="critical",
        affected_assets=[],
        iocs=["1.2.3.4"],
        source="test",
        tenant_id=tenant,
    )
    assert escalated["incident"].severity == "critical"

    not_downgraded = merge_correlated_alert(
        thread_id="inc-1",
        description="milder alert",
        severity="low",
        affected_assets=[],
        iocs=["1.2.3.4"],
        source="test",
        tenant_id=tenant,
    )
    assert not_downgraded["incident"].severity == "critical"


def test_merge_appends_audit_entry_and_message_without_losing_history(tenant):
    _seed_incident(tenant)

    result = merge_correlated_alert(
        thread_id="inc-1",
        description="second alert",
        severity="medium",
        affected_assets=[],
        iocs=["1.2.3.4"],
        source="ingestion:suricata",
        tenant_id=tenant,
    )

    assert "Triage -> escalated" in result["audit_log"]
    assert any("Correlation" in entry for entry in result["audit_log"])
    assert len(result["messages"]) == 1
    message = result["messages"][0]
    name = message.get("name") if isinstance(message, dict) else getattr(message, "name", None)
    assert name == "Correlation"


def test_merge_records_the_match_reason_in_audit_log_and_message(tenant):
    _seed_incident(tenant)

    result = merge_correlated_alert(
        thread_id="inc-1",
        description="second alert",
        severity="medium",
        affected_assets=[],
        iocs=["10.0.0.9"],
        source="ingestion:suricata",
        tenant_id=tenant,
        match_reason="'10.0.0.9' and '10.0.0.5' are both in 10.0.0.0/24",
    )

    assert any("10.0.0.0/24" in entry for entry in result["audit_log"])
    message = result["messages"][0]
    content = message.get("content") if isinstance(message, dict) else getattr(message, "content", "")
    assert "10.0.0.0/24" in content


def test_merge_uses_a_default_match_reason_when_none_given(tenant):
    _seed_incident(tenant)

    result = merge_correlated_alert(
        thread_id="inc-1",
        description="second alert",
        severity="medium",
        affected_assets=[],
        iocs=["1.2.3.4"],
        source="ingestion:suricata",
        tenant_id=tenant,
    )

    assert any("shared indicator" in entry for entry in result["audit_log"])


def test_merge_folds_semantic_judge_usage_into_token_usage(tenant):
    _seed_incident(tenant)

    result = merge_correlated_alert(
        thread_id="inc-1",
        description="second alert",
        severity="medium",
        affected_assets=[],
        iocs=["1.2.3.4"],
        source="ingestion:test",
        tenant_id=tenant,
        match_reason="same TTP against a different host",
        usage={"input_tokens": 40, "output_tokens": 10, "total_tokens": 50},
    )

    by_agent = result["token_usage"]["by_agent"]
    assert by_agent["Correlation Judge"]["total_tokens"] == 50
    assert result["token_usage"]["total_tokens"] == 50


def test_merge_without_usage_does_not_touch_token_usage(tenant):
    _seed_incident(tenant)

    result = merge_correlated_alert(
        thread_id="inc-1",
        description="second alert",
        severity="medium",
        affected_assets=[],
        iocs=["1.2.3.4"],
        source="ingestion:suricata",
        tenant_id=tenant,
    )

    assert result.get("token_usage") == {}


def test_merge_raises_for_unknown_thread(tenant):
    with pytest.raises(ValueError):
        merge_correlated_alert(
            thread_id="never-existed",
            description="x",
            severity="medium",
            affected_assets=[],
            iocs=["1.2.3.4"],
            source="test",
            tenant_id=tenant,
        )
