"""Tests remediation/pipeline.py's execute_if_eligible -- the glue
between an already-approved ProposedAction and remediation/executor.py,
including that a broken/misbehaving executor never raises out of this
function (it must never break the approve flow), and that a real,
durable remediation_log.jsonl record is written."""

import json

from remediation.pipeline import build_remediation_payload, execute_if_eligible
from state import Incident, ProposedAction


def _incident(**overrides):
    defaults = dict(id="inc-1", description="brute force", severity="high", status="pending_approval")
    defaults.update(overrides)
    return Incident(**defaults)


def _action(**overrides):
    defaults = dict(action="Block IP", target="203.0.113.9", rationale="active brute force", action_type="block_ip")
    defaults.update(overrides)
    return ProposedAction(**defaults)


def test_not_automatable_returns_none_without_attempting_anything(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SENTINELOS_REMEDIATION_ENABLED", raising=False)

    def _fail(*a, **kw):
        raise AssertionError("must not attempt to send when not automatable")

    monkeypatch.setattr("remediation.pipeline.send_remediation_request", _fail)

    executed, detail = execute_if_eligible(_incident(), _action(), "t1")
    assert executed is None
    assert "not automatable" in detail


def test_other_action_type_is_never_automatable(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ACTION_TYPES", "other")

    executed, detail = execute_if_eligible(_incident(), _action(action_type="other"), "t1")
    assert executed is None


def test_eligible_dry_run_reports_executed_true(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    monkeypatch.delenv("SENTINELOS_REMEDIATION_DRY_RUN", raising=False)  # defaults to true

    executed, detail = execute_if_eligible(_incident(), _action(), "t1")
    assert executed is True
    assert "dry_run" in detail


def test_eligible_real_send_failure_reports_executed_false(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_DRY_RUN", "false")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_WEBHOOK_URL", "http://127.0.0.1:1/unreachable")

    executed, detail = execute_if_eligible(_incident(), _action(), "t1")
    assert executed is False
    assert "request_failed" in detail


def test_executor_exception_is_caught_and_reported_as_not_executed(monkeypatch, tmp_path):
    """A broken/misbehaving executor call must never propagate out of
    execute_if_eligible -- this is called from the approve flow, which
    must never be broken by a remediation-side bug."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")

    def _raise(*a, **kw):
        raise RuntimeError("boom")

    monkeypatch.setattr("remediation.pipeline.send_remediation_request", _raise)

    executed, detail = execute_if_eligible(_incident(), _action(), "t1")
    assert executed is False
    assert "error" in detail.lower()


def test_writes_a_durable_remediation_log_record(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")

    execute_if_eligible(_incident(), _action(), "log-tenant")

    log_path = tmp_path / "log-tenant" / "remediation_log.jsonl"
    assert log_path.exists()
    record = json.loads(log_path.read_text(encoding="utf-8").strip().splitlines()[0])
    assert record["thread_id"] == "inc-1"
    assert record["action_type"] == "block_ip"
    assert record["target"] == "203.0.113.9"
    assert record["outcome"] == "dry_run"


def test_not_automatable_writes_no_log_record(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SENTINELOS_REMEDIATION_ENABLED", raising=False)

    execute_if_eligible(_incident(), _action(), "no-log-tenant")

    log_path = tmp_path / "no-log-tenant" / "remediation_log.jsonl"
    assert not log_path.exists()


def test_build_remediation_payload_shape():
    payload = build_remediation_payload(_incident(), _action(approved_by="j.smith"), "t1")
    assert payload["thread_id"] == "inc-1"
    assert payload["tenant_id"] == "t1"
    assert payload["action_type"] == "block_ip"
    assert payload["target"] == "203.0.113.9"
    assert payload["approved_by"] == "j.smith"
    assert payload["incident_severity"] == "high"


def test_build_remediation_payload_includes_dashboard_link_when_configured(monkeypatch):
    monkeypatch.setenv("SENTINELOS_DASHBOARD_BASE_URL", "https://sentinelos.example.com")
    payload = build_remediation_payload(_incident(), _action(), "t1")
    assert payload["dashboard_url"] == "https://sentinelos.example.com/tenants/t1/incidents/inc-1"


def test_build_remediation_payload_omits_dashboard_link_when_not_configured(monkeypatch):
    monkeypatch.delenv("SENTINELOS_DASHBOARD_BASE_URL", raising=False)
    payload = build_remediation_payload(_incident(), _action(), "t1")
    assert "dashboard_url" not in payload
