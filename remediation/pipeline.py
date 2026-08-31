"""Wires remediation/executor.py into the approve flow
(workflows/incident_pipeline.py:resolve_proposed_actions) — deciding
which already-approved actions are even eligible, building what gets
sent, and recording what happened back onto the durable per-tenant
remediation log so an approved-but-failed execution is visible there
too, not only in the audit_log a caller happens to read right away.
"""

import json
import os

from graph import tenant_data_dir
from remediation.executor import is_automatable, send_remediation_request
from utils.log_rotation import append_line


def _dashboard_link(tenant_id: str, thread_id: str) -> str:
    base = os.getenv("CAVENDEX_DASHBOARD_BASE_URL", "").rstrip("/")
    if not base:
        return ""
    tenant_segment = "" if tenant_id in (None, "default") else f"/tenants/{tenant_id}"
    return f"{base}{tenant_segment}/incidents/{thread_id}"


def build_remediation_payload(incident, action, tenant_id: str) -> dict:
    payload = {
        "thread_id": incident.id,
        "tenant_id": tenant_id,
        "action_type": action.action_type,
        "action": action.action,
        "target": action.target,
        "rationale": action.rationale,
        "approved_by": action.approved_by,
        "incident_severity": incident.severity,
        "incident_description": incident.description,
    }
    link = _dashboard_link(tenant_id, incident.id)
    if link:
        payload["dashboard_url"] = link
    return payload


def _log_remediation(tenant_id: str, thread_id: str, action, result: dict) -> None:
    log_path = os.path.join(tenant_data_dir(tenant_id), "remediation_log.jsonl")
    record = {
        "thread_id": thread_id,
        "action_type": action.action_type,
        "action": action.action,
        "target": action.target,
        "approved_by": action.approved_by,
        **result,
    }
    append_line(log_path, json.dumps(record))


def execute_if_eligible(incident, action, tenant_id: str):
    """Attempt real remediation execution for one already-approved
    action. Returns (executed, detail):

    - (None, reason) if the action was never eligible at all (not
      automatable given current config) — no attempt was made; this is
      the ordinary case, not a failure.
    - (True, detail) if a real send succeeded, or a dry run completed.
    - (False, detail) if a real send was attempted and failed.

    Never raises — a broken remediation receiver must never break the
    approve flow itself.
    """
    if not is_automatable(action.action_type):
        return None, f"not automatable (action_type={action.action_type!r})"

    try:
        payload = build_remediation_payload(incident, action, tenant_id)
        result = send_remediation_request(payload)
    except Exception as exc:
        result = {"outcome": "error", "detail": f"Unexpected error building/sending request: {exc}"}

    try:
        _log_remediation(tenant_id, incident.id, action, result)
    except Exception:
        pass

    executed = result["outcome"] in ("sent", "dry_run")
    return executed, f"{result['outcome']}: {result['detail']}"
