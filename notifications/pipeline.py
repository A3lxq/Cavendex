"""Decides WHEN an incident is worth interrupting a human for, and what
to tell them — the piece that closes a real gap: this project could
triage, investigate, and draft a remediation plan entirely on its own,
but had no way to actually tell anyone. An analyst had to go check the
dashboard or CLI to find out anything happened at all.

Two triggers, both real "a human should look at this" moments, not every
state change:

- The incident just reached `pending_approval` — the Responder Agent is
  waiting on an actual decision. This is the single most important
  "someone needs to act now" moment in the whole project.
- The incident's severity is at or above CAVENDEX_ALERT_MIN_SEVERITY
  (default "high"), regardless of status — so a critical incident still
  mid-investigation doesn't wait for Responder to get a human's
  attention.

Called explicitly from workflows/incident_pipeline.py at the three points
that represent genuinely new or updated incident state an analyst hasn't
seen yet (a freshly promoted incident, a correlated merge) — deliberately
NOT from resolve_proposed_actions (a human just acted, re-notifying them
of their own decision is noise) or run_threat_hunt (an analyst-initiated
query they're already looking at, not something to page them about).
"""

import os

from notifications.webhook import send_webhook_notification
from state import SEVERITY_RANK


def _min_alert_severity_rank() -> int:
    threshold = os.getenv("CAVENDEX_ALERT_MIN_SEVERITY", "high")
    return SEVERITY_RANK.get(threshold, 2)


def should_notify(incident) -> bool:
    if incident is None:
        return False
    if incident.status == "pending_approval":
        return True
    return SEVERITY_RANK.get(incident.severity, 1) >= _min_alert_severity_rank()


def _dashboard_link(tenant_id: str, thread_id: str) -> str:
    base = os.getenv("CAVENDEX_DASHBOARD_BASE_URL", "").rstrip("/")
    if not base:
        return ""
    tenant_segment = "" if tenant_id in (None, "default") else f"/tenants/{tenant_id}"
    return f"{base}{tenant_segment}/incidents/{thread_id}"


def build_notification_payload(state: dict, reason: str) -> dict:
    incident = state["incident"]
    tenant_id = state.get("tenant_id") or "default"
    link = _dashboard_link(tenant_id, incident.id)

    text = (
        f"[Cavendex] {incident.severity.upper()} incident {incident.id} "
        f"({incident.status}) in tenant '{tenant_id}': {incident.description[:200]}"
    )
    if link:
        text += f"\n{link}"

    payload = {
        # "text" is the key Slack/Discord incoming webhooks render
        # out of the box, with no template configuration needed.
        "text": text,
        "reason": reason,
        "thread_id": incident.id,
        "tenant_id": tenant_id,
        "severity": incident.severity,
        "status": incident.status,
        "description": incident.description,
    }
    if link:
        payload["dashboard_url"] = link
    return payload


def notify_if_needed(state: dict, reason: str = "incident_updated") -> None:
    """Send a webhook notification if `state`'s incident meets either
    trigger above. Swallows every failure — a broken webhook is a real
    operational problem worth knowing about (it's reflected in the
    boolean send_webhook_notification returns, for a caller that wants
    to log it), but it must never be allowed to break incident
    processing itself.
    """
    try:
        incident = state.get("incident")
        if not should_notify(incident):
            return
        send_webhook_notification(build_notification_payload(state, reason))
    except Exception:
        pass
