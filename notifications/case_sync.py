"""Jira Cloud case-management sync — creates a tracked Jira issue for
every incident and keeps it updated (via comments) as the incident
progresses, so an analyst's existing ticketing workflow doesn't need a
second, separate system of record for triage state. Off by default
(`CAVENDEX_JIRA_BASE_URL` unset); fully inert unset, the same "opt-in,
never required" convention every other optional integration in this
project follows.

Auth is Jira Cloud's own documented scheme: an API token plus the
account email, sent as HTTP Basic Auth — no OAuth dance needed, matching
this project's existing preference for the simplest auth model that's
still real (the same reasoning `poll_connector.py`'s static-token model
already uses for most SIEM/EDR APIs, and Splunk's oneshot search mode
over the more complex async job-poll flow). Uses Jira Cloud's REST API
v2 (`/rest/api/2/issue`), not v3 — v3 requires the `description` field in
Atlassian Document Format (a nested JSON structure); v2 still accepts a
plain string, which is the simpler, still-real, still-documented choice
for a plain-text incident summary.

Deliberately follows `remediation/executor.py`'s richer outcome-taxonomy
template, not `notifications/webhook.py`'s simpler fire-and-forget one: a
missed ticket sync is a real operational gap worth being able to see (an
analyst working from Jira who never gets a ticket has no idea an
incident happened) — every sync attempt's outcome is recorded to a
durable local log, the same reasoning `utils/audit_export.py` already
uses for its own external anchor.

No new Incident/state field for the Jira issue key — it's dashboard/index-
level bookkeeping, not part of the core incident model, so it lives in
`utils/incident_index.py` as a new column (`jira_issue_key`), the same
"small file, not a system" pattern `assigned_to` already uses, and is
excluded from `upsert_incident_summary`'s own INSERT/UPDATE for the same
reason: a routine pipeline re-upsert must never silently wipe it.
"""

import json
import os

from utils.log_rotation import append_line
from utils.tenancy import sanitize_tenant_id


def _base_url() -> str:
    return os.getenv("CAVENDEX_JIRA_BASE_URL", "").rstrip("/")


def _email() -> str:
    return os.getenv("CAVENDEX_JIRA_EMAIL", "")


def _api_token() -> str:
    return os.getenv("CAVENDEX_JIRA_API_TOKEN", "")


def _project_key() -> str:
    return os.getenv("CAVENDEX_JIRA_PROJECT_KEY", "")


def is_configured() -> bool:
    return bool(_base_url() and _email() and _api_token() and _project_key())


def _auth():
    return (_email(), _api_token())


def _sync_log_path(tenant_id: str) -> str:
    from graph import tenant_data_dir

    return os.path.join(tenant_data_dir(sanitize_tenant_id(tenant_id)), "jira_sync_log.jsonl")


def _record_outcome(tenant_id: str, thread_id: str, action: str, outcome: dict) -> None:
    record = {"thread_id": thread_id, "action": action, **outcome}
    append_line(_sync_log_path(tenant_id), json.dumps(record))


def _create_issue(incident) -> dict:
    """Real Jira Cloud issue creation. Returns {"outcome": ..., "detail":
    ..., "issue_key": ... on success}. Never raises.
    """
    import requests

    body = {
        "fields": {
            "project": {"key": _project_key()},
            "summary": f"[Cavendex] {incident.description[:200]}",
            "description": (
                f"Cavendex incident {incident.id}\n\n"
                f"Severity: {incident.severity}\n"
                f"Status: {incident.status}\n"
                f"Source: {incident.source or 'unknown'}\n"
                f"IOCs: {', '.join(incident.iocs) or 'none'}\n"
                f"Affected assets: {', '.join(incident.affected_assets) or 'none'}\n\n"
                f"{incident.description}"
            ),
            "issuetype": {"name": "Task"},
        }
    }
    try:
        response = requests.post(
            f"{_base_url()}/rest/api/2/issue", json=body, auth=_auth(), timeout=15
        )
    except requests.RequestException as exc:
        return {"outcome": "request_failed", "detail": f"Request failed: {exc}"}

    if 200 <= response.status_code < 300:
        issue_key = (response.json() or {}).get("key")
        if not issue_key:
            return {"outcome": "http_error", "detail": "2xx response had no issue key"}
        return {"outcome": "created", "detail": f"HTTP {response.status_code}", "issue_key": issue_key}
    return {"outcome": "http_error", "detail": f"HTTP {response.status_code}: {response.text[:300]}"}


def _add_comment(issue_key: str, incident) -> dict:
    """Adds a status-update comment to an already-created Jira issue,
    rather than overwriting it — a natural, append-only progress trail
    directly in Jira, the same "never rewrite history" instinct this
    project's own audit chain follows. Never raises.
    """
    import requests

    body = {
        "body": (
            f"Cavendex update — severity: {incident.severity}, status: {incident.status}. "
            f"IOCs: {', '.join(incident.iocs) or 'none'}."
        )
    }
    try:
        response = requests.post(
            f"{_base_url()}/rest/api/2/issue/{issue_key}/comment", json=body, auth=_auth(), timeout=15
        )
    except requests.RequestException as exc:
        return {"outcome": "request_failed", "detail": f"Request failed: {exc}"}

    if 200 <= response.status_code < 300:
        return {"outcome": "updated", "detail": f"HTTP {response.status_code}"}
    return {"outcome": "http_error", "detail": f"HTTP {response.status_code}: {response.text[:300]}"}


def sync_incident(tenant_id: str, incident) -> dict:
    """Creates a Jira issue for this incident the first time it's seen,
    or adds a progress comment to the already-created issue on every
    later call — called from every persist point (see
    workflows/incident_pipeline.py:_persist), the same "one call, the
    module itself decides create vs. update" shape as every other
    optional side-effect in this project. Returns
    {"outcome": ..., "detail": ...}; never raises, and a failure here
    must never block real incident processing.
    """
    if not is_configured():
        return {"outcome": "not_configured", "detail": "Jira sync is not configured"}

    from utils.incident_index import get_jira_issue_key, set_jira_issue_key

    existing_key = get_jira_issue_key(tenant_id, incident.id)
    if existing_key:
        result = _add_comment(existing_key, incident)
        _record_outcome(tenant_id, incident.id, "comment", result)
        return result

    result = _create_issue(incident)
    if result["outcome"] == "created":
        set_jira_issue_key(tenant_id, incident.id, result["issue_key"])
    _record_outcome(tenant_id, incident.id, "create", result)
    return result
