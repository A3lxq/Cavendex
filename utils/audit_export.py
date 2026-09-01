"""External anchor for the audit chain — see utils/audit_chain.py.

`record_chain()` gives detect-only tamper-evidence: it tells you whether an
incident's audit_log has changed since it was last persisted, but the
ledger recording that lives on the same host as everything else — an
attacker with the same filesystem access needed to edit audit_log in the
first place could, in principle, also rewrite the local ledger to match
(see audit_chain.py's own module docstring for the full honest limit).

This module closes that specific gap by shipping a copy of every ledger
entry off-box, to a webhook you control, the instant it's appended — an
attacker would now need to also compromise wherever that copy landed to
erase the anchor, a materially higher bar than editing one host's files.

Off by default (CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL unset) — fully inert,
same "opt-in, never a silent behavior change" convention as every other
optional integration in this project. Never raises: an export failure must
never block real incident persistence, the same contract every other
side-effect here follows (utils/incident_index.py, vault writes,
notifications/webhook.py). Unlike a routine alert notification, though, a
silently-failing external anchor would defeat the entire point of having
one — every export attempt's outcome (not just failures) is recorded to a
durable local data/{tenant}/audit_export_log.jsonl record, so a gap in the
anchor is itself locally detectable rather than a second silent failure
stacked on top of the first.
"""

import hashlib
import hmac
import json
import os

from utils.log_rotation import append_line
from utils.tenancy import sanitize_tenant_id


def _webhook_url() -> str:
    return os.getenv("CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL", "").strip()


def _signing_secret() -> str:
    return os.getenv("CAVENDEX_AUDIT_EXPORT_SIGNING_SECRET", "").strip()


def sign_payload(body: bytes, secret: str) -> str:
    """Same HMAC-SHA256 "sha256=<hex>" shape as notifications/webhook.py
    and remediation/executor.py's own sign_payload — a distinct secret
    (CAVENDEX_AUDIT_EXPORT_SIGNING_SECRET) since this is a different
    receiver with a different purpose.
    """
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _export_log_path(tenant_id: str) -> str:
    return os.path.join(
        os.getenv("CAVENDEX_DATA_DIR", "data"), sanitize_tenant_id(tenant_id), "audit_export_log.jsonl"
    )


def _record_export_outcome(tenant_id: str, entry: dict, outcome: dict) -> None:
    record = {
        "timestamp": entry.get("timestamp"),
        "thread_id": entry.get("thread_id"),
        "chain_hash": entry.get("chain_hash"),
        **outcome,
    }
    append_line(_export_log_path(tenant_id), json.dumps(record))


def send_audit_export(tenant_id: str, entry: dict) -> dict:
    """POST one audit-chain ledger entry (the same shape record_chain()
    appends locally) to CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL. Returns
    {"outcome": ..., "detail": ...}; never raises.

    Outcomes: "sent" (2xx response), "http_error" (non-2xx response),
    "request_failed" (network error). Deliberately returns early with no
    local log record at all when unconfigured — matching
    remediation/pipeline.py's own convention of only logging real attempts,
    not "this feature isn't in use," to avoid a no-op record on every
    single incident persist for the vast majority of deployments that
    never turn this on.
    """
    url = _webhook_url()
    if not url:
        return {"outcome": "not_configured", "detail": "CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL is not set"}

    import requests

    body = json.dumps(entry).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    secret = _signing_secret()
    if secret:
        headers["X-Cavendex-Audit-Export-Signature"] = sign_payload(body, secret)

    try:
        response = requests.post(url, data=body, headers=headers, timeout=10)
    except requests.RequestException as exc:
        outcome = {"outcome": "request_failed", "detail": f"Request failed: {exc}"}
    else:
        if 200 <= response.status_code < 300:
            outcome = {"outcome": "sent", "detail": f"HTTP {response.status_code}"}
        else:
            outcome = {"outcome": "http_error", "detail": f"HTTP {response.status_code}: {response.text[:300]}"}

    _record_export_outcome(tenant_id, entry, outcome)
    return outcome


def has_export_failures(tenant_id: str) -> bool:
    """Whether this tenant's local export log has ever recorded a failed
    (non-"sent") export outcome — used by `cli.py verify-audit` to flag
    that the external anchor may have gaps, without having to parse the
    whole log inline there.
    """
    path = _export_log_path(tenant_id)
    if not os.path.exists(path):
        return False
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("outcome") not in ("sent",):
                    return True
    except OSError:
        return False
    return False
