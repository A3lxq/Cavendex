"""Real, opt-in remediation execution behind the human approval gate —
the piece DEPLOYMENT.md's Known Limitations previously stated plainly:
"The Responder Agent never executes anything against a real system." It
still doesn't, directly — SentinelOS never runs a local shell command,
touches a firewall, or calls one specific EDR/SOAR vendor's API itself.
Instead, an approved, automatable action is POSTed to an operator-
configured webhook (the same "no vendor hardcoded, generic outbound
POST" principle as notifications/webhook.py) that the operator's own
SOAR platform, firewall API gateway, or custom script listens on —
SentinelOS asks; whatever's on the other end of that webhook decides
how (and whether) to actually act, sandboxed by construction on
infrastructure the operator controls and is responsible for validating.

Opt-in at two independent levels, both required before anything is
actually sent anywhere:
- SENTINELOS_REMEDIATION_ENABLED (default false) — the master switch.
- SENTINELOS_REMEDIATION_ACTION_TYPES (default "block_ip,isolate_host")
  — only a ProposedAction whose Responder-assigned action_type is in
  this list is eligible at all; "other" (the Responder's fallback when
  no cleaner category clearly fits) is never eligible regardless of
  this setting, since it carries no machine-actionable shape a receiver
  could safely act on.

SENTINELOS_REMEDIATION_DRY_RUN (default true whenever remediation is
enabled at all) is the literal sandbox: while true, nothing is ever
actually sent over the network — every eligible action is logged (the
audit log, plus a durable data/{tenant}/remediation_log.jsonl record via
remediation/pipeline.py) exactly as it would have been sent, so an
operator can verify the whole wire-up end-to-end before flipping this to
a real webhook call. Never raises into the caller — a broken or
unreachable remediation receiver must never block the approve flow
itself, the same never-raise contract every other external call in this
project follows (enrichment/providers.py, notifications/webhook.py).
"""

import hashlib
import hmac
import json
import os


def _remediation_enabled() -> bool:
    return os.getenv("SENTINELOS_REMEDIATION_ENABLED", "false").strip().lower() in ("1", "true", "yes")


def _dry_run() -> bool:
    return os.getenv("SENTINELOS_REMEDIATION_DRY_RUN", "true").strip().lower() in ("1", "true", "yes")


def _webhook_url() -> str:
    return os.getenv("SENTINELOS_REMEDIATION_WEBHOOK_URL", "").strip()


def _signing_secret() -> str:
    return os.getenv("SENTINELOS_REMEDIATION_WEBHOOK_SIGNING_SECRET", "").strip()


def _allowed_action_types() -> set:
    raw = os.getenv("SENTINELOS_REMEDIATION_ACTION_TYPES", "block_ip,isolate_host")
    return {v.strip() for v in raw.split(",") if v.strip()}


def is_automatable(action_type: str) -> bool:
    """Whether `action_type` is eligible for automated execution at all,
    given current configuration. "other" is never eligible regardless of
    SENTINELOS_REMEDIATION_ACTION_TYPES — it's the Responder's fallback
    for "no cleaner category applies," not a real machine-actionable
    request shape.
    """
    if action_type == "other":
        return False
    return _remediation_enabled() and action_type in _allowed_action_types()


def sign_payload(body: bytes, secret: str) -> str:
    """Same HMAC-SHA256 "sha256=<hex>" shape as
    notifications/webhook.py:sign_payload — a distinct secret
    (SENTINELOS_REMEDIATION_WEBHOOK_SIGNING_SECRET) since a remediation
    receiver is a materially more sensitive trust boundary than a
    notification channel and may reasonably be a different system.
    """
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def send_remediation_request(payload: dict) -> dict:
    """POST `payload` to SENTINELOS_REMEDIATION_WEBHOOK_URL, or simulate
    doing so under SENTINELOS_REMEDIATION_DRY_RUN (checked first — dry
    run never touches the network even if a URL happens to be
    configured). Returns {"outcome": ..., "detail": ...}; never raises.

    Outcomes: "dry_run" (nothing sent), "sent" (2xx response),
    "http_error" (non-2xx response), "request_failed" (network error),
    "not_configured" (remediation enabled and not a dry run, but no
    webhook URL set — a real misconfiguration worth surfacing distinctly
    from every other case rather than silently doing nothing).
    """
    if _dry_run():
        return {"outcome": "dry_run", "detail": "SENTINELOS_REMEDIATION_DRY_RUN is set; nothing was sent"}

    url = _webhook_url()
    if not url:
        return {"outcome": "not_configured", "detail": "SENTINELOS_REMEDIATION_WEBHOOK_URL is not set"}

    import requests

    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    secret = _signing_secret()
    if secret:
        headers["X-SentinelOS-Signature"] = sign_payload(body, secret)

    try:
        response = requests.post(url, data=body, headers=headers, timeout=15)
    except requests.RequestException as exc:
        return {"outcome": "request_failed", "detail": f"Request failed: {exc}"}

    if 200 <= response.status_code < 300:
        return {"outcome": "sent", "detail": f"HTTP {response.status_code}"}
    return {"outcome": "http_error", "detail": f"HTTP {response.status_code}: {response.text[:300]}"}
