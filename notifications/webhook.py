"""Generic webhook notifications — POST a JSON payload to any URL you
configure. This works natively with Slack, Discord, Microsoft Teams, and
PagerDuty's Events API (all of which accept a plain webhook POST), or
your own relay script, without this project picking a vendor — the same
"pluggable, not vendor-locked" principle as ingestion/polling.py.

Opt-in: nothing is ever sent unless SENTINELOS_ALERT_WEBHOOK_URL is set.
Never raises into the caller — a broken or unreachable webhook endpoint
must never block real incident processing, the same never-raise contract
every other external call in this project follows (enrichment/providers.py,
ingestion/semantic_correlation.py, etc.).

Signing (opt-in, SENTINELOS_WEBHOOK_SIGNING_SECRET): without it, anyone
who obtains (or guesses) the configured URL can send a receiver a
convincing-looking fake incident notification, and the receiver has no
way to tell it apart from a real one. Setting the secret HMAC-SHA256
signs every request body and sends it as X-SentinelOS-Signature, the
same "sha256=<hex>" shape GitHub/Stripe/Slack's own outbound webhooks
already use — additive, so it never breaks a receiver that doesn't check
it.
"""

import hashlib
import hmac
import json
import os


def _webhook_url() -> str:
    return os.getenv("SENTINELOS_ALERT_WEBHOOK_URL", "").strip()


def _signing_secret() -> str:
    return os.getenv("SENTINELOS_WEBHOOK_SIGNING_SECRET", "").strip()


def webhook_configured() -> bool:
    return bool(_webhook_url())


def sign_payload(body: bytes, secret: str) -> str:
    """HMAC-SHA256 of the exact raw bytes sent, hex-encoded and prefixed
    like GitHub/Stripe's own signature headers — a receiver verifies by
    recomputing this over the raw body they received (not a re-serialized
    version of the parsed JSON, which can reorder keys or reformat
    whitespace and silently break the comparison) and using a
    constant-time comparison against this header's value.
    """
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def send_webhook_notification(payload: dict) -> bool:
    """POST `payload` as JSON to SENTINELOS_ALERT_WEBHOOK_URL. Returns
    True if the request was sent and got a 2xx response, False for
    anything else (not configured, network failure, non-2xx) — never
    raises. Signs the body with SENTINELOS_WEBHOOK_SIGNING_SECRET if set.
    """
    url = _webhook_url()
    if not url:
        return False

    import requests

    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    secret = _signing_secret()
    if secret:
        headers["X-SentinelOS-Signature"] = sign_payload(body, secret)

    try:
        response = requests.post(url, data=body, headers=headers, timeout=10)
        return 200 <= response.status_code < 300
    except requests.RequestException:
        return False
