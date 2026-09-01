#!/usr/bin/env python3
"""A real receiver for Cavendex's remediation webhook (see remediation/
executor.py) that actually carries out an approved `isolate_host` action
via CrowdStrike Falcon's Real Time Response / Hosts API — a concrete,
symmetric counterpart to this project's existing CrowdStrike *ingest*
connector (ingestion/crowdstrike_polling.py), reusing that exact same
OAuth2 client-credentials helper rather than reimplementing it.

Cavendex itself never calls a firewall/EDR/IAM API directly (see README's
Security Notes) — it POSTs an approved, eligible action to whatever
receiver you configure via CAVENDEX_REMEDIATION_WEBHOOK_URL. This script
IS that receiver, for one concrete vendor and one concrete action type.
Run it yourself, on infrastructure you control, alongside Cavendex; it is
not started automatically by anything in this project.

What it does on a real approved `isolate_host` action:
  1. Verifies the request's X-Cavendex-Signature HMAC (see
     remediation/executor.py:sign_payload) against
     CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET -- rejects anything that
     doesn't match, so only Cavendex (which knows the shared secret) can
     trigger a real containment action through this receiver.
  2. Exchanges CROWDSTRIKE_CLIENT_ID/CROWDSTRIKE_CLIENT_SECRET for a real
     OAuth2 bearer token (ingestion.crowdstrike_polling._get_oauth_token
     -- the same cached, auto-refreshing exchange the ingest connector
     already uses; nothing about OAuth2 is reimplemented here).
  3. Looks up the target hostname's real Falcon Agent ID (AID) via
     GET /devices/queries/devices/v1?filter=hostname:'<hostname>'.
  4. Calls POST /devices/entities/devices-actions/v2?action_name=contain
     with that AID -- Falcon's real "Network Containment" action, which
     isolates the host from the network except for traffic to the Falcon
     cloud itself.

Every other action_type (block_ip, disable_account, reset_credentials,
"other") is deliberately NOT implemented here -- this is one concrete,
honestly-scoped worked example, not a general-purpose remediation
receiver. Extending it to another action type or vendor API is a
straightforward addition to _handle_isolate_host below, following the
same shape.

HONESTY NOTE: the OAuth2 exchange and Hosts/RTR API call shapes are built
from CrowdStrike's documented Falcon API, not verified against a live
Falcon tenant -- this project has none to honestly test against (the
same caveat as every other vendor-specific integration; see README's
Known Gaps). Verified instead against a real local HTTP server matching
Falcon's documented OAuth2 and devices-actions API shapes, the same tier
ingestion/crowdstrike_polling.py itself was verified against.

Usage:
    export CROWDSTRIKE_CLIENT_ID=...
    export CROWDSTRIKE_CLIENT_SECRET=...
    export CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET=a-shared-secret
    python examples/crowdstrike_rtr_receiver.py --port 9100

Then in Cavendex's own .env:
    CAVENDEX_REMEDIATION_ENABLED=true
    CAVENDEX_REMEDIATION_ACTION_TYPES=isolate_host
    CAVENDEX_REMEDIATION_WEBHOOK_URL=http://<this-host>:9100/remediate
    CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET=a-shared-secret   # must match
    CAVENDEX_REMEDIATION_DRY_RUN=false   # only once you've verified the wiring under dry-run
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ingestion.crowdstrike_polling import CrowdStrikeConfig, _get_oauth_token  # noqa: E402


def _falcon_config() -> CrowdStrikeConfig:
    return CrowdStrikeConfig(
        name="rtr-receiver",
        base_url=os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com"),
    )


def _verify_signature(body: bytes, signature_header: str, secret: str) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def _lookup_device_id(token: str, base_url: str, hostname: str):
    import requests

    response = requests.get(
        f"{base_url}/devices/queries/devices/v1",
        headers={"Authorization": f"Bearer {token}"},
        params={"filter": f"hostname:'{hostname}'"},
        timeout=30,
    )
    response.raise_for_status()
    resources = (response.json() or {}).get("resources") or []
    return resources[0] if resources else None


def _contain_device(token: str, base_url: str, device_id: str) -> dict:
    import requests

    response = requests.post(
        f"{base_url}/devices/entities/devices-actions/v2",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        params={"action_name": "contain"},
        json={"ids": [device_id]},
        timeout=30,
    )
    return {"status_code": response.status_code, "body": response.text[:500]}


def _handle_isolate_host(payload: dict) -> tuple:
    """Returns (http_status, response_body_dict)."""
    hostname = payload.get("target")
    if not hostname:
        return 400, {"error": "payload has no target hostname"}

    config = _falcon_config()
    token = _get_oauth_token(config)
    if not token:
        return 500, {"error": "CROWDSTRIKE_CLIENT_ID/CROWDSTRIKE_CLIENT_SECRET not configured"}

    device_id = _lookup_device_id(token, config.base_url, hostname)
    if not device_id:
        return 404, {"error": f"no Falcon-managed device found for hostname {hostname!r}"}

    result = _contain_device(token, config.base_url, device_id)
    if 200 <= result["status_code"] < 300:
        return 200, {"status": "contained", "device_id": device_id, "falcon_response": result["body"]}
    return 502, {"status": "falcon_error", "device_id": device_id, "falcon_response": result["body"]}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)

        secret = os.getenv("CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET", "")
        if secret and not _verify_signature(body, self.headers.get("X-Cavendex-Signature", ""), secret):
            self._respond(401, {"error": "invalid or missing signature"})
            return

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON body"})
            return

        action_type = payload.get("action_type")
        print(f"Received remediation request: action_type={action_type} target={payload.get('target')}", flush=True)

        if action_type == "isolate_host":
            status, response_body = _handle_isolate_host(payload)
        else:
            status, response_body = 501, {"error": f"this example receiver only implements isolate_host, got {action_type!r}"}

        self._respond(status, response_body)

    def _respond(self, status: int, body: dict):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description="Real CrowdStrike Falcon RTR receiver for Cavendex remediation")
    parser.add_argument("--port", type=int, default=9100)
    args = parser.parse_args()

    if not os.getenv("CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET"):
        print(
            "⚠️  CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET is not set — this receiver will accept "
            "an unsigned request from anyone who can reach it. Set it (and the matching value in "
            "Cavendex's own .env) before pointing a real deployment at this."
        )

    server = HTTPServer(("0.0.0.0", args.port), Handler)
    print(f"CrowdStrike RTR remediation receiver listening on :{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
