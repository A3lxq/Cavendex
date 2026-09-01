"""Tests examples/crowdstrike_rtr_receiver.py against two real local HTTP
servers -- one standing in for the receiver script itself (a real request/
response cycle, not calling its functions in-process), one standing in
for Falcon's OAuth2 and devices-actions API (the same fake-Falcon
approach test_crowdstrike_polling.py already uses, and the same real
OAuth2 helper -- ingestion.crowdstrike_polling._get_oauth_token -- reused
by the receiver itself, not reimplemented). This does NOT verify Falcon
actually behaves this way; that part is documented as unverified in the
receiver's own docstring, since this project has no live Falcon tenant
to test against."""

import hashlib
import hmac
import importlib.util
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

import pytest

from ingestion.crowdstrike_polling import _token_cache

_RECEIVER_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "examples", "crowdstrike_rtr_receiver.py")
_spec = importlib.util.spec_from_file_location("crowdstrike_rtr_receiver", _RECEIVER_PATH)
receiver = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(receiver)


@pytest.fixture(autouse=True)
def _reset_token_cache():
    _token_cache.clear()
    yield
    _token_cache.clear()


class _FakeFalconHandler(BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw_body = self.rfile.read(length) if length else b""
        path = urlparse(self.path).path
        self.seen.append({"method": self.command, "path": path, "raw_body": raw_body})
        response = self.responses.get(path, {})
        payload = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def log_message(self, *a):
        pass


@pytest.fixture
def falcon_server():
    seen = []
    responses = {
        "/oauth2/token": {"access_token": "fake-falcon-token", "expires_in": 1799},
        "/devices/queries/devices/v1": {"resources": ["aid-real-device-001"]},
        "/devices/entities/devices-actions/v2": {"resources": [{"id": "aid-real-device-001"}]},
    }

    class Handler(_FakeFalconHandler):
        pass

    Handler.seen = seen
    Handler.responses = responses

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.seen = seen
    server.responses = responses
    server.base_url = f"http://127.0.0.1:{server.server_address[1]}"
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def receiver_server(monkeypatch, falcon_server):
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("CROWDSTRIKE_BASE_URL", falcon_server.base_url)

    server = HTTPServer(("127.0.0.1", 0), receiver.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.url = f"http://127.0.0.1:{server.server_address[1]}/remediate"
    yield server
    server.shutdown()
    server.server_close()


def _post(url, body: dict, secret: str = None):
    import requests

    raw = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-Cavendex-Signature"] = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return requests.post(url, data=raw, headers=headers, timeout=10)


# ---------- _verify_signature ----------


def test_verify_signature_accepts_a_correctly_signed_body():
    body = b'{"a": 1}'
    sig = "sha256=" + hmac.new(b"shh", body, hashlib.sha256).hexdigest()
    assert receiver._verify_signature(body, sig, "shh") is True


def test_verify_signature_rejects_wrong_secret():
    body = b'{"a": 1}'
    sig = "sha256=" + hmac.new(b"wrong-secret", body, hashlib.sha256).hexdigest()
    assert receiver._verify_signature(body, sig, "shh") is False


def test_verify_signature_rejects_missing_header():
    assert receiver._verify_signature(b"{}", "", "shh") is False


# ---------- end-to-end over real HTTP ----------


def test_isolate_host_end_to_end_contains_the_real_device(monkeypatch, receiver_server, falcon_server):
    monkeypatch.setenv("CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET", "shared-secret")

    response = _post(
        receiver_server.url,
        {"action_type": "isolate_host", "target": "FIN-SRV-02", "thread_id": "inc-1"},
        secret="shared-secret",
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "contained"
    assert body["device_id"] == "aid-real-device-001"

    # Confirm the real call sequence actually happened against Falcon:
    # a real OAuth2 exchange, a real device lookup, a real contain call.
    paths = [r["path"] for r in falcon_server.seen]
    assert "/oauth2/token" in paths
    assert "/devices/queries/devices/v1" in paths
    assert "/devices/entities/devices-actions/v2" in paths


def test_rejects_request_with_bad_signature(monkeypatch, receiver_server):
    monkeypatch.setenv("CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET", "shared-secret")

    response = _post(
        receiver_server.url,
        {"action_type": "isolate_host", "target": "FIN-SRV-02"},
        secret="the-wrong-secret",
    )

    assert response.status_code == 401


def test_refuses_every_request_when_no_secret_configured_at_all(monkeypatch, receiver_server):
    """A real fix from a security review: this receiver executes a real
    network-isolation action, so unlike a routine notification receiver
    there's no safe "accept it anyway" default when unconfigured -- it
    must refuse (503) rather than silently act on an unsigned request."""
    monkeypatch.delenv("CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET", raising=False)

    response = _post(receiver_server.url, {"action_type": "isolate_host", "target": "FIN-SRV-02"})

    assert response.status_code == 503


def test_unimplemented_action_type_returns_501(monkeypatch, receiver_server):
    monkeypatch.setenv("CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET", "shared-secret")

    response = _post(receiver_server.url, {"action_type": "block_ip", "target": "1.2.3.4"}, secret="shared-secret")

    assert response.status_code == 501


def test_isolate_host_with_no_target_returns_400(monkeypatch, receiver_server):
    monkeypatch.setenv("CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET", "shared-secret")

    response = _post(receiver_server.url, {"action_type": "isolate_host"}, secret="shared-secret")

    assert response.status_code == 400


def test_isolate_host_with_invalid_hostname_returns_400(monkeypatch, receiver_server):
    """A real fix from a security review: a hostname is interpolated
    directly into a Falcon Query Language filter string
    (hostname:'<hostname>') to look up the target device -- an untrusted
    value (this project's own threat model already treats an incident's
    affected_assets, the source of this field, as attacker-influenceable)
    containing a stray quote or FQL syntax could change which device
    actually gets matched and isolated. A hostname outside a real
    hostname's normal character set is rejected outright rather than
    risked."""
    monkeypatch.setenv("CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET", "shared-secret")

    response = _post(
        receiver_server.url,
        {"action_type": "isolate_host", "target": "FIN-SRV-02' or hostname:'*"},
        secret="shared-secret",
    )

    assert response.status_code == 400


def test_isolate_host_with_unknown_hostname_returns_404(monkeypatch, receiver_server, falcon_server):
    monkeypatch.setenv("CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET", "shared-secret")
    falcon_server.responses["/devices/queries/devices/v1"] = {"resources": []}

    response = _post(
        receiver_server.url, {"action_type": "isolate_host", "target": "no-such-host"}, secret="shared-secret"
    )

    assert response.status_code == 404


def test_isolate_host_without_crowdstrike_credentials_returns_500(monkeypatch, receiver_server):
    monkeypatch.setenv("CAVENDEX_REMEDIATION_WEBHOOK_SIGNING_SECRET", "shared-secret")
    monkeypatch.delenv("CROWDSTRIKE_CLIENT_ID", raising=False)
    monkeypatch.delenv("CROWDSTRIKE_CLIENT_SECRET", raising=False)

    response = _post(
        receiver_server.url, {"action_type": "isolate_host", "target": "FIN-SRV-02"}, secret="shared-secret"
    )

    assert response.status_code == 500
