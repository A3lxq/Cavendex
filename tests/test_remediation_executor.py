"""Tests remediation/executor.py: the eligibility gate (is_automatable),
the dry-run sandbox, and the real webhook send against a real local HTTP
server (not mocked requests) -- the same "prefer real I/O" approach as
notifications/webhook.py's own tests."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from remediation.executor import is_automatable, send_remediation_request, sign_payload


# ---------- is_automatable ----------


def test_other_is_never_automatable_even_when_enabled_and_listed(monkeypatch):
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ACTION_TYPES", "other,block_ip")
    assert is_automatable("other") is False


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SENTINELOS_REMEDIATION_ENABLED", raising=False)
    assert is_automatable("block_ip") is False


def test_enabled_and_in_default_allowlist(monkeypatch):
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    monkeypatch.delenv("SENTINELOS_REMEDIATION_ACTION_TYPES", raising=False)
    assert is_automatable("block_ip") is True
    assert is_automatable("isolate_host") is True


def test_enabled_but_not_in_allowlist(monkeypatch):
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ACTION_TYPES", "block_ip")
    assert is_automatable("disable_account") is False


def test_custom_allowlist_can_add_a_type(monkeypatch):
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ENABLED", "true")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_ACTION_TYPES", "disable_account,reset_credentials")
    assert is_automatable("disable_account") is True
    assert is_automatable("block_ip") is False


# ---------- send_remediation_request: dry run ----------


def test_dry_run_is_the_default_and_never_calls_the_network(monkeypatch):
    monkeypatch.delenv("SENTINELOS_REMEDIATION_DRY_RUN", raising=False)
    monkeypatch.setenv("SENTINELOS_REMEDIATION_WEBHOOK_URL", "http://127.0.0.1:1/should-never-be-hit")

    def _fail(*a, **kw):
        raise AssertionError("must not call the network in dry-run mode")

    monkeypatch.setattr("requests.post", _fail)

    result = send_remediation_request({"action_type": "block_ip"})
    assert result["outcome"] == "dry_run"


def test_explicit_dry_run_false_but_no_url_reports_not_configured(monkeypatch):
    monkeypatch.setenv("SENTINELOS_REMEDIATION_DRY_RUN", "false")
    monkeypatch.delenv("SENTINELOS_REMEDIATION_WEBHOOK_URL", raising=False)

    result = send_remediation_request({"action_type": "block_ip"})
    assert result["outcome"] == "not_configured"


# ---------- send_remediation_request: real HTTP ----------


class _RecordingHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)
        self.seen.append({"body": json.loads(body), "headers": dict(self.headers), "raw_body": body})
        self.send_response(self.status_to_send)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


@pytest.fixture
def http_server():
    seen = []

    class Handler(_RecordingHandler):
        pass

    Handler.seen = seen
    Handler.status_to_send = 200

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    server.seen = seen
    server.handler_cls = Handler
    server.url = f"http://127.0.0.1:{server.server_address[1]}/remediate"

    yield server

    server.shutdown()
    server.server_close()


def test_real_send_reaches_a_real_server_and_reports_sent(monkeypatch, http_server):
    monkeypatch.setenv("SENTINELOS_REMEDIATION_DRY_RUN", "false")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_WEBHOOK_URL", http_server.url)

    result = send_remediation_request({"action_type": "block_ip", "target": "1.2.3.4"})
    assert result["outcome"] == "sent"
    assert http_server.seen[0]["body"] == {"action_type": "block_ip", "target": "1.2.3.4"}


def test_real_send_signs_the_body_when_secret_configured(monkeypatch, http_server):
    monkeypatch.setenv("SENTINELOS_REMEDIATION_DRY_RUN", "false")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_WEBHOOK_URL", http_server.url)
    monkeypatch.setenv("SENTINELOS_REMEDIATION_WEBHOOK_SIGNING_SECRET", "shh")

    send_remediation_request({"action_type": "block_ip"})

    sent = http_server.seen[0]
    expected = sign_payload(sent["raw_body"], "shh")
    assert sent["headers"]["X-SentinelOS-Signature"] == expected


def test_real_send_no_signature_header_when_no_secret(monkeypatch, http_server):
    monkeypatch.setenv("SENTINELOS_REMEDIATION_DRY_RUN", "false")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_WEBHOOK_URL", http_server.url)
    monkeypatch.delenv("SENTINELOS_REMEDIATION_WEBHOOK_SIGNING_SECRET", raising=False)

    send_remediation_request({"action_type": "block_ip"})
    assert "X-SentinelOS-Signature" not in http_server.seen[0]["headers"]


def test_real_send_non_2xx_reports_http_error(monkeypatch, http_server):
    http_server.handler_cls.status_to_send = 503
    monkeypatch.setenv("SENTINELOS_REMEDIATION_DRY_RUN", "false")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_WEBHOOK_URL", http_server.url)

    result = send_remediation_request({"action_type": "block_ip"})
    assert result["outcome"] == "http_error"
    assert "503" in result["detail"]


def test_unreachable_url_reports_request_failed(monkeypatch):
    monkeypatch.setenv("SENTINELOS_REMEDIATION_DRY_RUN", "false")
    monkeypatch.setenv("SENTINELOS_REMEDIATION_WEBHOOK_URL", "http://127.0.0.1:1/unreachable")

    result = send_remediation_request({"action_type": "block_ip"})
    assert result["outcome"] == "request_failed"
