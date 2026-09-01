"""Tests utils/audit_export.py: the not-configured no-op, a real webhook
send against a real local HTTP server (not mocked requests), signing, and
the durable local export-outcome log has_export_failures() reads back --
same "prefer real I/O" approach as tests/test_remediation_executor.py."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from utils.audit_export import has_export_failures, send_audit_export, sign_payload

_ENTRY = {
    "timestamp": "2026-01-01T00:00:00+00:00",
    "thread_id": "audit-export-test",
    "audit_log_length": 2,
    "chain_hash": "deadbeef",
}


def _export_log_path(tenant_id="default"):
    return os.path.join(os.getenv("CAVENDEX_DATA_DIR", "data"), tenant_id, "audit_export_log.jsonl")


def test_not_configured_is_a_pure_noop_with_no_local_log_record(monkeypatch):
    monkeypatch.delenv("CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL", raising=False)

    def _fail(*a, **kw):
        raise AssertionError("must not call the network when unconfigured")

    monkeypatch.setattr("requests.post", _fail)

    result = send_audit_export("default", _ENTRY)
    assert result["outcome"] == "not_configured"
    assert not os.path.exists(_export_log_path())


# ---------- real HTTP ----------


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
    server.url = f"http://127.0.0.1:{server.server_address[1]}/audit-export"

    yield server

    server.shutdown()
    server.server_close()


def test_real_send_reaches_a_real_server_and_reports_sent(monkeypatch, http_server):
    monkeypatch.setenv("CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL", http_server.url)

    result = send_audit_export("default", _ENTRY)
    assert result["outcome"] == "sent"
    assert http_server.seen[0]["body"] == _ENTRY


def test_real_send_signs_the_body_when_secret_configured(monkeypatch, http_server):
    monkeypatch.setenv("CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL", http_server.url)
    monkeypatch.setenv("CAVENDEX_AUDIT_EXPORT_SIGNING_SECRET", "shh")

    send_audit_export("default", _ENTRY)

    sent = http_server.seen[0]
    expected = sign_payload(sent["raw_body"], "shh")
    assert sent["headers"]["X-Cavendex-Audit-Export-Signature"] == expected


def test_real_send_no_signature_header_when_no_secret(monkeypatch, http_server):
    monkeypatch.setenv("CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL", http_server.url)
    monkeypatch.delenv("CAVENDEX_AUDIT_EXPORT_SIGNING_SECRET", raising=False)

    send_audit_export("default", _ENTRY)
    assert "X-Cavendex-Audit-Export-Signature" not in http_server.seen[0]["headers"]


def test_real_send_non_2xx_reports_http_error(monkeypatch, http_server):
    http_server.handler_cls.status_to_send = 503
    monkeypatch.setenv("CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL", http_server.url)

    result = send_audit_export("default", _ENTRY)
    assert result["outcome"] == "http_error"
    assert "503" in result["detail"]


def test_unreachable_url_reports_request_failed(monkeypatch):
    monkeypatch.setenv("CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL", "http://127.0.0.1:1/unreachable")

    result = send_audit_export("default", _ENTRY)
    assert result["outcome"] == "request_failed"


# ---------- durable local export log ----------


def test_successful_send_is_recorded_locally_and_not_a_failure(monkeypatch, http_server):
    # Own tenant, isolated from every other test in this file -- the export
    # log is append-only, so reusing a tenant another test already wrote a
    # failure record into would make has_export_failures() correctly (but
    # confusingly, for this specific assertion) return True regardless of
    # what this test itself sent.
    tenant = "test-successful-send-only"
    monkeypatch.setenv("CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL", http_server.url)

    send_audit_export(tenant, _ENTRY)

    assert os.path.exists(_export_log_path(tenant))
    with open(_export_log_path(tenant)) as f:
        record = json.loads(f.readline())
    assert record["outcome"] == "sent"
    assert record["thread_id"] == "audit-export-test"
    assert has_export_failures(tenant) is False


def test_failed_send_is_recorded_and_flagged_as_a_failure(monkeypatch):
    tenant = "test-failed-send-only"
    monkeypatch.setenv("CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL", "http://127.0.0.1:1/unreachable")

    send_audit_export(tenant, _ENTRY)

    assert has_export_failures(tenant) is True


def test_has_export_failures_false_when_log_never_existed(monkeypatch):
    assert has_export_failures("a-tenant-with-no-export-log-at-all") is False


def test_has_export_failures_is_per_tenant(monkeypatch):
    monkeypatch.setenv("CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL", "http://127.0.0.1:1/unreachable")
    send_audit_export("tenant-a", _ENTRY)
    assert has_export_failures("tenant-a") is True
    assert has_export_failures("tenant-b") is False
