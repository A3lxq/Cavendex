"""Tests utils/auth_monitor.py's own logic — the auth-failure logging and
alert-threshold state machine — against a real local HTTP server for the
webhook side (same technique as test_notifications.py), not a mocked
requests.post."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from utils.auth_monitor import record_auth_failure, reset_for_tests


class _RecordingHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.seen.append(json.loads(body) if body else None)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def http_server():
    seen = []

    class Handler(_RecordingHandler):
        pass

    Handler.seen = seen
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.seen = seen
    server.url = f"http://127.0.0.1:{server.server_address[1]}/webhook"
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _isolate():
    reset_for_tests()
    yield
    reset_for_tests()


def test_every_failure_is_logged(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CAVENDEX_AUTH_FAILURE_ALERT_THRESHOLD", "0")  # logging only, no alert

    record_auth_failure("1.2.3.4", "/incidents/x", tenant_id="acme")

    log_path = tmp_path / "auth_failures.jsonl"
    assert log_path.exists()
    entry = json.loads(log_path.read_text().strip())
    assert entry["source_ip"] == "1.2.3.4"
    assert entry["path"] == "/incidents/x"
    assert entry["tenant_id"] == "acme"


def test_alert_fires_once_threshold_is_reached(monkeypatch, tmp_path, http_server):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CAVENDEX_ALERT_WEBHOOK_URL", http_server.url)
    monkeypatch.setenv("CAVENDEX_AUTH_FAILURE_ALERT_THRESHOLD", "3")
    monkeypatch.setenv("CAVENDEX_AUTH_FAILURE_WINDOW_SECONDS", "300")

    for _ in range(2):
        record_auth_failure("9.9.9.9", "/incidents")
    assert http_server.seen == []  # below threshold, no alert yet

    record_auth_failure("9.9.9.9", "/incidents")  # 3rd failure crosses the threshold

    assert len(http_server.seen) == 1
    assert http_server.seen[0]["reason"] == "auth_failure_burst"
    assert http_server.seen[0]["source_ip"] == "9.9.9.9"
    assert http_server.seen[0]["count"] == 3


def test_alert_does_not_refire_every_failure_after_threshold(monkeypatch, tmp_path, http_server):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CAVENDEX_ALERT_WEBHOOK_URL", http_server.url)
    monkeypatch.setenv("CAVENDEX_AUTH_FAILURE_ALERT_THRESHOLD", "2")

    for _ in range(5):
        record_auth_failure("9.9.9.9", "/incidents")

    assert len(http_server.seen) == 1  # not one alert per failure


def test_different_sources_tracked_independently(monkeypatch, tmp_path, http_server):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CAVENDEX_ALERT_WEBHOOK_URL", http_server.url)
    monkeypatch.setenv("CAVENDEX_AUTH_FAILURE_ALERT_THRESHOLD", "3")

    for _ in range(2):
        record_auth_failure("1.1.1.1", "/incidents")
    for _ in range(2):
        record_auth_failure("2.2.2.2", "/incidents")

    assert http_server.seen == []  # neither source alone crossed the threshold


def test_disabled_when_threshold_is_zero(monkeypatch, tmp_path, http_server):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CAVENDEX_ALERT_WEBHOOK_URL", http_server.url)
    monkeypatch.setenv("CAVENDEX_AUTH_FAILURE_ALERT_THRESHOLD", "0")

    for _ in range(10):
        record_auth_failure("9.9.9.9", "/incidents")

    assert http_server.seen == []


def test_never_raises_when_data_dir_is_unwritable(monkeypatch, tmp_path):
    # A regular file where a directory is expected — os.makedirs() fails
    # with a real OSError, not a guessed one.
    blocker = tmp_path / "blocks-the-directory"
    blocker.write_text("x")
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(blocker))
    monkeypatch.delenv("CAVENDEX_ALERT_WEBHOOK_URL", raising=False)

    record_auth_failure("1.2.3.4", "/incidents")  # must not raise
