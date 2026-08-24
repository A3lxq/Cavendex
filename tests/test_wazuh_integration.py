"""Tests examples/wazuh_integration.py's own mechanics — argument parsing,
reading the alert file Wazuh would write, and forwarding it — against a
real local HTTP server (same technique as test_notifications.py), not a
mocked `requests.post`. This does NOT verify Wazuh actually invokes the
script this way; that part is documented as unverified in the script's
own docstring, since this project has no live Wazuh manager to test
against.
"""

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "examples", "wazuh_integration.py")


class _RecordingHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.seen.append({"headers": dict(self.headers), "body": json.loads(body)})
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def _http_server():
    seen = []

    class Handler(_RecordingHandler):
        pass

    Handler.seen = seen
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.seen = seen
    server.url = f"http://127.0.0.1:{server.server_address[1]}/ingest/wazuh"
    return server


def _run_script(alert_file, api_key, hook_url):
    return subprocess.run(
        [sys.executable, SCRIPT, alert_file, api_key or "", hook_url or ""],
        capture_output=True, text=True,
    )


def test_forwards_the_alert_file_verbatim(tmp_path):
    server = _http_server()
    try:
        alert = {"rule": {"id": "5720", "level": 10, "description": "test"}, "agent": {"name": "host1"}}
        alert_file = tmp_path / "alert.json"
        alert_file.write_text(json.dumps(alert))

        result = _run_script(str(alert_file), "my-api-key", server.url)

        assert result.returncode == 0
        assert len(server.seen) == 1
        assert server.seen[0]["body"] == alert
    finally:
        server.shutdown()


def test_sets_bearer_auth_header_when_api_key_given(tmp_path):
    server = _http_server()
    try:
        alert_file = tmp_path / "alert.json"
        alert_file.write_text(json.dumps({"rule": {"id": "1", "level": 5, "description": "x"}}))

        _run_script(str(alert_file), "secret-key", server.url)

        assert server.seen[0]["headers"]["Authorization"] == "Bearer secret-key"
    finally:
        server.shutdown()


def test_omits_auth_header_when_no_api_key(tmp_path):
    server = _http_server()
    try:
        alert_file = tmp_path / "alert.json"
        alert_file.write_text(json.dumps({"rule": {"id": "1", "level": 5, "description": "x"}}))

        _run_script(str(alert_file), "", server.url)

        assert "Authorization" not in server.seen[0]["headers"]
    finally:
        server.shutdown()


def test_exits_nonzero_on_missing_alert_file():
    result = _run_script("/nonexistent/path/alert.json", "key", "http://127.0.0.1:1/ingest/wazuh")
    assert result.returncode != 0
    assert "could not read/parse" in result.stderr


def test_exits_nonzero_on_missing_hook_url(tmp_path):
    alert_file = tmp_path / "alert.json"
    alert_file.write_text(json.dumps({"rule": {"id": "1", "level": 5, "description": "x"}}))

    result = _run_script(str(alert_file), "key", "")

    assert result.returncode != 0
    assert "hook_url" in result.stderr


def test_exits_nonzero_on_unreachable_hook_url(tmp_path):
    alert_file = tmp_path / "alert.json"
    alert_file.write_text(json.dumps({"rule": {"id": "1", "level": 5, "description": "x"}}))

    # Nothing listens on this port — a real connection failure, not mocked.
    result = _run_script(str(alert_file), "key", "http://127.0.0.1:1/ingest/wazuh")

    assert result.returncode != 0
    assert "failed to forward" in result.stderr
