"""Tests notifications/case_sync.py: the not-configured no-op, real Jira
issue creation and comment-adding against a real local HTTP server
standing in for Jira Cloud's documented REST v2 API (not mocked
requests) -- the same tier Wazuh/Splunk/CrowdStrike already carry, since
no real Jira Cloud tenant is available to this project to test against."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from notifications.case_sync import is_configured, sync_incident
from state import Incident
from utils.incident_index import get_jira_issue_key, reset_for_tests, upsert_incident_summary

TENANT = "case-sync-test"


def setup_function():
    reset_for_tests()


def _isolate(monkeypatch, tmp_path):
    # incident_index.db is a real on-disk file per tenant -- reset_for_tests()
    # only clears the in-memory connection cache, not persisted rows, so
    # every test needs its own CAVENDEX_DATA_DIR to avoid seeing an
    # earlier test's jira_issue_key for the same tenant/thread_id.
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))


def _configure(monkeypatch, base_url):
    monkeypatch.setenv("CAVENDEX_JIRA_BASE_URL", base_url)
    monkeypatch.setenv("CAVENDEX_JIRA_EMAIL", "analyst@example.com")
    monkeypatch.setenv("CAVENDEX_JIRA_API_TOKEN", "fake-token")
    monkeypatch.setenv("CAVENDEX_JIRA_PROJECT_KEY", "SEC")


def _incident(thread_id="inc-1", **overrides):
    defaults = dict(id=thread_id, description="Brute force from 1.2.3.4", severity="high", status="investigating")
    defaults.update(overrides)
    return Incident(**defaults)


def _seed_index(tenant_id, incident):
    upsert_incident_summary(tenant_id, {"incident": incident, "tenant_id": tenant_id})


def test_not_configured_is_a_pure_noop(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    for var in ("CAVENDEX_JIRA_BASE_URL", "CAVENDEX_JIRA_EMAIL", "CAVENDEX_JIRA_API_TOKEN", "CAVENDEX_JIRA_PROJECT_KEY"):
        monkeypatch.delenv(var, raising=False)
    assert is_configured() is False

    def _fail(*a, **kw):
        raise AssertionError("must not call the network when unconfigured")

    monkeypatch.setattr("requests.post", _fail)

    incident = _incident()
    _seed_index(TENANT, incident)
    result = sync_incident(TENANT, incident)
    assert result["outcome"] == "not_configured"


# ---------- real HTTP ----------


class _JiraHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        self.seen.append({"path": self.path, "headers": dict(self.headers), "body": body})
        self.send_response(self.status_to_send)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if self.path == "/rest/api/2/issue":
            self.wfile.write(json.dumps({"key": "SEC-101"}).encode())
        else:
            self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


@pytest.fixture
def jira_server():
    seen = []

    class Handler(_JiraHandler):
        pass

    Handler.seen = seen
    Handler.status_to_send = 201

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.seen = seen
    server.handler_cls = Handler
    server.base_url = f"http://127.0.0.1:{server.server_address[1]}"
    yield server
    server.shutdown()
    server.server_close()


def test_first_sync_creates_a_real_issue_and_records_the_key(monkeypatch, tmp_path, jira_server):
    _isolate(monkeypatch, tmp_path)
    _configure(monkeypatch, jira_server.base_url)
    incident = _incident()
    _seed_index(TENANT, incident)

    result = sync_incident(TENANT, incident)

    assert result["outcome"] == "created"
    assert result["issue_key"] == "SEC-101"
    assert jira_server.seen[0]["path"] == "/rest/api/2/issue"
    assert jira_server.seen[0]["body"]["fields"]["project"] == {"key": "SEC"}
    assert jira_server.seen[0]["body"]["fields"]["summary"].startswith("[Cavendex]")
    assert get_jira_issue_key(TENANT, incident.id) == "SEC-101"


def test_second_sync_adds_a_comment_to_the_existing_issue_instead_of_creating_a_duplicate(monkeypatch, tmp_path, jira_server):
    _isolate(monkeypatch, tmp_path)
    _configure(monkeypatch, jira_server.base_url)
    incident = _incident(status="investigating")
    _seed_index(TENANT, incident)

    sync_incident(TENANT, incident)  # creates SEC-101
    incident.status = "closed"
    result = sync_incident(TENANT, incident)  # should comment, not create again

    assert result["outcome"] == "updated"
    assert len(jira_server.seen) == 2
    assert jira_server.seen[1]["path"] == "/rest/api/2/issue/SEC-101/comment"
    assert "closed" in jira_server.seen[1]["body"]["body"]


def test_uses_basic_auth_with_email_and_api_token(monkeypatch, tmp_path, jira_server):
    _isolate(monkeypatch, tmp_path)
    _configure(monkeypatch, jira_server.base_url)
    incident = _incident()
    _seed_index(TENANT, incident)

    sync_incident(TENANT, incident)

    import base64

    expected = "Basic " + base64.b64encode(b"analyst@example.com:fake-token").decode()
    assert jira_server.seen[0]["headers"]["Authorization"] == expected


def test_create_failure_is_recorded_and_never_raises(monkeypatch, tmp_path, jira_server):
    _isolate(monkeypatch, tmp_path)
    jira_server.handler_cls.status_to_send = 500
    _configure(monkeypatch, jira_server.base_url)
    incident = _incident()
    _seed_index(TENANT, incident)

    result = sync_incident(TENANT, incident)

    assert result["outcome"] == "http_error"
    assert get_jira_issue_key(TENANT, incident.id) is None


def test_unreachable_url_reports_request_failed(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _configure(monkeypatch, "http://127.0.0.1:1")
    incident = _incident()
    _seed_index(TENANT, incident)

    result = sync_incident(TENANT, incident)

    assert result["outcome"] == "request_failed"
