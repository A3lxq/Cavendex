"""Tests ingestion/sentinel_polling.py against two real local HTTP
servers -- one standing in for Azure AD's OAuth2 token endpoint, one
standing in for the Log Analytics query API -- real HTTP, real JSON
parsing, real query-string/header construction, the same "prefer real
I/O over a guessed shape" approach test_crowdstrike_polling.py already
uses. ingest_normalized_alert() itself is mocked in the poll_once()
tests -- its own decision logic is already covered by
test_ingestion_pipeline.py; these tests are about the connector's own
job: authenticating, querying, extracting, and advancing the cursor
correctly."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

import pytest

from ingestion.sentinel_polling import (
    SentinelConfig,
    _get_oauth_token,
    _token_cache,
    fetch_new_alerts,
    load_config,
    load_cursor,
    poll_once,
    save_cursor,
)


class _FakeHandler(BaseHTTPRequestHandler):
    """A minimal, real HTTP server standing in for either Azure AD's or
    Log Analytics' real endpoints. Configure per-path JSON responses via
    `handler.responses[path] = body_dict`; every request is recorded in
    `handler.seen` (method, path, headers, and the parsed JSON body for
    a POST)."""

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw_body = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw_body) if raw_body else None
        except json.JSONDecodeError:
            body = raw_body.decode(errors="replace")

        path = urlparse(self.path).path
        self.seen.append({"method": self.command, "path": path, "headers": dict(self.headers), "body": body})
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


def _start_server():
    seen = []
    responses = {}

    class Handler(_FakeHandler):
        pass

    Handler.seen = seen
    Handler.responses = responses

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    server.seen = seen
    server.responses = responses
    server.base_url = f"http://127.0.0.1:{server.server_address[1]}"
    return server


@pytest.fixture
def login_server():
    server = _start_server()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def api_server():
    server = _start_server()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _reset_token_cache():
    _token_cache.clear()
    yield
    _token_cache.clear()


def _config(login_server, api_server, **overrides):
    return SentinelConfig(
        name=overrides.pop("name", "sentinel-test"),
        workspace_id=overrides.pop("workspace_id", "ws-123"),
        login_base_url=login_server.base_url,
        api_base_url=api_server.base_url,
        **overrides,
    )


# ---------- _get_oauth_token ----------


def test_get_oauth_token_returns_none_without_credentials(monkeypatch, login_server, api_server):
    monkeypatch.delenv("AZURE_SENTINEL_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_SENTINEL_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_SENTINEL_CLIENT_SECRET", raising=False)
    config = _config(login_server, api_server)

    assert _get_oauth_token(config) is None
    assert login_server.seen == []  # never even attempted the exchange


def test_get_oauth_token_performs_a_real_client_credentials_exchange(monkeypatch, login_server, api_server):
    monkeypatch.setenv("AZURE_SENTINEL_TENANT_ID", "aad-tenant-1")
    monkeypatch.setenv("AZURE_SENTINEL_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("AZURE_SENTINEL_CLIENT_SECRET", "test-secret")
    login_server.responses["/aad-tenant-1/oauth2/v2.0/token"] = {"access_token": "real-token-abc", "expires_in": 3599}
    config = _config(login_server, api_server)

    token = _get_oauth_token(config)
    assert token == "real-token-abc"
    assert login_server.seen[0]["method"] == "POST"
    assert login_server.seen[0]["path"] == "/aad-tenant-1/oauth2/v2.0/token"


def test_get_oauth_token_is_cached_across_calls(monkeypatch, login_server, api_server):
    monkeypatch.setenv("AZURE_SENTINEL_TENANT_ID", "aad-tenant-1")
    monkeypatch.setenv("AZURE_SENTINEL_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("AZURE_SENTINEL_CLIENT_SECRET", "test-secret")
    login_server.responses["/aad-tenant-1/oauth2/v2.0/token"] = {"access_token": "cached-token", "expires_in": 3599}
    config = _config(login_server, api_server)

    _get_oauth_token(config)
    _get_oauth_token(config)
    assert len(login_server.seen) == 1  # second call hit the cache, not the network


def test_get_oauth_token_refreshes_once_expired(monkeypatch, login_server, api_server):
    monkeypatch.setenv("AZURE_SENTINEL_TENANT_ID", "aad-tenant-1")
    monkeypatch.setenv("AZURE_SENTINEL_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("AZURE_SENTINEL_CLIENT_SECRET", "test-secret")
    login_server.responses["/aad-tenant-1/oauth2/v2.0/token"] = {"access_token": "short-lived", "expires_in": 61}
    config = _config(login_server, api_server)

    _get_oauth_token(config)
    from ingestion.sentinel_polling import _token_cache as cache

    key = ("aad-tenant-1", "test-client-id")
    token, _expiry = cache[key]
    cache[key] = (token, time.monotonic() - 1)

    login_server.responses["/aad-tenant-1/oauth2/v2.0/token"] = {"access_token": "refreshed", "expires_in": 3599}
    new_token = _get_oauth_token(config)
    assert new_token == "refreshed"
    assert len(login_server.seen) == 2


# ---------- fetch_new_alerts ----------


def test_fetch_new_alerts_queries_the_configured_workspace_and_zips_rows(login_server, api_server):
    api_server.responses["/v1/workspaces/ws-123/query"] = {
        "tables": [
            {
                "columns": [{"name": "AlertName"}, {"name": "AlertSeverity"}, {"name": "TimeGenerated"}],
                "rows": [
                    ["Suspicious sign-in", "High", "2024-01-01T00:00:00Z"],
                    ["Impossible travel", "Medium", "2024-01-01T00:05:00Z"],
                ],
            }
        ]
    }
    config = _config(login_server, api_server)

    records, new_cursor = fetch_new_alerts(config, "fake-token", cursor=None)
    assert records == [
        {"AlertName": "Suspicious sign-in", "AlertSeverity": "High", "TimeGenerated": "2024-01-01T00:00:00Z"},
        {"AlertName": "Impossible travel", "AlertSeverity": "Medium", "TimeGenerated": "2024-01-01T00:05:00Z"},
    ]
    assert new_cursor == "2024-01-01T00:05:00Z"

    call = api_server.seen[0]
    assert call["method"] == "POST"
    assert call["path"] == "/v1/workspaces/ws-123/query"
    assert call["headers"]["Authorization"] == "Bearer fake-token"
    assert "SecurityAlert" in call["body"]["query"]


def test_fetch_new_alerts_includes_cursor_as_a_datetime_filter(login_server, api_server):
    api_server.responses["/v1/workspaces/ws-123/query"] = {"tables": [{"columns": [], "rows": []}]}
    config = _config(login_server, api_server)

    fetch_new_alerts(config, "fake-token", cursor="2024-01-01T00:00:00Z")

    query = api_server.seen[0]["body"]["query"]
    assert "datetime(2024-01-01T00:00:00Z)" in query


def test_fetch_new_alerts_handles_no_tables_in_response(login_server, api_server):
    api_server.responses["/v1/workspaces/ws-123/query"] = {"tables": []}
    config = _config(login_server, api_server)

    records, new_cursor = fetch_new_alerts(config, "fake-token", cursor="some-cursor")
    assert records == []
    assert new_cursor == "some-cursor"


# ---------- poll_once ----------


@pytest.fixture
def fake_ingest_normalized_alert(monkeypatch):
    calls = []

    def _fake(alert, tenant_id=None):
        calls.append({"alert": alert, "tenant_id": tenant_id})
        return {"outcome": "promoted", "thread_id": "fake-id"}

    monkeypatch.setattr("ingestion.pipeline.ingest_normalized_alert", _fake)
    return calls


def test_poll_once_returns_auth_failed_without_credentials(
    monkeypatch, login_server, api_server, fake_ingest_normalized_alert, tmp_path
):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("AZURE_SENTINEL_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_SENTINEL_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_SENTINEL_CLIENT_SECRET", raising=False)
    config = _config(login_server, api_server)

    results = poll_once(config)
    assert results == [{"outcome": "auth_failed"}]
    assert fake_ingest_normalized_alert == []


def test_poll_once_ingests_each_normalized_alert(
    monkeypatch, login_server, api_server, fake_ingest_normalized_alert, tmp_path
):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AZURE_SENTINEL_TENANT_ID", "aad-tenant-1")
    monkeypatch.setenv("AZURE_SENTINEL_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("AZURE_SENTINEL_CLIENT_SECRET", "test-secret")
    login_server.responses["/aad-tenant-1/oauth2/v2.0/token"] = {"access_token": "tok", "expires_in": 3599}
    api_server.responses["/v1/workspaces/ws-123/query"] = {
        "tables": [
            {
                "columns": [{"name": "AlertName"}, {"name": "AlertSeverity"}, {"name": "TimeGenerated"}],
                "rows": [["Suspicious sign-in", "High", "2024-01-01T00:00:00Z"]],
            }
        ]
    }
    config = _config(login_server, api_server, tenant="sentinel-tenant")

    results = poll_once(config)
    assert len(results) == 1
    assert len(fake_ingest_normalized_alert) == 1
    alert = fake_ingest_normalized_alert[0]["alert"]
    assert alert.severity == "high"
    assert "Suspicious sign-in" in alert.description
    assert fake_ingest_normalized_alert[0]["tenant_id"] == "sentinel-tenant"
    assert load_cursor(config) == "2024-01-01T00:00:00Z"


def test_poll_once_skips_records_with_no_alert_name(
    monkeypatch, login_server, api_server, fake_ingest_normalized_alert, tmp_path
):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AZURE_SENTINEL_TENANT_ID", "aad-tenant-1")
    monkeypatch.setenv("AZURE_SENTINEL_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("AZURE_SENTINEL_CLIENT_SECRET", "test-secret")
    login_server.responses["/aad-tenant-1/oauth2/v2.0/token"] = {"access_token": "tok", "expires_in": 3599}
    api_server.responses["/v1/workspaces/ws-123/query"] = {
        "tables": [{"columns": [{"name": "AlertSeverity"}], "rows": [["High"]]}]
    }
    config = _config(login_server, api_server)

    results = poll_once(config)
    assert results == []
    assert fake_ingest_normalized_alert == []


def test_poll_once_persists_cursor_across_calls(
    monkeypatch, login_server, api_server, fake_ingest_normalized_alert, tmp_path
):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AZURE_SENTINEL_TENANT_ID", "aad-tenant-1")
    monkeypatch.setenv("AZURE_SENTINEL_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("AZURE_SENTINEL_CLIENT_SECRET", "test-secret")
    login_server.responses["/aad-tenant-1/oauth2/v2.0/token"] = {"access_token": "tok", "expires_in": 3599}
    config = _config(login_server, api_server, name="cursor-persist-sentinel")

    api_server.responses["/v1/workspaces/ws-123/query"] = {
        "tables": [
            {
                "columns": [{"name": "AlertName"}, {"name": "TimeGenerated"}],
                "rows": [["Alert A", "2024-01-01T00:00:00Z"]],
            }
        ]
    }
    poll_once(config)
    assert load_cursor(config) == "2024-01-01T00:00:00Z"

    api_server.responses["/v1/workspaces/ws-123/query"] = {
        "tables": [
            {
                "columns": [{"name": "AlertName"}, {"name": "TimeGenerated"}],
                "rows": [["Alert B", "2024-01-01T01:00:00Z"]],
            }
        ]
    }
    poll_once(config)

    query_calls = [c for c in api_server.seen if c["path"] == "/v1/workspaces/ws-123/query"]
    assert "datetime(2024-01-01T00:00:00Z)" in query_calls[-1]["body"]["query"]
    assert load_cursor(config) == "2024-01-01T01:00:00Z"


def test_save_and_load_cursor_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    config = SentinelConfig(name="roundtrip-sentinel", workspace_id="ws-1", tenant="roundtrip-tenant")

    assert load_cursor(config) is None
    save_cursor(config, "abc")
    assert load_cursor(config) == "abc"


# ---------- load_config ----------


def test_load_config_from_the_shipped_example():
    config = load_config("examples/sentinel_poller_config.example.json")
    assert config.name == "sentinel-security-alerts"
    assert config.azure_ad_tenant_id_env == "AZURE_SENTINEL_TENANT_ID"
    assert config.client_id_env == "AZURE_SENTINEL_CLIENT_ID"
    assert config.client_secret_env == "AZURE_SENTINEL_CLIENT_SECRET"
    assert config.table == "SecurityAlert"


def test_load_config_ignores_unknown_comment_fields(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"_comment": "ignored", "name": "x", "workspace_id": "ws-1"}))
    config = load_config(str(path))
    assert config.name == "x"
