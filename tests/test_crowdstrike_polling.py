"""Tests ingestion/crowdstrike_polling.py against a real local HTTP
server standing in for the Falcon API's OAuth2 token endpoint and its
two-step query/summarize Detects flow -- real HTTP, real JSON parsing,
real query-string/header construction, the same "prefer real I/O over a
guessed shape" approach test_polling_connector.py and
test_syslog_listener.py already use. ingest_normalized_alert() itself is
mocked in the poll_once() tests -- its own decision logic is already
covered by test_ingestion_pipeline.py; these tests are about the
connector's own job: authenticating, fetching, extracting, and advancing
the cursor correctly."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from ingestion.crowdstrike_polling import (
    CrowdStrikeConfig,
    _get_oauth_token,
    _token_cache,
    fetch_new_detections,
    load_config,
    load_cursor,
    poll_once,
    save_cursor,
)


class _FakeFalconHandler(BaseHTTPRequestHandler):
    """A minimal, real HTTP server standing in for the Falcon API's real
    endpoints. Configure per-path JSON responses via
    `handler.responses[path] = body_dict`; every request is recorded in
    `handler.seen` (method, path, query params, headers, and the parsed
    JSON body for a POST)."""

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw_body = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw_body) if raw_body and self.headers.get("Content-Type", "").startswith(
                "application/json"
            ) else None
        except json.JSONDecodeError:
            body = None

        path = urlparse(self.path).path
        self.seen.append(
            {
                "method": self.command,
                "path": path,
                "query": parse_qs(urlparse(self.path).query),
                "headers": dict(self.headers),
                "body": body,
            }
        )
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
    responses = {}

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


@pytest.fixture(autouse=True)
def _reset_token_cache():
    _token_cache.clear()
    yield
    _token_cache.clear()


def _config(base_url, **overrides):
    return CrowdStrikeConfig(name=overrides.pop("name", "cs-test"), base_url=base_url, **overrides)


# ---------- _get_oauth_token ----------


def test_get_oauth_token_returns_none_without_credentials(monkeypatch, falcon_server):
    monkeypatch.delenv("CROWDSTRIKE_CLIENT_ID", raising=False)
    monkeypatch.delenv("CROWDSTRIKE_CLIENT_SECRET", raising=False)
    config = _config(falcon_server.base_url)

    assert _get_oauth_token(config) is None
    assert falcon_server.seen == []  # never even attempted the exchange


def test_get_oauth_token_performs_a_real_client_credentials_exchange(monkeypatch, falcon_server):
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "test-secret")
    falcon_server.responses["/oauth2/token"] = {"access_token": "real-token-abc", "expires_in": 1799}
    config = _config(falcon_server.base_url)

    token = _get_oauth_token(config)
    assert token == "real-token-abc"
    assert falcon_server.seen[0]["method"] == "POST"
    assert falcon_server.seen[0]["path"] == "/oauth2/token"


def test_get_oauth_token_is_cached_across_calls(monkeypatch, falcon_server):
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "test-secret")
    falcon_server.responses["/oauth2/token"] = {"access_token": "cached-token", "expires_in": 1799}
    config = _config(falcon_server.base_url)

    _get_oauth_token(config)
    _get_oauth_token(config)
    assert len(falcon_server.seen) == 1  # second call hit the cache, not the network


def test_get_oauth_token_refreshes_once_expired(monkeypatch, falcon_server):
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "test-secret")
    falcon_server.responses["/oauth2/token"] = {"access_token": "short-lived", "expires_in": 61}
    config = _config(falcon_server.base_url)

    _get_oauth_token(config)
    # Force the cached entry to look already-expired without a real sleep.
    from ingestion.crowdstrike_polling import _token_cache as cache

    key = (config.base_url, "test-client-id")
    token, _expiry = cache[key]
    cache[key] = (token, time.monotonic() - 1)

    falcon_server.responses["/oauth2/token"] = {"access_token": "refreshed", "expires_in": 1799}
    new_token = _get_oauth_token(config)
    assert new_token == "refreshed"
    assert len(falcon_server.seen) == 2


# ---------- fetch_new_detections ----------


def test_fetch_new_detections_performs_the_real_two_step_flow(falcon_server):
    falcon_server.responses["/detects/queries/detects/v1"] = {"resources": ["ldt:a:1", "ldt:a:2"]}
    falcon_server.responses["/detects/entities/summaries/GET/v1"] = {
        "resources": [
            {"detection_id": "ldt:a:1", "created_timestamp": "2024-01-01T00:00:00Z"},
            {"detection_id": "ldt:a:2", "created_timestamp": "2024-01-01T00:05:00Z"},
        ]
    }
    config = _config(falcon_server.base_url)

    summaries, new_cursor = fetch_new_detections(config, "fake-token", cursor=None)
    assert [s["detection_id"] for s in summaries] == ["ldt:a:1", "ldt:a:2"]
    assert new_cursor == "2024-01-01T00:05:00Z"

    query_call = next(c for c in falcon_server.seen if c["path"] == "/detects/queries/detects/v1")
    assert query_call["headers"]["Authorization"] == "Bearer fake-token"
    summary_call = next(c for c in falcon_server.seen if c["path"] == "/detects/entities/summaries/GET/v1")
    assert summary_call["body"] == {"ids": ["ldt:a:1", "ldt:a:2"]}


def test_fetch_new_detections_sends_cursor_as_a_filter(falcon_server):
    falcon_server.responses["/detects/queries/detects/v1"] = {"resources": []}
    config = _config(falcon_server.base_url)

    fetch_new_detections(config, "fake-token", cursor="2024-01-01T00:00:00Z")

    query_call = falcon_server.seen[0]
    assert query_call["query"]["filter"] == ["created_timestamp:>'2024-01-01T00:00:00Z'"]


def test_fetch_new_detections_no_new_ids_short_circuits_before_the_summary_call(falcon_server):
    falcon_server.responses["/detects/queries/detects/v1"] = {"resources": []}
    config = _config(falcon_server.base_url)

    summaries, new_cursor = fetch_new_detections(config, "fake-token", cursor="some-cursor")
    assert summaries == []
    assert new_cursor == "some-cursor"
    assert not any(c["path"] == "/detects/entities/summaries/GET/v1" for c in falcon_server.seen)


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
    monkeypatch, falcon_server, fake_ingest_normalized_alert, tmp_path
):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CROWDSTRIKE_CLIENT_ID", raising=False)
    monkeypatch.delenv("CROWDSTRIKE_CLIENT_SECRET", raising=False)
    config = _config(falcon_server.base_url)

    results = poll_once(config)
    assert results == [{"outcome": "auth_failed"}]
    assert fake_ingest_normalized_alert == []


def test_poll_once_ingests_each_normalized_detection(
    monkeypatch, falcon_server, fake_ingest_normalized_alert, tmp_path
):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "test-secret")
    falcon_server.responses["/oauth2/token"] = {"access_token": "tok", "expires_in": 1799}
    falcon_server.responses["/detects/queries/detects/v1"] = {"resources": ["ldt:a:1"]}
    falcon_server.responses["/detects/entities/summaries/GET/v1"] = {
        "resources": [
            {
                "detection_id": "ldt:a:1",
                "created_timestamp": "2024-01-01T00:00:00Z",
                "max_severity_displayname": "High",
                "device": {"hostname": "WORKSTATION-01"},
            }
        ]
    }
    config = _config(falcon_server.base_url, tenant="cs-tenant")

    results = poll_once(config)
    assert len(results) == 1
    assert len(fake_ingest_normalized_alert) == 1
    alert = fake_ingest_normalized_alert[0]["alert"]
    assert alert.severity == "high"
    assert "WORKSTATION-01" in alert.description
    assert fake_ingest_normalized_alert[0]["tenant_id"] == "cs-tenant"
    assert load_cursor(config) == "2024-01-01T00:00:00Z"


def test_poll_once_skips_non_dict_summaries(monkeypatch, falcon_server, fake_ingest_normalized_alert, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "test-secret")
    falcon_server.responses["/oauth2/token"] = {"access_token": "tok", "expires_in": 1799}
    falcon_server.responses["/detects/queries/detects/v1"] = {"resources": ["x"]}
    falcon_server.responses["/detects/entities/summaries/GET/v1"] = {"resources": ["not a dict"]}
    config = _config(falcon_server.base_url)

    results = poll_once(config)
    assert results == []
    assert fake_ingest_normalized_alert == []


def test_poll_once_persists_cursor_across_calls(
    monkeypatch, falcon_server, fake_ingest_normalized_alert, tmp_path
):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "test-secret")
    falcon_server.responses["/oauth2/token"] = {"access_token": "tok", "expires_in": 1799}
    config = _config(falcon_server.base_url, name="cursor-persist-cs")

    falcon_server.responses["/detects/queries/detects/v1"] = {"resources": ["ldt:a:1"]}
    falcon_server.responses["/detects/entities/summaries/GET/v1"] = {
        "resources": [{"detection_id": "ldt:a:1", "created_timestamp": "2024-01-01T00:00:00Z"}]
    }
    poll_once(config)
    assert load_cursor(config) == "2024-01-01T00:00:00Z"

    falcon_server.responses["/detects/queries/detects/v1"] = {"resources": ["ldt:a:2"]}
    falcon_server.responses["/detects/entities/summaries/GET/v1"] = {
        "resources": [{"detection_id": "ldt:a:2", "created_timestamp": "2024-01-01T01:00:00Z"}]
    }
    poll_once(config)

    query_calls = [c for c in falcon_server.seen if c["path"] == "/detects/queries/detects/v1"]
    assert query_calls[-1]["query"]["filter"] == ["created_timestamp:>'2024-01-01T00:00:00Z'"]
    assert load_cursor(config) == "2024-01-01T01:00:00Z"


def test_save_and_load_cursor_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    config = CrowdStrikeConfig(name="roundtrip-cs", tenant="roundtrip-tenant")

    assert load_cursor(config) is None
    save_cursor(config, "abc")
    assert load_cursor(config) == "abc"


# ---------- load_config ----------


def test_load_config_from_the_shipped_example():
    config = load_config("examples/crowdstrike_poller_config.example.json")
    assert config.name == "crowdstrike-detects"
    assert config.client_id_env == "CROWDSTRIKE_CLIENT_ID"
    assert config.client_secret_env == "CROWDSTRIKE_CLIENT_SECRET"


def test_load_config_ignores_unknown_comment_fields(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"_comment": "ignored", "name": "x"}))
    config = load_config(str(path))
    assert config.name == "x"
