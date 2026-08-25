"""Tests ingestion/polling.py against a real local HTTP server (Python's
stdlib http.server) rather than mocking `requests` — genuinely exercises
HTTP GET/POST, query params, headers, and JSON parsing over a real
socket, the same "prefer real I/O over a guessed shape" approach used for
syslog_listener.py's socket tests and the live provider tests elsewhere
in this project. ingest_normalized_alert() itself is mocked in the
poll_once() tests — its own decision logic is already covered by
test_ingestion_pipeline.py; these tests are about the connector's own
job: fetching, extracting, mapping, and advancing the cursor correctly.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from ingestion.polling import (
    PollerConfig,
    _get_nested,
    fetch_records,
    load_config,
    load_cursor,
    normalize_polled_record,
    poll_once,
    save_cursor,
)


class _RecordingHandler(BaseHTTPRequestHandler):
    """Serves whatever JSON body the test configured via
    `_RecordingHandler.responses` and records every request it receives
    (path, query params, headers) into `_RecordingHandler.seen`."""

    def _handle(self):
        self.seen.append(
            {
                "method": self.command,
                "path": self.path,
                "query": parse_qs(urlparse(self.path).query),
                "headers": dict(self.headers),
            }
        )
        body = json.dumps(self.responses[min(len(self.seen) - 1, len(self.responses) - 1)]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def log_message(self, *a):
        pass


@pytest.fixture
def http_server():
    """Starts a real local HTTP server for the duration of one test.
    Configure its responses via `server.set_responses([...])`, read what
    it received via `server.seen`."""
    seen = []
    responses = [{}]

    class Handler(_RecordingHandler):
        pass

    Handler.seen = seen
    Handler.responses = responses

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    server.seen = seen
    server.set_responses = lambda r: responses.__setitem__(slice(None), r)
    server.url = f"http://127.0.0.1:{server.server_address[1]}/alerts"

    yield server

    server.shutdown()
    server.server_close()


# ---------- _get_nested ----------


def test_get_nested_simple_key():
    assert _get_nested({"a": 1}, "a") == 1


def test_get_nested_dotted_path():
    assert _get_nested({"a": {"b": {"c": 42}}}, "a.b.c") == 42


def test_get_nested_list_index():
    assert _get_nested({"a": [10, 20, 30]}, "a.1") == 20


def test_get_nested_missing_path_returns_none():
    assert _get_nested({"a": 1}, "a.b.c") is None
    assert _get_nested({"a": 1}, "x") is None


def test_get_nested_empty_path_returns_whole_object():
    data = {"a": 1}
    assert _get_nested(data, None) is data
    assert _get_nested(data, "") is data


# ---------- normalize_polled_record ----------


def test_normalize_polled_record_maps_all_fields():
    record = {
        "title": "Suspicious login",
        "severity": "high",
        "source_name": "acme-siem",
        "indicators": ["1.2.3.4"],
        "affected_hosts": ["WEB-01"],
        "alert_id": "abc123",
    }
    field_map = {
        "description": "title", "severity": "severity", "source": "source_name",
        "iocs": "indicators", "affected_assets": "affected_hosts", "dedup_key": "alert_id",
    }
    alert = normalize_polled_record(record, field_map, "fallback-source")
    assert alert.description == "Suspicious login"
    assert alert.severity == "high"
    assert alert.source == "acme-siem"
    assert alert.iocs == ["1.2.3.4"]
    assert alert.affected_assets == ["WEB-01"]
    assert alert.dedup_key == "abc123"


def test_normalize_polled_record_defaults_missing_fields():
    alert = normalize_polled_record({}, {}, "fallback-source")
    assert alert.description == "Untitled alert"
    assert alert.severity == "medium"
    assert alert.source == "fallback-source"
    assert alert.iocs == []
    assert alert.affected_assets == []
    assert alert.dedup_key  # a hash, but non-empty


def test_normalize_polled_record_invalid_severity_falls_back_to_medium():
    alert = normalize_polled_record({"sev": "apocalyptic"}, {"severity": "sev"}, "src")
    assert alert.severity == "medium"


def test_normalize_polled_record_scalar_ioc_becomes_single_item_list():
    alert = normalize_polled_record({"ip": "1.2.3.4"}, {"iocs": "ip"}, "src")
    assert alert.iocs == ["1.2.3.4"]


def test_normalize_polled_record_dedup_key_is_stable_for_identical_records():
    record = {"a": 1, "b": 2}
    a1 = normalize_polled_record(record, {}, "src")
    a2 = normalize_polled_record(record, {}, "src")
    assert a1.dedup_key == a2.dedup_key


def test_normalize_polled_record_non_dict_returns_none():
    assert normalize_polled_record("not a dict", {}, "src") is None
    assert normalize_polled_record(None, {}, "src") is None


def test_normalize_polled_record_applies_severity_map():
    alert = normalize_polled_record(
        {"sev": "informational"}, {"severity": "sev"}, "src", severity_map={"informational": "low"}
    )
    assert alert.severity == "low"


def test_normalize_polled_record_severity_map_miss_falls_back_to_medium():
    alert = normalize_polled_record(
        {"sev": "unmapped-value"}, {"severity": "sev"}, "src", severity_map={"informational": "low"}
    )
    assert alert.severity == "medium"


def test_normalize_polled_record_no_severity_map_behaves_as_before():
    alert = normalize_polled_record({"sev": "high"}, {"severity": "sev"}, "src")
    assert alert.severity == "high"


# ---------- fetch_records against a real HTTP server ----------


def test_fetch_records_extracts_via_records_path(http_server):
    http_server.set_responses([{"results": [{"title": "a"}, {"title": "b"}]}])
    config = PollerConfig(name="t", base_url=http_server.url, records_path="results")

    records, cursor = fetch_records(config, cursor=None)
    assert records == [{"title": "a"}, {"title": "b"}]
    assert cursor is None


def test_fetch_records_body_itself_is_the_list_when_no_records_path(http_server):
    http_server.set_responses([[{"title": "a"}]])
    config = PollerConfig(name="t", base_url=http_server.url, records_path=None)

    records, _ = fetch_records(config, cursor=None)
    assert records == [{"title": "a"}]


def test_fetch_records_advances_cursor_from_last_record(http_server):
    http_server.set_responses([{"results": [{"ts": "100"}, {"ts": "200"}]}])
    config = PollerConfig(name="t", base_url=http_server.url, records_path="results", cursor_field="ts")

    _, new_cursor = fetch_records(config, cursor=None)
    assert new_cursor == "200"


def test_fetch_records_sends_cursor_as_query_param(http_server):
    http_server.set_responses([{"results": []}])
    config = PollerConfig(
        name="t", base_url=http_server.url, records_path="results", cursor_query_param="since",
    )

    fetch_records(config, cursor="12345")
    assert http_server.seen[0]["query"]["since"] == ["12345"]


def test_fetch_records_sends_static_query_params(http_server):
    http_server.set_responses([{"results": []}])
    config = PollerConfig(
        name="t", base_url=http_server.url, records_path="results",
        static_query_params={"limit": "50"},
    )

    fetch_records(config, cursor=None)
    assert http_server.seen[0]["query"]["limit"] == ["50"]


def test_fetch_records_sends_auth_header_from_env_var(http_server, monkeypatch):
    monkeypatch.setenv("TEST_POLLER_TOKEN", "sekret123")
    http_server.set_responses([{"results": []}])
    config = PollerConfig(
        name="t", base_url=http_server.url, records_path="results",
        auth_header="Authorization", auth_scheme="Bearer", auth_token_env="TEST_POLLER_TOKEN",
    )

    fetch_records(config, cursor=None)
    assert http_server.seen[0]["headers"]["Authorization"] == "Bearer sekret123"


def test_fetch_records_no_auth_header_when_env_var_unset(http_server, monkeypatch):
    monkeypatch.delenv("TEST_POLLER_TOKEN_MISSING", raising=False)
    http_server.set_responses([{"results": []}])
    config = PollerConfig(
        name="t", base_url=http_server.url, records_path="results",
        auth_header="Authorization", auth_token_env="TEST_POLLER_TOKEN_MISSING",
    )

    fetch_records(config, cursor=None)
    assert "Authorization" not in http_server.seen[0]["headers"]


def test_fetch_records_uses_configured_method(http_server):
    http_server.set_responses([{"results": []}])
    config = PollerConfig(name="t", base_url=http_server.url, records_path="results", method="POST")

    fetch_records(config, cursor=None)
    assert http_server.seen[0]["method"] == "POST"


# ---------- poll_once: cursor persistence + ingestion ----------


@pytest.fixture
def fake_ingest_normalized_alert(monkeypatch):
    calls = []

    def _fake(alert, tenant_id=None):
        calls.append({"alert": alert, "tenant_id": tenant_id})
        return {"outcome": "promoted", "thread_id": "fake-id"}

    monkeypatch.setattr("ingestion.pipeline.ingest_normalized_alert", _fake)
    return calls


def test_poll_once_ingests_each_record(http_server, fake_ingest_normalized_alert, monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    http_server.set_responses(
        [{"results": [{"title": "first"}, {"title": "second"}]}]
    )
    config = PollerConfig(
        name="poll-once-test", base_url=http_server.url, records_path="results",
        field_map={"description": "title"}, tenant="poll-once-tenant",
    )

    results = poll_once(config)
    assert len(results) == 2
    assert len(fake_ingest_normalized_alert) == 2
    assert fake_ingest_normalized_alert[0]["alert"].description == "first"
    assert fake_ingest_normalized_alert[0]["tenant_id"] == "poll-once-tenant"


def test_poll_once_skips_non_dict_records(http_server, fake_ingest_normalized_alert, monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    http_server.set_responses([{"results": ["not a dict", 42]}])
    config = PollerConfig(name="t", base_url=http_server.url, records_path="results", tenant="skip-tenant")

    results = poll_once(config)
    assert results == []
    assert fake_ingest_normalized_alert == []


def test_poll_once_persists_cursor_across_calls(http_server, fake_ingest_normalized_alert, monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    config = PollerConfig(
        name="cursor-persist-test", base_url=http_server.url, records_path="results",
        cursor_field="ts", cursor_query_param="since", tenant="cursor-tenant",
    )

    http_server.set_responses([{"results": [{"title": "a", "ts": "100"}]}])
    poll_once(config)
    assert load_cursor(config) == "100"

    http_server.set_responses([{"results": [{"title": "b", "ts": "200"}]}])
    poll_once(config)
    assert http_server.seen[-1]["query"]["since"] == ["100"]
    assert load_cursor(config) == "200"


def test_poll_once_uses_registered_normalizer_when_configured(
    http_server, fake_ingest_normalized_alert, monkeypatch, tmp_path
):
    """A config with `normalizer` set must hand each raw record to that
    NORMALIZERS-registered function directly -- exercising this via the
    real 'splunk' normalizer to prove it's actually wired through
    poll_once(), not just unit-testable in isolation."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    http_server.set_responses(
        [{"results": [{"rule_name": "Excessive Failed Logins", "urgency": "informational", "src": "1.2.3.4"}]}]
    )
    config = PollerConfig(
        name="normalizer-test", base_url=http_server.url, records_path="results",
        normalizer="splunk", tenant="normalizer-tenant",
    )

    results = poll_once(config)
    assert len(results) == 1
    alert = fake_ingest_normalized_alert[0]["alert"]
    assert "Excessive Failed Logins" in alert.description
    assert alert.severity == "low"  # Splunk's "informational" -> our "low", not the generic default "medium"
    assert alert.source == "splunk"


def test_poll_once_normalizer_skips_non_dict_records(
    http_server, fake_ingest_normalized_alert, monkeypatch, tmp_path
):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    http_server.set_responses([{"results": ["not a dict"]}])
    config = PollerConfig(
        name="normalizer-skip-test", base_url=http_server.url, records_path="results", normalizer="splunk",
    )

    results = poll_once(config)
    assert results == []
    assert fake_ingest_normalized_alert == []


def test_poll_once_unknown_normalizer_name_skips_every_record(
    http_server, fake_ingest_normalized_alert, monkeypatch, tmp_path
):
    """A typo'd normalizer name must degrade to 'nothing ingested,' not
    raise or silently fall back to the generic field_map path -- fail
    loud enough to notice (no results at all) rather than guessing what
    the operator meant."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    http_server.set_responses([{"results": [{"rule_name": "x"}]}])
    config = PollerConfig(
        name="bad-normalizer-test", base_url=http_server.url, records_path="results",
        normalizer="not-a-real-normalizer",
    )

    results = poll_once(config)
    assert results == []
    assert fake_ingest_normalized_alert == []


# ---------- Splunk example config ----------


def test_load_splunk_example_config():
    config = load_config("examples/splunk_poller_config.example.json")
    assert config.name == "splunk-es-notable"
    assert config.normalizer == "splunk"
    assert config.method == "POST"
    assert config.auth_token_env == "SPLUNK_API_TOKEN"
    assert config.records_path == "results"


def test_save_and_load_cursor_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    config = PollerConfig(name="roundtrip-test", base_url="http://example.invalid", tenant="roundtrip-tenant")

    assert load_cursor(config) is None
    save_cursor(config, "abc")
    assert load_cursor(config) == "abc"


# ---------- load_config ----------


def test_load_config_from_the_shipped_example():
    config = load_config("examples/poller_config.example.json")
    assert config.name == "my-siem"
    assert config.field_map["description"] == "title"
    assert config.auth_token_env == "MY_SIEM_API_TOKEN"


def test_load_config_ignores_unknown_comment_fields(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"_comment": "ignored", "name": "x", "base_url": "http://example.invalid"}))
    config = load_config(str(path))
    assert config.name == "x"
