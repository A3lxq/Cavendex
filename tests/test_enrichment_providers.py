"""Provider lookup tests. The "no key configured"/"disabled" and cache
paths are pure unit tests; the invalid-key path is a genuine live test
against the real AbuseIPDB/VirusTotal APIs (skipped automatically if this
environment has no network access) — proving the HTTP error handling is
correct against real responses, not a guessed shape. Shodan's free
InternetDB endpoint needs no key at all, so its live test goes further:
a real *success-path* response (200, real JSON) against a stable,
always-scanned IP (8.8.8.8), not just an error path."""

import socket

import pytest

from enrichment.providers import (
    lookup_domain_resolutions_virustotal,
    lookup_hash_virustotal,
    lookup_ip_abuseipdb,
    lookup_ip_shodan,
    lookup_ip_virustotal,
    reset_cache_for_tests,
)


def _network_reachable() -> bool:
    try:
        socket.create_connection(("api.abuseipdb.com", 443), timeout=5).close()
        return True
    except OSError:
        return False


def _shodan_reachable() -> bool:
    try:
        socket.create_connection(("internetdb.shodan.io", 443), timeout=5).close()
        return True
    except OSError:
        return False


_HAS_NETWORK = _network_reachable()
_HAS_SHODAN_NETWORK = _shodan_reachable()


@pytest.fixture(autouse=True)
def _reset_cache():
    reset_cache_for_tests()
    yield
    reset_cache_for_tests()


def test_abuseipdb_returns_none_without_api_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    assert lookup_ip_abuseipdb("8.8.8.8") is None


def test_virustotal_returns_none_without_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    assert lookup_ip_virustotal("8.8.8.8") is None
    assert lookup_hash_virustotal("d41d8cd98f00b204e9800998ecf8427e") is None


@pytest.mark.skipif(not _HAS_NETWORK, reason="No network access in this environment")
def test_abuseipdb_invalid_key_returns_error_verdict_live(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "definitely-not-a-real-key")
    result = lookup_ip_abuseipdb("8.8.8.8")
    assert result is not None
    assert result.verdict == "error"
    assert "401" in result.detail


@pytest.mark.skipif(not _HAS_NETWORK, reason="No network access in this environment")
def test_virustotal_invalid_key_returns_error_verdict_live(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "definitely-not-a-real-key")
    result = lookup_ip_virustotal("8.8.8.8")
    assert result is not None
    assert result.verdict == "error"
    assert "401" in result.detail


def test_shodan_returns_none_when_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SENTINELOS_SHODAN_ENABLED", raising=False)

    def _fail(*a, **kw):
        raise AssertionError("must not call the network when Shodan is disabled")

    monkeypatch.setattr("requests.get", _fail)
    assert lookup_ip_shodan("8.8.8.8") is None


def test_shodan_explicitly_disabled(monkeypatch):
    monkeypatch.setenv("SENTINELOS_SHODAN_ENABLED", "false")
    assert lookup_ip_shodan("8.8.8.8") is None


@pytest.mark.skipif(not _HAS_SHODAN_NETWORK, reason="No network access in this environment")
def test_shodan_live_success_path_against_real_internetdb(monkeypatch):
    """A genuine live call against Shodan's real, keyless InternetDB
    endpoint for a stable, always-scanned IP (Google Public DNS) — proves
    the success-path field parsing (ports/vulns/hostnames/tags) matches
    the real response shape, not a guessed one."""
    monkeypatch.setenv("SENTINELOS_SHODAN_ENABLED", "true")
    result = lookup_ip_shodan("8.8.8.8")
    assert result is not None
    assert result.source == "shodan"
    assert result.indicator == "8.8.8.8"
    assert result.verdict in ("harmless", "suspicious")
    assert "port" in result.detail.lower()
    assert result.link == "https://www.shodan.io/host/8.8.8.8"


def test_shodan_404_returns_unknown_verdict(monkeypatch):
    monkeypatch.setenv("SENTINELOS_SHODAN_ENABLED", "true")

    class _FakeResponse:
        status_code = 404
        text = '{"detail":"No information available"}'

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_shodan("203.0.113.9")
    assert result.verdict == "unknown"


def test_shodan_error_status_returns_error_verdict(monkeypatch):
    monkeypatch.setenv("SENTINELOS_SHODAN_ENABLED", "true")

    class _FakeResponse:
        status_code = 503
        text = "Service Unavailable"

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_shodan("203.0.113.9")
    assert result.verdict == "error"
    assert "503" in result.detail


def test_shodan_request_exception_returns_error_verdict(monkeypatch):
    monkeypatch.setenv("SENTINELOS_SHODAN_ENABLED", "true")

    import requests

    def _raise(*a, **kw):
        raise requests.ConnectionError("boom")

    monkeypatch.setattr("requests.get", _raise)
    result = lookup_ip_shodan("203.0.113.9")
    assert result.verdict == "error"
    assert "boom" in result.detail


def test_shodan_known_vuln_maps_to_suspicious(monkeypatch):
    monkeypatch.setenv("SENTINELOS_SHODAN_ENABLED", "true")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {
                "ip": "203.0.113.9",
                "ports": [22, 3389],
                "hostnames": ["legacy.example.com"],
                "tags": ["vpn"],
                "vulns": ["CVE-2021-12345"],
            }

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_shodan("203.0.113.9")
    assert result.verdict == "suspicious"
    assert "CVE-2021-12345" in result.detail
    assert "3389" in result.detail
    assert "legacy.example.com" in result.detail


def test_shodan_no_vulns_maps_to_harmless(monkeypatch):
    monkeypatch.setenv("SENTINELOS_SHODAN_ENABLED", "true")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"ip": "203.0.113.9", "ports": [443], "hostnames": [], "tags": [], "vulns": []}

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_shodan("203.0.113.9")
    assert result.verdict == "harmless"


def test_shodan_results_are_cached(monkeypatch):
    monkeypatch.setenv("SENTINELOS_SHODAN_ENABLED", "true")
    call_count = {"n": 0}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"ip": "1.2.3.4", "ports": [80], "hostnames": [], "tags": [], "vulns": []}

    def _fake_get(*args, **kwargs):
        call_count["n"] += 1
        return _FakeResponse()

    monkeypatch.setattr("requests.get", _fake_get)

    lookup_ip_shodan("1.2.3.4")
    lookup_ip_shodan("1.2.3.4")

    assert call_count["n"] == 1


def test_domain_resolutions_returns_none_without_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    assert lookup_domain_resolutions_virustotal("evil-c2.example") is None


@pytest.mark.skipif(not _HAS_NETWORK, reason="No network access in this environment")
def test_domain_resolutions_invalid_key_returns_none_live(monkeypatch):
    """Unlike the EnrichmentResult-returning lookups, this one has no
    "error" verdict to distinguish -- an invalid key and an unconfigured
    key both mean "no signal" to its only caller (identity correlation),
    so this proves the real 401 path degrades to None rather than raising
    or returning a malformed value."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "definitely-not-a-real-key")
    assert lookup_domain_resolutions_virustotal("evil-c2.example") is None


def test_domain_resolutions_parses_real_response_shape(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {
                "data": [
                    {"attributes": {"ip_address": "203.0.113.9", "date": 1}},
                    {"attributes": {"ip_address": "203.0.113.10", "date": 2}},
                    {"attributes": {}},
                ]
            }

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    ips = lookup_domain_resolutions_virustotal("evil-c2.example")
    assert ips == ["203.0.113.9", "203.0.113.10"]


def test_domain_resolutions_empty_data_is_a_real_empty_list_not_none(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"data": []}

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    assert lookup_domain_resolutions_virustotal("never-seen.example") == []


def test_domain_resolutions_error_status_returns_none(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 503
        text = "Service Unavailable"

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    assert lookup_domain_resolutions_virustotal("evil-c2.example") is None


def test_domain_resolutions_request_exception_returns_none(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")

    import requests

    def _raise(*a, **kw):
        raise requests.ConnectionError("boom")

    monkeypatch.setattr("requests.get", _raise)
    assert lookup_domain_resolutions_virustotal("evil-c2.example") is None


def test_domain_resolutions_are_cached(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    call_count = {"n": 0}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"data": [{"attributes": {"ip_address": "203.0.113.9"}}]}

    def _fake_get(*args, **kwargs):
        call_count["n"] += 1
        return _FakeResponse()

    monkeypatch.setattr("requests.get", _fake_get)

    lookup_domain_resolutions_virustotal("evil-c2.example")
    lookup_domain_resolutions_virustotal("evil-c2.example")

    assert call_count["n"] == 1


def test_results_are_cached_to_avoid_repeat_calls(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key")

    call_count = {"n": 0}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "US", "isp": "x"}}

    def _fake_get(*args, **kwargs):
        call_count["n"] += 1
        return _FakeResponse()

    monkeypatch.setattr("requests.get", _fake_get)

    lookup_ip_abuseipdb("1.2.3.4")
    lookup_ip_abuseipdb("1.2.3.4")

    assert call_count["n"] == 1  # second call hit the cache, not the network
