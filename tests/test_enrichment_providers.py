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
    lookup_domain_metadefender,
    lookup_domain_otx,
    lookup_domain_resolutions_virustotal,
    lookup_domain_threatfox,
    lookup_hash_malwarebazaar,
    lookup_hash_metadefender,
    lookup_hash_otx,
    lookup_hash_threatfox,
    lookup_hash_virustotal,
    lookup_hash_xforce,
    lookup_ip_abuseipdb,
    lookup_ip_censys,
    lookup_ip_greynoise,
    lookup_ip_metadefender,
    lookup_ip_otx,
    lookup_ip_shodan,
    lookup_ip_threatfox,
    lookup_ip_virustotal,
    lookup_ip_xforce,
    lookup_url_metadefender,
    lookup_url_threatfox,
    lookup_url_urlhaus,
    lookup_url_xforce,
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


# ---------- 8 newer providers (AlienVault OTX, GreyNoise, MalwareBazaar,
# ThreatFox, URLhaus, IBM X-Force, Metadefender, Censys) ----------
#
# Deliberately NO live network tests against these 8, unlike the
# AbuseIPDB/VirusTotal/Shodan tests above (per explicit instruction while
# this feature was reviewed) -- every test below is a pure unit test
# (no-key gating, cache behavior) or uses a monkeypatched fake response,
# never a real outbound call. A live-verification pass against these
# providers' real APIs is deferred, not skipped by oversight.


def test_otx_returns_none_without_api_key(monkeypatch):
    monkeypatch.delenv("ALIENVAULT_OTX_API_KEY", raising=False)
    assert lookup_ip_otx("8.8.8.8") is None
    assert lookup_domain_otx("example.com") is None
    assert lookup_hash_otx("d41d8cd98f00b204e9800998ecf8427e") is None


def test_otx_pulse_count_zero_is_unknown(monkeypatch):
    monkeypatch.setenv("ALIENVAULT_OTX_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"pulse_info": {"count": 0, "pulses": []}}

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_otx("203.0.113.9")
    assert result.verdict == "unknown"


def test_otx_pulse_count_positive_is_malicious(monkeypatch):
    monkeypatch.setenv("ALIENVAULT_OTX_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"pulse_info": {"count": 3, "pulses": [{"name": "FIN7 C2 infrastructure"}]}}

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_otx("203.0.113.9")
    assert result.verdict == "malicious"
    assert "FIN7 C2 infrastructure" in result.detail
    assert "3" in result.detail


def test_otx_404_returns_unknown(monkeypatch):
    monkeypatch.setenv("ALIENVAULT_OTX_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 404
        text = "not found"

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    assert lookup_ip_otx("203.0.113.9").verdict == "unknown"


def test_otx_error_status_returns_error(monkeypatch):
    monkeypatch.setenv("ALIENVAULT_OTX_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 503
        text = "Service Unavailable"

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_otx("203.0.113.9")
    assert result.verdict == "error"
    assert "503" in result.detail


def test_otx_request_exception_returns_error(monkeypatch):
    monkeypatch.setenv("ALIENVAULT_OTX_API_KEY", "fake-key")
    import requests

    monkeypatch.setattr("requests.get", lambda *a, **kw: (_ for _ in ()).throw(requests.ConnectionError("boom")))
    result = lookup_ip_otx("203.0.113.9")
    assert result.verdict == "error"
    assert "boom" in result.detail


def test_otx_results_are_cached(monkeypatch):
    monkeypatch.setenv("ALIENVAULT_OTX_API_KEY", "fake-key")
    call_count = {"n": 0}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"pulse_info": {"count": 0, "pulses": []}}

    def _fake_get(*a, **kw):
        call_count["n"] += 1
        return _FakeResponse()

    monkeypatch.setattr("requests.get", _fake_get)
    lookup_ip_otx("1.2.3.4")
    lookup_ip_otx("1.2.3.4")
    assert call_count["n"] == 1


def test_greynoise_returns_none_without_api_key(monkeypatch):
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    assert lookup_ip_greynoise("8.8.8.8") is None


def test_greynoise_malicious_classification(monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"classification": "malicious", "noise": True, "riot": False}

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_greynoise("203.0.113.9")
    assert result.verdict == "malicious"
    assert "background scanning noise" in result.detail


def test_greynoise_benign_riot_classification(monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"classification": "benign", "noise": False, "riot": True, "name": "Google"}

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_greynoise("8.8.8.8")
    assert result.verdict == "harmless"
    assert "Google" in result.detail


def test_greynoise_404_returns_unknown(monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 404
        text = "not found"

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    assert lookup_ip_greynoise("203.0.113.9").verdict == "unknown"


def test_greynoise_error_status_returns_error(monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 401
        text = "Unauthorized"

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_greynoise("203.0.113.9")
    assert result.verdict == "error"
    assert "401" in result.detail


def test_greynoise_results_are_cached(monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "fake-key")
    call_count = {"n": 0}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"classification": "unknown", "noise": False, "riot": False}

    def _fake_get(*a, **kw):
        call_count["n"] += 1
        return _FakeResponse()

    monkeypatch.setattr("requests.get", _fake_get)
    lookup_ip_greynoise("1.2.3.4")
    lookup_ip_greynoise("1.2.3.4")
    assert call_count["n"] == 1


def test_malwarebazaar_returns_none_without_api_key(monkeypatch):
    monkeypatch.delenv("ABUSECH_API_KEY", raising=False)
    assert lookup_hash_malwarebazaar("d41d8cd98f00b204e9800998ecf8427e") is None


def test_malwarebazaar_found_is_malicious(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"query_status": "ok", "data": [{"signature": "AsyncRAT", "tags": ["rat", "asyncrat"]}]}

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_hash_malwarebazaar("d41d8cd98f00b204e9800998ecf8427e")
    assert result.verdict == "malicious"
    assert "AsyncRAT" in result.detail


def test_malwarebazaar_not_found_is_unknown(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"query_status": "hash_not_found"}

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_hash_malwarebazaar("d41d8cd98f00b204e9800998ecf8427e")
    assert result.verdict == "unknown"


def test_malwarebazaar_error_status_returns_error(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 403
        text = "Forbidden"

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_hash_malwarebazaar("d41d8cd98f00b204e9800998ecf8427e")
    assert result.verdict == "error"
    assert "403" in result.detail


def test_malwarebazaar_request_exception_returns_error(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")
    import requests

    monkeypatch.setattr("requests.post", lambda *a, **kw: (_ for _ in ()).throw(requests.ConnectionError("boom")))
    result = lookup_hash_malwarebazaar("d41d8cd98f00b204e9800998ecf8427e")
    assert result.verdict == "error"
    assert "boom" in result.detail


def test_malwarebazaar_results_are_cached(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")
    call_count = {"n": 0}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"query_status": "hash_not_found"}

    def _fake_post(*a, **kw):
        call_count["n"] += 1
        return _FakeResponse()

    monkeypatch.setattr("requests.post", _fake_post)
    lookup_hash_malwarebazaar("d41d8cd98f00b204e9800998ecf8427e")
    lookup_hash_malwarebazaar("d41d8cd98f00b204e9800998ecf8427e")
    assert call_count["n"] == 1


def test_threatfox_returns_none_without_api_key(monkeypatch):
    monkeypatch.delenv("ABUSECH_API_KEY", raising=False)
    assert lookup_ip_threatfox("8.8.8.8") is None
    assert lookup_domain_threatfox("example.com") is None
    assert lookup_hash_threatfox("d41d8cd98f00b204e9800998ecf8427e") is None
    assert lookup_url_threatfox("http://evil.example.com/") is None


def test_threatfox_found_is_malicious_with_confidence(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {
                "query_status": "ok",
                "data": [{"malware_printable": "AsyncRAT", "confidence_level": 90, "threat_type": "botnet_cc"}],
            }

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_threatfox("203.0.113.9")
    assert result.verdict == "malicious"
    assert "AsyncRAT" in result.detail
    assert "90" in result.detail


def test_threatfox_no_result_is_unknown(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"query_status": "no_result"}

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    assert lookup_url_threatfox("http://evil.example.com/").verdict == "unknown"


def test_threatfox_error_status_returns_error(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 401
        text = "Unauthorized"

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_threatfox("203.0.113.9")
    assert result.verdict == "error"
    assert "401" in result.detail


def test_threatfox_request_exception_returns_error(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")
    import requests

    monkeypatch.setattr("requests.post", lambda *a, **kw: (_ for _ in ()).throw(requests.ConnectionError("boom")))
    result = lookup_ip_threatfox("203.0.113.9")
    assert result.verdict == "error"
    assert "boom" in result.detail


def test_threatfox_results_are_cached(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")
    call_count = {"n": 0}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"query_status": "no_result"}

    def _fake_post(*a, **kw):
        call_count["n"] += 1
        return _FakeResponse()

    monkeypatch.setattr("requests.post", _fake_post)
    lookup_ip_threatfox("1.2.3.4")
    lookup_ip_threatfox("1.2.3.4")
    assert call_count["n"] == 1


def test_urlhaus_returns_none_without_api_key(monkeypatch):
    monkeypatch.delenv("ABUSECH_API_KEY", raising=False)
    assert lookup_url_urlhaus("http://evil.example.com/payload.exe") is None


def test_urlhaus_found_is_malicious(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "payloads": [{"file_type": "exe"}],
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/",
            }

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_url_urlhaus("http://evil.example.com/payload.exe")
    assert result.verdict == "malicious"
    assert "malware_download" in result.detail
    assert "exe" in result.detail
    assert result.link == "https://urlhaus.abuse.ch/url/12345/"


def test_urlhaus_no_results_is_unknown(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"query_status": "no_results"}

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_url_urlhaus("http://never-seen.example.com/")
    assert result.verdict == "unknown"


def test_urlhaus_error_status_returns_error(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 500
        text = "Internal Server Error"

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_url_urlhaus("http://evil.example.com/")
    assert result.verdict == "error"
    assert "500" in result.detail


def test_urlhaus_request_exception_returns_error(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")
    import requests

    monkeypatch.setattr("requests.post", lambda *a, **kw: (_ for _ in ()).throw(requests.ConnectionError("boom")))
    result = lookup_url_urlhaus("http://evil.example.com/")
    assert result.verdict == "error"
    assert "boom" in result.detail


def test_urlhaus_rejects_a_non_urlhaus_reference_link(monkeypatch):
    """Defense-in-depth: only ever surface a link that actually points at
    urlhaus.abuse.ch, never whatever a (real, trusted, but defensively
    treated) response body happens to put in that field."""
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {
                "query_status": "ok", "url_status": "online", "threat": "malware_download",
                "payloads": [], "urlhaus_reference": "http://attacker.example.com/not-urlhaus",
            }

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_url_urlhaus("http://evil.example.com/x")
    assert result.link is None


def test_urlhaus_results_are_cached(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")
    call_count = {"n": 0}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"query_status": "no_results"}

    def _fake_post(*a, **kw):
        call_count["n"] += 1
        return _FakeResponse()

    monkeypatch.setattr("requests.post", _fake_post)
    lookup_url_urlhaus("http://evil.example.com/")
    lookup_url_urlhaus("http://evil.example.com/")
    assert call_count["n"] == 1


def test_xforce_returns_none_without_both_credentials(monkeypatch):
    monkeypatch.delenv("IBM_XFORCE_API_KEY", raising=False)
    monkeypatch.delenv("IBM_XFORCE_API_PASSWORD", raising=False)
    assert lookup_ip_xforce("8.8.8.8") is None

    monkeypatch.setenv("IBM_XFORCE_API_KEY", "key-only")
    assert lookup_ip_xforce("8.8.8.8") is None  # password still missing

    monkeypatch.delenv("IBM_XFORCE_API_KEY", raising=False)
    monkeypatch.setenv("IBM_XFORCE_API_PASSWORD", "password-only")
    assert lookup_ip_xforce("8.8.8.8") is None  # key still missing


def test_xforce_high_score_is_malicious(monkeypatch):
    monkeypatch.setenv("IBM_XFORCE_API_KEY", "fake-key")
    monkeypatch.setenv("IBM_XFORCE_API_PASSWORD", "fake-password")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"score": 8.5}

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_xforce("203.0.113.9")
    assert result.verdict == "malicious"


def test_xforce_low_score_is_harmless(monkeypatch):
    monkeypatch.setenv("IBM_XFORCE_API_KEY", "fake-key")
    monkeypatch.setenv("IBM_XFORCE_API_PASSWORD", "fake-password")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"score": 1}

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_xforce("8.8.8.8")
    assert result.verdict == "harmless"


def test_xforce_unrecognized_shape_does_not_crash(monkeypatch):
    """Response-shape uncertainty (see module docstring) must degrade to
    'unknown', never raise."""
    monkeypatch.setenv("IBM_XFORCE_API_KEY", "fake-key")
    monkeypatch.setenv("IBM_XFORCE_API_PASSWORD", "fake-password")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"something_unexpected": True}

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_xforce("203.0.113.9")
    assert result.verdict == "unknown"


def test_xforce_404_returns_unknown(monkeypatch):
    monkeypatch.setenv("IBM_XFORCE_API_KEY", "fake-key")
    monkeypatch.setenv("IBM_XFORCE_API_PASSWORD", "fake-password")

    class _FakeResponse:
        status_code = 404
        text = "not found"

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    assert lookup_ip_xforce("203.0.113.9").verdict == "unknown"


def test_xforce_error_status_returns_error(monkeypatch):
    monkeypatch.setenv("IBM_XFORCE_API_KEY", "fake-key")
    monkeypatch.setenv("IBM_XFORCE_API_PASSWORD", "fake-password")

    class _FakeResponse:
        status_code = 401
        text = "Unauthorized"

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_xforce("203.0.113.9")
    assert result.verdict == "error"
    assert "401" in result.detail


def test_xforce_request_exception_returns_error(monkeypatch):
    monkeypatch.setenv("IBM_XFORCE_API_KEY", "fake-key")
    monkeypatch.setenv("IBM_XFORCE_API_PASSWORD", "fake-password")
    import requests

    monkeypatch.setattr("requests.get", lambda *a, **kw: (_ for _ in ()).throw(requests.ConnectionError("boom")))
    result = lookup_ip_xforce("203.0.113.9")
    assert result.verdict == "error"
    assert "boom" in result.detail


def test_xforce_uses_http_basic_auth(monkeypatch):
    monkeypatch.setenv("IBM_XFORCE_API_KEY", "the-key")
    monkeypatch.setenv("IBM_XFORCE_API_PASSWORD", "the-password")
    seen = {}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"score": 0}

    def _fake_get(*a, **kw):
        seen["auth"] = kw.get("auth")
        return _FakeResponse()

    monkeypatch.setattr("requests.get", _fake_get)
    lookup_ip_xforce("203.0.113.9")
    assert seen["auth"] == ("the-key", "the-password")


def test_xforce_results_are_cached(monkeypatch):
    monkeypatch.setenv("IBM_XFORCE_API_KEY", "fake-key")
    monkeypatch.setenv("IBM_XFORCE_API_PASSWORD", "fake-password")
    call_count = {"n": 0}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"score": 0}

    def _fake_get(*a, **kw):
        call_count["n"] += 1
        return _FakeResponse()

    monkeypatch.setattr("requests.get", _fake_get)
    lookup_ip_xforce("1.2.3.4")
    lookup_ip_xforce("1.2.3.4")
    assert call_count["n"] == 1


def test_metadefender_returns_none_without_api_key(monkeypatch):
    monkeypatch.delenv("METADEFENDER_API_KEY", raising=False)
    assert lookup_ip_metadefender("8.8.8.8") is None
    assert lookup_domain_metadefender("example.com") is None
    assert lookup_hash_metadefender("d41d8cd98f00b204e9800998ecf8427e") is None
    assert lookup_url_metadefender("http://evil.example.com/") is None


def test_metadefender_detections_is_malicious(monkeypatch):
    monkeypatch.setenv("METADEFENDER_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return [{"lookup_result": {"detected_by": 12, "total_detected_avs": 40}}]

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_hash_metadefender("d41d8cd98f00b204e9800998ecf8427e")
    assert result.verdict == "malicious"
    assert "12" in result.detail
    assert "40" in result.detail


def test_metadefender_no_detections_is_harmless(monkeypatch):
    monkeypatch.setenv("METADEFENDER_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return [{"lookup_result": {"detected_by": 0, "total_detected_avs": 40}}]

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_metadefender("8.8.8.8")
    assert result.verdict == "harmless"


def test_metadefender_empty_response_is_unknown(monkeypatch):
    """Response-shape uncertainty (see module docstring) must degrade to
    'unknown', never raise or crash on an empty/unexpected body."""
    monkeypatch.setenv("METADEFENDER_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return []

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_metadefender("8.8.8.8")
    assert result.verdict == "unknown"


def test_metadefender_error_status_returns_error(monkeypatch):
    monkeypatch.setenv("METADEFENDER_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 403
        text = "Forbidden"

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_metadefender("8.8.8.8")
    assert result.verdict == "error"
    assert "403" in result.detail


def test_metadefender_request_exception_returns_error(monkeypatch):
    monkeypatch.setenv("METADEFENDER_API_KEY", "fake-key")
    import requests

    monkeypatch.setattr("requests.post", lambda *a, **kw: (_ for _ in ()).throw(requests.ConnectionError("boom")))
    result = lookup_ip_metadefender("8.8.8.8")
    assert result.verdict == "error"
    assert "boom" in result.detail


def test_metadefender_results_are_cached(monkeypatch):
    monkeypatch.setenv("METADEFENDER_API_KEY", "fake-key")
    call_count = {"n": 0}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return []

    def _fake_post(*a, **kw):
        call_count["n"] += 1
        return _FakeResponse()

    monkeypatch.setattr("requests.post", _fake_post)
    lookup_ip_metadefender("1.2.3.4")
    lookup_ip_metadefender("1.2.3.4")
    assert call_count["n"] == 1


def test_censys_returns_none_without_api_key(monkeypatch):
    monkeypatch.delenv("CENSYS_API_KEY", raising=False)
    assert lookup_ip_censys("8.8.8.8") is None


def test_censys_with_services_is_harmless(monkeypatch):
    monkeypatch.setenv("CENSYS_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"result": {"services": [{"port": 443}, {"port": 22}]}}

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_censys("203.0.113.9")
    assert result.verdict == "harmless"
    assert "22" in result.detail
    assert "443" in result.detail


def test_censys_no_services_is_unknown(monkeypatch):
    monkeypatch.setenv("CENSYS_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"result": {"services": []}}

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_censys("203.0.113.9")
    assert result.verdict == "unknown"


def test_censys_uses_bearer_auth(monkeypatch):
    monkeypatch.setenv("CENSYS_API_KEY", "the-token")
    seen = {}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"result": {"services": []}}

    def _fake_get(*a, **kw):
        seen["headers"] = kw.get("headers")
        return _FakeResponse()

    monkeypatch.setattr("requests.get", _fake_get)
    lookup_ip_censys("203.0.113.9")
    assert seen["headers"]["Authorization"] == "Bearer the-token"


def test_censys_404_returns_unknown(monkeypatch):
    monkeypatch.setenv("CENSYS_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 404
        text = "not found"

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    assert lookup_ip_censys("203.0.113.9").verdict == "unknown"


def test_censys_error_status_returns_error(monkeypatch):
    monkeypatch.setenv("CENSYS_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 401
        text = "Unauthorized"

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_censys("203.0.113.9")
    assert result.verdict == "error"
    assert "401" in result.detail


def test_censys_request_exception_returns_error(monkeypatch):
    monkeypatch.setenv("CENSYS_API_KEY", "fake-key")
    import requests

    monkeypatch.setattr("requests.get", lambda *a, **kw: (_ for _ in ()).throw(requests.ConnectionError("boom")))
    result = lookup_ip_censys("203.0.113.9")
    assert result.verdict == "error"
    assert "boom" in result.detail


def test_censys_results_are_cached(monkeypatch):
    monkeypatch.setenv("CENSYS_API_KEY", "fake-key")
    call_count = {"n": 0}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"result": {"services": []}}

    def _fake_get(*a, **kw):
        call_count["n"] += 1
        return _FakeResponse()

    monkeypatch.setattr("requests.get", _fake_get)
    lookup_ip_censys("1.2.3.4")
    lookup_ip_censys("1.2.3.4")
    assert call_count["n"] == 1


def test_path_segments_are_url_encoded_not_interpolated_raw(monkeypatch):
    """Security regression guard: an indicator containing path-breaking
    characters must never be concatenated raw into a request URL's path
    -- it's always run through urllib.parse.quote first (see
    enrichment/providers.py's module-level security note)."""
    monkeypatch.setenv("ALIENVAULT_OTX_API_KEY", "fake-key")
    seen = {}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"pulse_info": {"count": 0, "pulses": []}}

    def _fake_get(url, *a, **kw):
        seen["url"] = url
        return _FakeResponse()

    monkeypatch.setattr("requests.get", _fake_get)
    lookup_domain_otx("evil.example/../../admin?x=1")
    assert "evil.example/../../admin?x=1" not in seen["url"]
    assert "%2F" in seen["url"] or "%2E%2E" in seen["url"].upper()


# ---------- Security audit fixes: malformed-JSON handling, truncation,
# and non-leaky error messages (applies across all 11 providers; a
# representative sample is exercised directly here) ----------


def test_malformed_json_200_response_degrades_to_error_not_a_crash(monkeypatch):
    """Security regression: a 200 response with a non-JSON body (a
    captive portal, a WAF/proxy error page, a provider outage serving
    HTML with a 200 status) must degrade to an "error" EnrichmentResult,
    never raise past this module -- see enrichment/providers.py's
    _parse_json. Exercised against AbuseIPDB as a representative case;
    every other provider follows the identical pattern."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200
        text = "<html>not json</html>"

        def json(self):
            raise ValueError("Expecting value: line 1 column 1 (char 0)")

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_abuseipdb("8.8.8.8")
    assert result is not None
    assert result.verdict == "error"


def test_malformed_json_never_raises_across_a_post_based_provider(monkeypatch):
    """Same guard, for a POST-based provider (different request/response
    shape than AbuseIPDB's GET) -- MalwareBazaar."""
    monkeypatch.setenv("ABUSECH_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200
        text = "not json at all"

        def json(self):
            raise ValueError("boom")

    monkeypatch.setattr("requests.post", lambda *a, **kw: _FakeResponse())
    result = lookup_hash_malwarebazaar("d41d8cd98f00b204e9800998ecf8427e")
    assert result is not None
    assert result.verdict == "error"


def test_abuseipdb_detail_is_truncated_even_with_an_oversized_field(monkeypatch):
    """Security regression: EnrichmentResult.detail is
    Field(max_length=1000) -- Pydantic RAISES on overflow rather than
    truncating, so every provider must manually truncate before
    construction. AbuseIPDB's isp/countryCode fields (real WHOIS/RIR
    data an attacker can influence by choosing which IP block to use)
    were the one function missing this truncation."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {
                "data": {
                    "abuseConfidenceScore": 10,
                    "totalReports": 1,
                    "countryCode": "US",
                    "isp": "X" * 2000,  # far past EnrichmentResult.detail's 1000-char cap
                }
            }

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_abuseipdb("8.8.8.8")  # must not raise a pydantic ValidationError
    assert result is not None
    assert len(result.detail) <= 1000


def test_error_detail_never_echoes_the_raw_response_body(monkeypatch):
    """Security regression: a non-200 provider response's raw body (which
    can contain anything -- an HTML error page, a WAF challenge,
    occasionally reflected request data) must never be echoed verbatim
    into a durable EnrichmentResult.detail. Only the status code is
    surfaced; the full body is logged server-side instead."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key")
    secret_looking_body = "<html>Internal error: debug-token=SUPERSECRET123</html>"

    class _FakeResponse:
        status_code = 500
        text = secret_looking_body

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())
    result = lookup_ip_abuseipdb("8.8.8.8")
    assert result is not None
    assert result.verdict == "error"
    assert "SUPERSECRET123" not in result.detail
    assert "500" in result.detail


def test_cache_size_is_bounded_not_unbounded(monkeypatch):
    """Security regression: a sustained stream of distinct classifiable
    indicators (each looked up exactly once, never triggering its own
    lazy per-key TTL expiry) must not grow the module-level cache
    without bound."""
    import enrichment.providers as providers

    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key")
    monkeypatch.setattr(providers, "_CACHE_MAX_ENTRIES", 10)

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}

    monkeypatch.setattr("requests.get", lambda *a, **kw: _FakeResponse())

    for i in range(25):
        lookup_ip_abuseipdb(f"10.0.0.{i}")

    assert len(providers._cache) <= 10


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
