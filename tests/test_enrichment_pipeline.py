"""Tests enrich_iocs()'s classify-then-lookup routing without any real
network call — provider functions are monkeypatched so we can assert
exactly which ones got invoked for which IOC types."""

from enrichment.pipeline import enrich_iocs, format_for_prompt
from enrichment.schemas import EnrichmentResult


def _fake_result(indicator, indicator_type, source):
    return EnrichmentResult(
        indicator=indicator, indicator_type=indicator_type, source=source,
        verdict="malicious", detail="fake result for testing",
    )


def test_unknown_iocs_never_trigger_a_lookup(monkeypatch):
    calls = []
    monkeypatch.setattr("enrichment.pipeline.lookup_ip_abuseipdb", lambda ip: calls.append(ip) or None)
    monkeypatch.setattr("enrichment.pipeline.lookup_ip_virustotal", lambda ip: calls.append(ip) or None)

    results = enrich_iocs(["DC-01", "Suricata rule ID and payload signature"])
    assert results == []
    assert calls == []


def test_ip_iocs_are_checked_against_both_key_based_ip_providers(monkeypatch):
    """Shodan is deliberately not mocked here — disabled by default
    (SENTINELOS_SHODAN_ENABLED unset), it should stay silent."""
    monkeypatch.delenv("SENTINELOS_SHODAN_ENABLED", raising=False)
    monkeypatch.setattr(
        "enrichment.pipeline.lookup_ip_abuseipdb",
        lambda ip: _fake_result(ip, "ip", "abuseipdb"),
    )
    monkeypatch.setattr(
        "enrichment.pipeline.lookup_ip_virustotal",
        lambda ip: _fake_result(ip, "ip", "virustotal"),
    )

    results = enrich_iocs(["203.0.113.5"])
    sources = {r.source for r in results}
    assert sources == {"abuseipdb", "virustotal"}


def test_ip_iocs_also_check_shodan_when_enabled(monkeypatch):
    monkeypatch.setattr("enrichment.pipeline.lookup_ip_abuseipdb", lambda ip: None)
    monkeypatch.setattr("enrichment.pipeline.lookup_ip_virustotal", lambda ip: None)
    monkeypatch.setattr(
        "enrichment.pipeline.lookup_ip_shodan",
        lambda ip: _fake_result(ip, "ip", "shodan"),
    )

    results = enrich_iocs(["203.0.113.5"])
    assert [r.source for r in results] == ["shodan"]


def test_hash_iocs_only_check_virustotal(monkeypatch):
    called = []
    monkeypatch.setattr("enrichment.pipeline.lookup_ip_abuseipdb", lambda ip: called.append(("abuseipdb", ip)) or None)
    monkeypatch.setattr(
        "enrichment.pipeline.lookup_hash_virustotal",
        lambda h: called.append(("virustotal", h)) or _fake_result(h, "hash", "virustotal"),
    )

    results = enrich_iocs(["d41d8cd98f00b204e9800998ecf8427e"])
    assert len(results) == 1
    assert results[0].source == "virustotal"
    assert ("abuseipdb", "d41d8cd98f00b204e9800998ecf8427e") not in called


def test_url_iocs_are_routed_to_url_capable_providers(monkeypatch):
    called = []
    monkeypatch.setattr(
        "enrichment.pipeline.lookup_url_urlhaus",
        lambda u: called.append(("urlhaus", u)) or _fake_result(u, "url", "urlhaus"),
    )
    monkeypatch.setattr("enrichment.pipeline.lookup_url_threatfox", lambda u: None)
    monkeypatch.setattr("enrichment.pipeline.lookup_url_xforce", lambda u: None)
    monkeypatch.setattr("enrichment.pipeline.lookup_url_metadefender", lambda u: None)
    monkeypatch.setattr("enrichment.pipeline.lookup_ip_abuseipdb", lambda ip: called.append(("abuseipdb", ip)) or None)

    results = enrich_iocs(["http://evil.example.com/payload.exe"])
    assert len(results) == 1
    assert results[0].source == "urlhaus"
    assert ("abuseipdb", "http://evil.example.com/payload.exe") not in called


def test_lookup_count_is_capped_per_incident(monkeypatch):
    monkeypatch.setenv("SENTINELOS_ENRICHMENT_MAX_LOOKUPS_PER_INCIDENT", "10")
    monkeypatch.setattr(
        "enrichment.pipeline.lookup_ip_abuseipdb",
        lambda ip: _fake_result(ip, "ip", "abuseipdb"),
    )
    monkeypatch.setattr("enrichment.pipeline.lookup_ip_virustotal", lambda ip: None)

    many_ips = [f"10.0.0.{i}" for i in range(1, 30)]
    results = enrich_iocs(many_ips)
    assert len(results) <= 10


def test_lookup_cap_bounds_attempts_not_just_appended_results(monkeypatch):
    """The cap must bound real outbound *attempts*, not just successful
    results -- a malicious/fabricated-IOC-heavy incident shouldn't be
    able to turn a wide per-IOC provider fan-out into far more than the
    configured number of real network calls. Every IP-capable provider
    here "succeeds" so appended-results count and attempt count would
    otherwise diverge sharply (up to 8 providers/IOC) if attempts were
    not itself bounded to the cap."""
    monkeypatch.setenv("SENTINELOS_ENRICHMENT_MAX_LOOKUPS_PER_INCIDENT", "5")
    attempts = []

    def _tracked(source):
        def _inner(ip):
            attempts.append((source, ip))
            return _fake_result(ip, "ip", source)
        return _inner

    for name, source in [
        ("lookup_ip_abuseipdb", "abuseipdb"), ("lookup_ip_virustotal", "virustotal"),
        ("lookup_ip_shodan", "shodan"), ("lookup_ip_otx", "alienvault_otx"),
        ("lookup_ip_greynoise", "greynoise"), ("lookup_ip_xforce", "ibm_xforce"),
        ("lookup_ip_metadefender", "metadefender"), ("lookup_ip_censys", "censys"),
    ]:
        monkeypatch.setattr(f"enrichment.pipeline.{name}", _tracked(source))

    many_ips = [f"10.0.0.{i}" for i in range(1, 10)]
    results = enrich_iocs(many_ips)
    assert len(results) == 5
    assert len(attempts) == 5


def test_format_for_prompt_handles_empty_results():
    text = format_for_prompt([])
    assert "No verified threat-intel" in text


def test_format_for_prompt_includes_verdict_and_source():
    results = [_fake_result("1.2.3.4", "ip", "abuseipdb")]
    text = format_for_prompt(results)
    assert "abuseipdb" in text
    assert "malicious" in text
    assert "1.2.3.4" in text
