"""Tests ingestion/identity_correlation.py's asset-identity and
domain-identity tiers, independent of the ingestion pipeline that calls
it. Follows the seeding pattern in tests/test_correlation.py: candidates
are plain dicts of the same shape ingestion/correlation.py's own
recent_open_candidates() produces, passed directly via the `candidates`
param so these tests don't need a real incident_index."""

import json

from enrichment.providers import reset_cache_for_tests
from ingestion.identity_correlation import find_identity_correlation
from ingestion.schemas import NormalizedAlert
from utils.asset_inventory import reset_for_tests as reset_inventory


def setup_function():
    reset_inventory()
    reset_cache_for_tests()


def _candidate(thread_id, iocs=None, affected_assets=None):
    return {"thread_id": thread_id, "iocs": iocs or [], "affected_assets": affected_assets or []}


def _alert(iocs=None, affected_assets=None, severity="medium"):
    return NormalizedAlert(
        description="new alert",
        severity=severity,
        source="test",
        iocs=iocs or [],
        affected_assets=affected_assets or [],
        dedup_key="k",
    )


def _write_inventory(monkeypatch, tmp_path, mapping):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(mapping))
    monkeypatch.setenv("CAVENDEX_ASSET_INVENTORY_PATH", str(path))


# ---------- No candidates / no signal ----------


def test_alert_with_no_iocs_or_assets_never_matches():
    candidates = [_candidate("inc-1", affected_assets=["WEB-01"])]
    match = find_identity_correlation("t1", _alert(), candidates=candidates)
    assert match is None


def test_no_candidates_never_matches(monkeypatch, tmp_path):
    _write_inventory(monkeypatch, tmp_path, {"WEB-01-RENAMED": "asset-042"})
    match = find_identity_correlation("t1", _alert(affected_assets=["WEB-01-RENAMED"]), candidates=[])
    assert match is None


def test_no_inventory_configured_never_matches(monkeypatch, tmp_path):
    monkeypatch.delenv("CAVENDEX_ASSET_INVENTORY_PATH", raising=False)
    candidates = [_candidate("inc-1", affected_assets=["WEB-01"])]
    match = find_identity_correlation(
        "t1", _alert(affected_assets=["WEB-01-RENAMED"]), candidates=candidates
    )
    assert match is None


# ---------- Asset identity tier ----------


def test_renamed_asset_correlates_via_inventory(monkeypatch, tmp_path):
    _write_inventory(monkeypatch, tmp_path, {"WEB-01": "asset-042", "WEB-01-RENAMED": "asset-042"})
    candidates = [_candidate("inc-1", affected_assets=["WEB-01"])]

    match = find_identity_correlation("t1", _alert(affected_assets=["WEB-01-RENAMED"]), candidates=candidates)
    assert match["thread_id"] == "inc-1"
    assert match["match_type"] == "identity_asset"
    assert "WEB-01-RENAMED" in match["reason"] and "WEB-01" in match["reason"]


def test_asset_not_in_inventory_does_not_correlate(monkeypatch, tmp_path):
    _write_inventory(monkeypatch, tmp_path, {"WEB-01": "asset-042"})
    candidates = [_candidate("inc-1", affected_assets=["WEB-01"])]

    match = find_identity_correlation("t1", _alert(affected_assets=["SOME-OTHER-HOST"]), candidates=candidates)
    assert match is None


def test_different_canonical_identities_do_not_correlate(monkeypatch, tmp_path):
    _write_inventory(monkeypatch, tmp_path, {"WEB-01": "asset-042", "DC-01": "asset-001"})
    candidates = [_candidate("inc-1", affected_assets=["WEB-01"])]

    match = find_identity_correlation("t1", _alert(affected_assets=["DC-01"]), candidates=candidates)
    assert match is None


def test_asset_identity_lookup_is_exact_string_not_case_folded(monkeypatch, tmp_path):
    _write_inventory(monkeypatch, tmp_path, {"WEB-01": "asset-042", "WEB-01-RENAMED": "asset-042"})
    candidates = [_candidate("inc-1", affected_assets=["WEB-01"])]

    match = find_identity_correlation("t1", _alert(affected_assets=["web-01-renamed"]), candidates=candidates)
    assert match is None


def test_asset_identity_checked_before_domain_identity(monkeypatch, tmp_path):
    """Even with DNS identity enabled, the free asset tier should short
    circuit before spending an API call -- proven here by not configuring
    a VirusTotal key at all and still getting the asset match."""
    monkeypatch.setenv("CAVENDEX_CORRELATION_IDENTITY_DNS_ENABLED", "true")
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    _write_inventory(monkeypatch, tmp_path, {"WEB-01": "asset-042", "WEB-01-RENAMED": "asset-042"})
    candidates = [_candidate("inc-1", affected_assets=["WEB-01"])]

    match = find_identity_correlation("t1", _alert(affected_assets=["WEB-01-RENAMED"]), candidates=candidates)
    assert match["match_type"] == "identity_asset"


# ---------- Domain identity tier ----------


def test_domain_identity_disabled_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("CAVENDEX_CORRELATION_IDENTITY_DNS_ENABLED", raising=False)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")

    def _fail(*a, **kw):
        raise AssertionError("must not call the network when DNS identity is disabled")

    monkeypatch.setattr("requests.get", _fail)

    candidates = [_candidate("inc-1", iocs=["stage-one.example"])]
    match = find_identity_correlation("t1", _alert(iocs=["stage-two.example"]), candidates=candidates)
    assert match is None


def test_shared_resolution_correlates_lexically_unrelated_domains(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_CORRELATION_IDENTITY_DNS_ENABLED", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")

    def _fake_get(url, headers=None, params=None, timeout=None):
        class _FakeResponse:
            status_code = 200

            def json(self_inner):
                if "stage-one" in url:
                    return {"data": [{"attributes": {"ip_address": "203.0.113.9"}}]}
                return {"data": [{"attributes": {"ip_address": "203.0.113.9"}}]}

        return _FakeResponse()

    monkeypatch.setattr("requests.get", _fake_get)

    candidates = [_candidate("inc-1", iocs=["stage-one.example"])]
    match = find_identity_correlation("t1", _alert(iocs=["stage-two.example"]), candidates=candidates)
    assert match["thread_id"] == "inc-1"
    assert match["match_type"] == "identity_domain"
    assert "stage-two.example" in match["reason"] and "stage-one.example" in match["reason"]


def test_no_shared_resolution_does_not_correlate(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_CORRELATION_IDENTITY_DNS_ENABLED", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")

    def _fake_get(url, headers=None, params=None, timeout=None):
        class _FakeResponse:
            status_code = 200

            def json(self_inner):
                if "stage-one" in url:
                    return {"data": [{"attributes": {"ip_address": "203.0.113.9"}}]}
                return {"data": [{"attributes": {"ip_address": "198.51.100.5"}}]}

        return _FakeResponse()

    monkeypatch.setattr("requests.get", _fake_get)

    candidates = [_candidate("inc-1", iocs=["stage-one.example"])]
    match = find_identity_correlation("t1", _alert(iocs=["stage-two.example"]), candidates=candidates)
    assert match is None


def test_domain_lookup_count_is_bounded_by_a_configurable_budget(monkeypatch, tmp_path):
    """Security regression: one alert with many domain IOCs matched
    against many candidates (each with their own domain IOCs) must never
    turn into an unbounded number of real VirusTotal calls -- see
    CAVENDEX_IDENTITY_DNS_MAX_LOOKUPS in ingestion/identity_correlation.py."""
    monkeypatch.setenv("CAVENDEX_CORRELATION_IDENTITY_DNS_ENABLED", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    monkeypatch.setenv("CAVENDEX_IDENTITY_DNS_MAX_LOOKUPS", "3")

    call_count = {"n": 0}

    def _fake_get(url, headers=None, params=None, timeout=None):
        call_count["n"] += 1

        class _FakeResponse:
            status_code = 200

            def json(self_inner):
                # Every domain resolves to a DIFFERENT IP, so nothing
                # ever matches -- isolates the call-count assertion from
                # match-found early-return behavior.
                return {"data": [{"attributes": {"ip_address": f"203.0.113.{call_count['n']}"}}]}

        return _FakeResponse()

    monkeypatch.setattr("requests.get", _fake_get)

    # 10 distinct alert domains, 10 candidates each with 10 distinct
    # domains -- without a budget this would attempt up to 110 real calls.
    alert_domains = [f"alert-{i}.example" for i in range(10)]
    candidates = [
        _candidate(f"inc-{c}", iocs=[f"cand-{c}-{i}.example" for i in range(10)]) for c in range(10)
    ]
    match = find_identity_correlation("t1", _alert(iocs=alert_domains), candidates=candidates)

    assert match is None
    assert call_count["n"] == 3


def test_non_domain_iocs_are_ignored_by_domain_identity_tier(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_CORRELATION_IDENTITY_DNS_ENABLED", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")

    def _fail(*a, **kw):
        raise AssertionError("must not call the network for a non-domain IOC")

    monkeypatch.setattr("requests.get", _fail)

    candidates = [_candidate("inc-1", iocs=["203.0.113.9"])]
    match = find_identity_correlation("t1", _alert(iocs=["198.51.100.5"]), candidates=candidates)
    assert match is None
