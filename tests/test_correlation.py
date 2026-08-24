"""Tests ingestion/correlation.py's exact and fuzzy matching against the
incident_index, independent of the ingestion pipeline that calls it."""

from datetime import datetime, timedelta, timezone

from ingestion.correlation import _registered_domain, find_correlated_incident
from ingestion.schemas import NormalizedAlert
from utils.incident_index import reset_for_tests, upsert_incident_summary
from state import Incident


def test_registered_domain_uses_the_real_public_suffix_list():
    assert _registered_domain("cdn.evil-c2.com") == "evil-c2.com"
    assert _registered_domain("mail.evil-c2.com") == "evil-c2.com"
    # The naive last-two-labels split this used to use would incorrectly
    # treat these as the same "registered domain" — the real PSL knows
    # .co.uk is a public suffix, not a registrable second-level domain.
    assert _registered_domain("foo.co.uk") == "foo.co.uk"
    assert _registered_domain("bar.co.uk") == "bar.co.uk"
    assert _registered_domain("mail.evil-c2.co.uk") == "evil-c2.co.uk"
    assert _registered_domain("cdn.evil-c2.co.uk") == "evil-c2.co.uk"


def setup_function():
    reset_for_tests()


def _seed(thread_id, tenant_id="t1", status="investigating", iocs=None, affected_assets=None):
    upsert_incident_summary(
        tenant_id,
        {
            "incident": Incident(
                id=thread_id,
                description="seeded",
                status=status,
                iocs=iocs or [],
                affected_assets=affected_assets or [],
            ),
            "tenant_id": tenant_id,
        },
    )


def _alert(iocs=None, affected_assets=None, severity="medium"):
    return NormalizedAlert(
        description="new alert",
        severity=severity,
        source="test",
        iocs=iocs or [],
        affected_assets=affected_assets or [],
        dedup_key="k",
    )


def test_shared_ioc_correlates_to_open_incident(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-1", iocs=["1.2.3.4"])

    match = find_correlated_incident("t1", _alert(iocs=["1.2.3.4"]))
    assert match["thread_id"] == "inc-1"
    assert match["match_type"] == "exact_ioc"


def test_shared_affected_asset_correlates_to_open_incident(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-1", affected_assets=["FIN-SRV-02"])

    match = find_correlated_incident("t1", _alert(affected_assets=["FIN-SRV-02"]))
    assert match["thread_id"] == "inc-1"
    assert match["match_type"] == "exact_asset"


def test_no_overlap_does_not_correlate(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-1", iocs=["1.2.3.4"], affected_assets=["FIN-SRV-02"])

    match = find_correlated_incident("t1", _alert(iocs=["9.9.9.9"], affected_assets=["OTHER-HOST"]))
    assert match is None


def test_alert_with_no_iocs_or_assets_never_correlates(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-1", iocs=["1.2.3.4"])

    match = find_correlated_incident("t1", _alert())
    assert match is None


def test_closed_incident_is_not_a_correlation_candidate(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-1", status="closed", iocs=["1.2.3.4"])

    match = find_correlated_incident("t1", _alert(iocs=["1.2.3.4"]))
    assert match is None


def test_correlation_scoped_to_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-1", tenant_id="tenant-a", iocs=["1.2.3.4"])

    match = find_correlated_incident("tenant-b", _alert(iocs=["1.2.3.4"]))
    assert match is None


def test_correlation_window_disabled_by_zero(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_CORRELATION_WINDOW_SECONDS", "0")
    _seed("inc-1", iocs=["1.2.3.4"])

    match = find_correlated_incident("t1", _alert(iocs=["1.2.3.4"]))
    assert match is None


def test_stale_incident_outside_window_does_not_correlate(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_CORRELATION_WINDOW_SECONDS", "60")
    _seed("inc-1", iocs=["1.2.3.4"])

    import utils.incident_index as idx

    conn = idx._get_connection("t1")
    stale = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    conn.execute("UPDATE incidents SET updated_at = ? WHERE thread_id = ?", (stale, "inc-1"))
    conn.commit()

    match = find_correlated_incident("t1", _alert(iocs=["1.2.3.4"]))
    assert match is None


# ---------- Fuzzy tier: subnet grouping ----------


def test_ips_in_same_subnet_correlate_via_fuzzy_tier(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-1", iocs=["10.0.0.5"])

    match = find_correlated_incident("t1", _alert(iocs=["10.0.0.9"]))
    assert match["thread_id"] == "inc-1"
    assert match["match_type"] == "subnet"
    assert "10.0.0.9" in match["reason"] and "10.0.0.5" in match["reason"]


def test_ips_in_different_subnet_do_not_correlate(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-1", iocs=["10.0.0.5"])

    match = find_correlated_incident("t1", _alert(iocs=["10.0.1.9"]))
    assert match is None


def test_subnet_prefix_bits_is_configurable(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_CORRELATION_SUBNET_PREFIX_BITS", "16")
    _seed("inc-1", iocs=["10.0.0.5"])

    match = find_correlated_incident("t1", _alert(iocs=["10.0.99.9"]))
    assert match["thread_id"] == "inc-1"
    assert match["match_type"] == "subnet"


# ---------- Fuzzy tier: domain family grouping ----------


def test_subdomains_of_same_registered_domain_correlate(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-1", iocs=["mail.evil-c2.com"])

    match = find_correlated_incident("t1", _alert(iocs=["cdn.evil-c2.com"]))
    assert match["thread_id"] == "inc-1"
    assert match["match_type"] == "domain_family"


def test_unrelated_domains_do_not_correlate(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-1", iocs=["mail.evil-c2.com"])

    match = find_correlated_incident("t1", _alert(iocs=["totally-unrelated.example"]))
    assert match is None


def test_multi_part_tld_domains_are_not_over_grouped(monkeypatch, tmp_path):
    """foo.co.uk and bar.co.uk must NOT be treated as the same registered
    domain just because they share a naive last-two-labels split — this
    is exactly the bug a real Public Suffix List lookup fixes."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-1", iocs=["mail.foo.co.uk"])

    match = find_correlated_incident("t1", _alert(iocs=["cdn.bar.co.uk"]))
    assert match is None


def test_multi_part_tld_subdomains_of_the_same_domain_still_correlate(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-1", iocs=["mail.evil-c2.co.uk"])

    match = find_correlated_incident("t1", _alert(iocs=["cdn.evil-c2.co.uk"]))
    assert match["thread_id"] == "inc-1"
    assert match["match_type"] == "domain_family"


# ---------- Tier ordering and the fuzzy opt-out ----------


def test_exact_match_preferred_over_fuzzy_match(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-fuzzy", iocs=["10.0.0.5"])
    _seed("inc-exact", iocs=["10.0.0.9"])

    match = find_correlated_incident("t1", _alert(iocs=["10.0.0.9"]))
    assert match["thread_id"] == "inc-exact"
    assert match["match_type"] == "exact_ioc"


def test_fuzzy_tier_disabled_by_env_var(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_CORRELATION_FUZZY_ENABLED", "false")
    _seed("inc-1", iocs=["10.0.0.5"])

    match = find_correlated_incident("t1", _alert(iocs=["10.0.0.9"]))
    assert match is None


def test_exact_match_still_works_when_fuzzy_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINELOS_CORRELATION_FUZZY_ENABLED", "false")
    _seed("inc-1", iocs=["1.2.3.4"])

    match = find_correlated_incident("t1", _alert(iocs=["1.2.3.4"]))
    assert match["thread_id"] == "inc-1"
    assert match["match_type"] == "exact_ioc"


def test_hash_iocs_never_participate_in_fuzzy_matching(monkeypatch, tmp_path):
    """A shared-length hex string that happens to classify as a hash should
    never fuzzy-match — fuzzy tier only ever looks at ip/domain-classified
    IOCs, never arbitrary strings (including the verbose free-text an LLM
    sometimes writes into incident.iocs)."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed("inc-1", iocs=["a" * 32])

    match = find_correlated_incident("t1", _alert(iocs=["b" * 32]))
    assert match is None
