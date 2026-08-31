"""Tests the promote/dedup/suppress decision logic in ingestion/pipeline.py
without any real LLM call — run_new_incident is monkeypatched so we can
assert exactly when it was (and wasn't) invoked."""

import pytest

from utils.asset_inventory import reset_for_tests as reset_asset_inventory
from utils.dedup import reset_for_tests as reset_dedup
from utils.incident_index import reset_for_tests as reset_index, upsert_incident_summary
from utils.rate_limit import reset_for_tests as reset_rate_limit
from state import Incident


class _FakeIncident:
    id = "fake-incident-id"
    status = "investigating"


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    reset_dedup()
    reset_index()
    reset_rate_limit()
    reset_asset_inventory()
    monkeypatch.setenv("CAVENDEX_DEDUP_WINDOW_SECONDS", "300")
    monkeypatch.setenv("CAVENDEX_INGEST_MIN_SEVERITY", "medium")
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CAVENDEX_INGEST_RATE_LIMIT_PER_MINUTE", raising=False)
    monkeypatch.delenv("CAVENDEX_ASSET_INVENTORY_PATH", raising=False)
    yield
    reset_dedup()
    reset_index()
    reset_rate_limit()
    reset_asset_inventory()


@pytest.fixture
def fake_run_new_incident(monkeypatch):
    import workflows.incident_pipeline as wip

    calls = []

    def _fake(**kwargs):
        calls.append(kwargs)
        return {"incident": _FakeIncident()}

    monkeypatch.setattr(wip, "run_new_incident", _fake)
    return calls


@pytest.fixture
def fake_semantic_correlation(monkeypatch):
    """Controls ingestion.pipeline's find_semantic_correlation return value
    directly — avoids needing a real/mocked LLM provider to test the
    ordering and usage-threading logic in ingest_alert itself."""
    import ingestion.pipeline as pipeline_mod

    state = {"return_value": (None, {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0})}

    def _fake(tenant_id, alert):
        return state["return_value"]

    monkeypatch.setattr(pipeline_mod, "find_semantic_correlation", _fake)
    return state


@pytest.fixture
def fake_merge_correlated_alert(monkeypatch):
    import workflows.incident_pipeline as wip

    calls = []

    def _fake(**kwargs):
        calls.append(kwargs)
        return {"incident": Incident(id=kwargs["thread_id"], description="merged", status="investigating")}

    monkeypatch.setattr(wip, "merge_correlated_alert", _fake)
    return calls


def test_unknown_source_is_reported_and_never_promotes(fake_run_new_incident):
    from ingestion.pipeline import ingest_alert

    result = ingest_alert("not-a-real-source", {}, tenant_id="t1")
    assert result["outcome"] == "unknown_source"
    assert len(fake_run_new_incident) == 0


def test_non_alert_event_is_reported_and_never_promotes(fake_run_new_incident):
    from ingestion.pipeline import ingest_alert

    result = ingest_alert("suricata", {"event_type": "flow"}, tenant_id="t1")
    assert result["outcome"] == "not_an_alert"
    assert len(fake_run_new_incident) == 0


def test_high_severity_alert_is_promoted(fake_run_new_incident):
    from ingestion.pipeline import ingest_alert

    result = ingest_alert(
        "generic", {"description": "bad thing", "severity": "high", "source": "test"}, tenant_id="t1"
    )
    assert result["outcome"] == "promoted"
    assert result["thread_id"] == "fake-incident-id"
    assert len(fake_run_new_incident) == 1


def test_low_severity_alert_is_suppressed_not_promoted(fake_run_new_incident):
    from ingestion.pipeline import ingest_alert

    result = ingest_alert(
        "generic", {"description": "minor thing", "severity": "low", "source": "test"}, tenant_id="t1"
    )
    assert result["outcome"] == "suppressed_low_severity"
    assert len(fake_run_new_incident) == 0


def test_duplicate_alert_within_window_is_deduped_not_promoted(fake_run_new_incident):
    from ingestion.pipeline import ingest_alert

    payload = {"description": "bad thing", "severity": "high", "source": "test", "dedup_key": "fixed-key"}
    first = ingest_alert("generic", payload, tenant_id="t1")
    second = ingest_alert("generic", payload, tenant_id="t1")

    assert first["outcome"] == "promoted"
    assert second["outcome"] == "deduped"
    assert len(fake_run_new_incident) == 1


def test_same_dedup_key_different_tenants_both_promote(fake_run_new_incident):
    from ingestion.pipeline import ingest_alert

    payload = {"description": "bad thing", "severity": "high", "source": "test", "dedup_key": "fixed-key"}
    r1 = ingest_alert("generic", payload, tenant_id="tenant-a")
    r2 = ingest_alert("generic", payload, tenant_id="tenant-b")

    assert r1["outcome"] == "promoted"
    assert r2["outcome"] == "promoted"
    assert len(fake_run_new_incident) == 2


def test_every_outcome_is_logged_to_ingestion_log(fake_run_new_incident, tmp_path, monkeypatch):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    from ingestion.pipeline import ingest_alert

    ingest_alert("generic", {"description": "x", "severity": "low", "source": "t"}, tenant_id="log-test")

    log_path = tmp_path / "log-test" / "ingestion_log.jsonl"
    assert log_path.exists()
    content = log_path.read_text(encoding="utf-8")
    assert "suppressed_low_severity" in content


def _seed_open_incident(tenant_id, thread_id, iocs=None, affected_assets=None):
    upsert_incident_summary(
        tenant_id,
        {
            "incident": Incident(
                id=thread_id,
                description="existing",
                status="investigating",
                iocs=iocs or [],
                affected_assets=affected_assets or [],
            ),
            "tenant_id": tenant_id,
        },
    )


def test_alert_sharing_an_ioc_with_open_incident_is_correlated_not_promoted(
    fake_run_new_incident, fake_merge_correlated_alert
):
    from ingestion.pipeline import ingest_alert

    _seed_open_incident("t1", "inc-1", iocs=["1.2.3.4"])

    result = ingest_alert(
        "generic",
        {"description": "related alert", "severity": "high", "source": "test", "iocs": ["1.2.3.4"]},
        tenant_id="t1",
    )

    assert result["outcome"] == "correlated"
    assert result["thread_id"] == "inc-1"
    assert len(fake_merge_correlated_alert) == 1
    assert len(fake_run_new_incident) == 0


def test_correlation_bypasses_the_severity_floor(fake_run_new_incident, fake_merge_correlated_alert):
    """A low-severity alert alone would be suppressed, but if it shares an
    IOC with an already-open incident it's evidence for that incident and
    should still get merged in, not silently dropped."""
    from ingestion.pipeline import ingest_alert

    _seed_open_incident("t1", "inc-1", iocs=["1.2.3.4"])

    result = ingest_alert(
        "generic",
        {"description": "low severity but related", "severity": "low", "source": "test", "iocs": ["1.2.3.4"]},
        tenant_id="t1",
    )

    assert result["outcome"] == "correlated"
    assert len(fake_merge_correlated_alert) == 1


def test_dedup_takes_priority_over_correlation(fake_run_new_incident, fake_merge_correlated_alert):
    from ingestion.pipeline import ingest_alert

    _seed_open_incident("t1", "inc-1", iocs=["1.2.3.4"])
    payload = {
        "description": "related alert",
        "severity": "high",
        "source": "test",
        "iocs": ["1.2.3.4"],
        "dedup_key": "fixed-key",
    }

    first = ingest_alert("generic", payload, tenant_id="t1")
    second = ingest_alert("generic", payload, tenant_id="t1")

    assert first["outcome"] == "correlated"
    assert second["outcome"] == "deduped"
    assert len(fake_merge_correlated_alert) == 1


def test_unrelated_alert_with_no_correlation_still_promotes_normally(
    fake_run_new_incident, fake_merge_correlated_alert
):
    from ingestion.pipeline import ingest_alert

    _seed_open_incident("t1", "inc-1", iocs=["1.2.3.4"])

    result = ingest_alert(
        "generic",
        {"description": "unrelated", "severity": "high", "source": "test", "iocs": ["9.9.9.9"]},
        tenant_id="t1",
    )

    assert result["outcome"] == "promoted"
    assert len(fake_merge_correlated_alert) == 0
    assert len(fake_run_new_incident) == 1


def test_fuzzy_subnet_match_correlates_and_surfaces_reason(fake_run_new_incident, fake_merge_correlated_alert):
    from ingestion.pipeline import ingest_alert

    _seed_open_incident("t1", "inc-1", iocs=["10.0.0.5"])

    result = ingest_alert(
        "generic",
        {"description": "same subnet, different IP", "severity": "high", "source": "test", "iocs": ["10.0.0.9"]},
        tenant_id="t1",
    )

    assert result["outcome"] == "correlated"
    assert result["match_type"] == "subnet"
    assert "10.0.0.9" in result["reason"] and "10.0.0.5" in result["reason"]
    merge_call = fake_merge_correlated_alert[0]
    assert merge_call["match_reason"] == result["reason"]


def test_renamed_asset_correlates_via_identity_tier(
    fake_run_new_incident, fake_merge_correlated_alert, monkeypatch, tmp_path
):
    """A renamed asset shares no IOC and no exact/fuzzy signal with the
    open incident -- exercises the full ingest_alert() -> pipeline wiring
    for ingestion/identity_correlation.py, not just the tier in
    isolation."""
    import json

    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(json.dumps({"WEB-01": "asset-042", "WEB-01-RENAMED": "asset-042"}))
    monkeypatch.setenv("CAVENDEX_ASSET_INVENTORY_PATH", str(inventory_path))

    from ingestion.pipeline import ingest_alert

    _seed_open_incident("t1", "inc-1", affected_assets=["WEB-01"])

    result = ingest_alert(
        "generic",
        {
            "description": "same host, new name",
            "severity": "high",
            "source": "test",
            "affected_assets": ["WEB-01-RENAMED"],
        },
        tenant_id="t1",
    )

    assert result["outcome"] == "correlated"
    assert result["thread_id"] == "inc-1"
    assert result["match_type"] == "identity_asset"
    assert len(fake_merge_correlated_alert) == 1
    assert len(fake_run_new_incident) == 0


def test_identity_tier_only_checked_when_exact_fuzzy_tier_finds_nothing(
    fake_run_new_incident, fake_merge_correlated_alert, monkeypatch, tmp_path
):
    """Exact IOC match must win even when an identity match is also
    available -- exact/fuzzy is checked first."""
    import json

    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(json.dumps({"WEB-01": "asset-042", "WEB-01-RENAMED": "asset-042"}))
    monkeypatch.setenv("CAVENDEX_ASSET_INVENTORY_PATH", str(inventory_path))

    from ingestion.pipeline import ingest_alert

    _seed_open_incident("t1", "inc-identity", affected_assets=["WEB-01"])
    _seed_open_incident("t1", "inc-exact", iocs=["1.2.3.4"])

    result = ingest_alert(
        "generic",
        {
            "description": "matches both tiers",
            "severity": "high",
            "source": "test",
            "iocs": ["1.2.3.4"],
            "affected_assets": ["WEB-01-RENAMED"],
        },
        tenant_id="t1",
    )

    assert result["outcome"] == "correlated"
    assert result["thread_id"] == "inc-exact"
    assert result["match_type"] == "exact_ioc"


def test_semantic_match_correlates_and_passes_usage_to_merge(
    fake_run_new_incident, fake_merge_correlated_alert, fake_semantic_correlation
):
    from ingestion.pipeline import ingest_alert

    usage = {"input_tokens": 30, "output_tokens": 10, "total_tokens": 40}
    fake_semantic_correlation["return_value"] = (
        {"thread_id": "inc-9", "match_type": "semantic", "reason": "same TTP, different host", "confidence": "high"},
        usage,
    )

    result = ingest_alert(
        "generic",
        {"description": "brute force against an unrelated host", "severity": "high", "source": "test"},
        tenant_id="t1",
    )

    assert result["outcome"] == "correlated"
    assert result["match_type"] == "semantic"
    assert result["reason"] == "same TTP, different host"
    assert len(fake_run_new_incident) == 0
    merge_call = fake_merge_correlated_alert[0]
    assert merge_call["thread_id"] == "inc-9"
    assert merge_call["usage"] == usage


def test_semantic_no_match_promotes_with_seed_usage(
    fake_run_new_incident, fake_merge_correlated_alert, fake_semantic_correlation
):
    from ingestion.pipeline import ingest_alert

    usage = {"input_tokens": 30, "output_tokens": 10, "total_tokens": 40}
    fake_semantic_correlation["return_value"] = (None, usage)

    result = ingest_alert(
        "generic",
        {"description": "checked but nothing correlated", "severity": "high", "source": "test"},
        tenant_id="t1",
    )

    assert result["outcome"] == "promoted"
    assert len(fake_merge_correlated_alert) == 0
    assert fake_run_new_incident[0]["seed_usage"] == usage


def test_semantic_zero_usage_does_not_seed_promotion(
    fake_run_new_incident, fake_merge_correlated_alert, fake_semantic_correlation
):
    """When the semantic tier never actually ran (disabled/no candidates),
    it returns all-zero usage — that should NOT get threaded into
    run_new_incident as a seed, or every incident would grow a pointless
    zero-valued 'Correlation Judge' token_usage entry forever."""
    from ingestion.pipeline import ingest_alert

    result = ingest_alert(
        "generic",
        {"description": "semantic tier disabled by default", "severity": "high", "source": "test"},
        tenant_id="t1",
    )

    assert result["outcome"] == "promoted"
    assert fake_run_new_incident[0]["seed_usage"] is None


def test_semantic_tier_is_not_checked_for_suppressed_low_severity_alerts(
    fake_run_new_incident, fake_merge_correlated_alert, monkeypatch
):
    """The semantic tier costs real tokens, so it must never even be
    called for an alert that's going to be suppressed as noise anyway —
    unlike the free exact/fuzzy tiers, it does not run ahead of the
    severity floor."""
    import ingestion.pipeline as pipeline_mod
    from ingestion.pipeline import ingest_alert

    def _fail(tenant_id, alert):
        raise AssertionError("semantic tier must not be checked for a suppressed alert")

    monkeypatch.setattr(pipeline_mod, "find_semantic_correlation", _fail)

    result = ingest_alert(
        "generic",
        {"description": "routine low severity noise", "severity": "low", "source": "test"},
        tenant_id="t1",
    )

    assert result["outcome"] == "suppressed_low_severity"


# ---------- Rate limiting: the shared gate, not just the API layer ----------


def test_ingest_is_rate_limited_independent_of_the_api_layer(monkeypatch, fake_run_new_incident):
    """This is the fix for a real, live-caught gap: syslog_listener.py and
    poll_connector.py call ingest_alert()/ingest_normalized_alert()
    in-process, never touching api.py's FastAPI rate-limit dependency —
    so the gate itself must enforce a limit, or a network-reachable
    syslog listener has zero abuse resistance."""
    monkeypatch.setenv("CAVENDEX_INGEST_RATE_LIMIT_PER_MINUTE", "2")
    from ingestion.pipeline import ingest_alert

    def _alert(n):
        return {"description": f"alert {n}", "severity": "high", "source": "test", "dedup_key": f"k{n}"}

    first = ingest_alert("generic", _alert(1), tenant_id="rl-tenant")
    second = ingest_alert("generic", _alert(2), tenant_id="rl-tenant")
    third = ingest_alert("generic", _alert(3), tenant_id="rl-tenant")

    assert first["outcome"] == "promoted"
    assert second["outcome"] == "promoted"
    assert third["outcome"] == "rate_limited"
    assert "retry_after" in third
    assert len(fake_run_new_incident) == 2


def test_ingest_rate_limit_is_checked_before_dedup(monkeypatch, fake_run_new_incident):
    """Rate limiting is the very first gate — even an exact duplicate
    still counts against the limit, since the point is bounding total
    call volume into this function, not just volume that would've been
    promoted anyway."""
    monkeypatch.setenv("CAVENDEX_INGEST_RATE_LIMIT_PER_MINUTE", "1")
    from ingestion.pipeline import ingest_alert

    payload = {"description": "x", "severity": "high", "source": "test", "dedup_key": "fixed"}
    first = ingest_alert("generic", payload, tenant_id="rl-tenant-2")
    second = ingest_alert("generic", payload, tenant_id="rl-tenant-2")

    assert first["outcome"] == "promoted"
    assert second["outcome"] == "rate_limited"  # not "deduped" — rate limit wins


def test_ingest_rate_limit_disabled_by_zero(monkeypatch, fake_run_new_incident):
    monkeypatch.setenv("CAVENDEX_INGEST_RATE_LIMIT_PER_MINUTE", "0")
    from ingestion.pipeline import ingest_alert

    for n in range(5):
        result = ingest_alert(
            "generic",
            {"description": f"alert {n}", "severity": "high", "source": "test", "dedup_key": f"k{n}"},
            tenant_id="rl-tenant-3",
        )
        assert result["outcome"] == "promoted"


def test_ingest_rate_limit_is_scoped_per_tenant(monkeypatch, fake_run_new_incident):
    monkeypatch.setenv("CAVENDEX_INGEST_RATE_LIMIT_PER_MINUTE", "1")
    from ingestion.pipeline import ingest_alert

    r1 = ingest_alert(
        "generic", {"description": "x", "severity": "high", "source": "test", "dedup_key": "k1"},
        tenant_id="tenant-a",
    )
    r2 = ingest_alert(
        "generic", {"description": "y", "severity": "high", "source": "test", "dedup_key": "k2"},
        tenant_id="tenant-b",
    )

    assert r1["outcome"] == "promoted"
    assert r2["outcome"] == "promoted"  # a different tenant's own bucket, unaffected
