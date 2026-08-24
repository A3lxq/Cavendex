from state import Incident
from utils.incident_index import (
    get_incident_stats,
    list_incidents,
    list_open_incidents,
    reset_for_tests,
    upsert_incident_summary,
)


def setup_function():
    reset_for_tests()


def _state(
    thread_id,
    description,
    severity="medium",
    status="open",
    tenant_id="t1",
    iocs=None,
    affected_assets=None,
    attack_technique=None,
):
    return {
        "incident": Incident(
            id=thread_id,
            description=description,
            severity=severity,
            status=status,
            iocs=iocs or [],
            affected_assets=affected_assets or [],
        ),
        "tenant_id": tenant_id,
        "attack_technique": attack_technique,
    }


def test_upsert_then_list_returns_the_incident(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    upsert_incident_summary("t1", _state("inc-1", "first incident", severity="high"))

    rows = list_incidents("t1")
    assert len(rows) == 1
    assert rows[0]["thread_id"] == "inc-1"
    assert rows[0]["severity"] == "high"


def test_upsert_updates_existing_row_not_duplicates(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    upsert_incident_summary("t1", _state("inc-1", "first incident", status="pending_approval"))
    upsert_incident_summary("t1", _state("inc-1", "first incident", status="contained"))

    rows = list_incidents("t1")
    assert len(rows) == 1
    assert rows[0]["status"] == "contained"


def test_has_pending_actions_reflects_status(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    upsert_incident_summary("t1", _state("inc-1", "x", status="pending_approval"))
    upsert_incident_summary("t1", _state("inc-2", "y", status="closed"))

    rows = {r["thread_id"]: r for r in list_incidents("t1")}
    assert rows["inc-1"]["has_pending_actions"] == 1
    assert rows["inc-2"]["has_pending_actions"] == 0


def test_tenants_have_independent_indexes(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    upsert_incident_summary("tenant-a", _state("inc-1", "x", tenant_id="tenant-a"))
    upsert_incident_summary("tenant-b", _state("inc-2", "y", tenant_id="tenant-b"))

    assert [r["thread_id"] for r in list_incidents("tenant-a")] == ["inc-1"]
    assert [r["thread_id"] for r in list_incidents("tenant-b")] == ["inc-2"]


def test_upsert_ignores_state_with_no_incident():
    upsert_incident_summary("t1", {"incident": None})
    upsert_incident_summary("t1", {})
    upsert_incident_summary("t1", None)
    # no exception raised is the assertion here


def test_upsert_stores_iocs_and_affected_assets(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    upsert_incident_summary(
        "t1", _state("inc-1", "x", iocs=["1.2.3.4"], affected_assets=["FIN-SRV-02"])
    )

    rows = list_open_incidents("t1")
    assert len(rows) == 1
    assert rows[0]["iocs"] == ["1.2.3.4"]
    assert rows[0]["affected_assets"] == ["FIN-SRV-02"]


def test_list_open_incidents_excludes_closed_and_contained(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    upsert_incident_summary("t1", _state("inc-open", "x", status="open"))
    upsert_incident_summary("t1", _state("inc-investigating", "x", status="investigating"))
    upsert_incident_summary("t1", _state("inc-pending", "x", status="pending_approval"))
    upsert_incident_summary("t1", _state("inc-contained", "x", status="contained"))
    upsert_incident_summary("t1", _state("inc-closed", "x", status="closed"))

    open_ids = {r["thread_id"] for r in list_open_incidents("t1")}
    assert open_ids == {"inc-open", "inc-investigating", "inc-pending"}


def test_list_open_incidents_scoped_by_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    upsert_incident_summary("tenant-a", _state("inc-1", "x", tenant_id="tenant-a"))
    upsert_incident_summary("tenant-b", _state("inc-2", "y", tenant_id="tenant-b"))

    assert [r["thread_id"] for r in list_open_incidents("tenant-a")] == ["inc-1"]
    assert [r["thread_id"] for r in list_open_incidents("tenant-b")] == ["inc-2"]


def test_created_at_is_preserved_across_updates(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    upsert_incident_summary("t1", _state("inc-1", "x", status="open"))
    first = list_open_incidents("t1")[0]

    upsert_incident_summary("t1", _state("inc-1", "x", status="investigating"))
    second = list_open_incidents("t1")[0]

    assert second["status"] == "investigating"
    assert second["created_at"] == first["created_at"]
    assert second["updated_at"] >= first["updated_at"]


def test_verified_attack_technique_is_stored(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    upsert_incident_summary(
        "t1",
        _state(
            "inc-1", "x",
            attack_technique={"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "verified": True},
        ),
    )

    rows = list_open_incidents("t1")
    assert rows[0]["attack_technique_id"] == "T1110"
    assert rows[0]["attack_technique_name"] == "Brute Force"


def test_unverified_attack_technique_is_not_stored(monkeypatch, tmp_path):
    """An unverified (possibly hallucinated) citation must never become
    "known ground truth" for a later semantic-correlation judgment."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    upsert_incident_summary(
        "t1",
        _state("inc-1", "x", attack_technique={"id": "T9999", "name": "Fake", "verified": False}),
    )

    rows = list_open_incidents("t1")
    assert rows[0]["attack_technique_id"] is None
    assert rows[0]["attack_technique_name"] is None


def test_no_attack_technique_cited_stores_none(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    upsert_incident_summary("t1", _state("inc-1", "x"))

    rows = list_open_incidents("t1")
    assert rows[0]["attack_technique_id"] is None
    assert rows[0]["attack_technique_name"] is None


# ---------- list_incidents filtering (search/severity/status) ----------


def _seed_mixed(tenant="t1"):
    upsert_incident_summary(tenant, _state("inc-1", "Brute force from 1.2.3.4", severity="high", status="open"))
    upsert_incident_summary(tenant, _state("inc-2", "Malware on DC-01", severity="critical", status="pending_approval"))
    upsert_incident_summary(tenant, _state("inc-3", "Suspicious login", severity="low", status="closed"))


def test_filter_by_severity(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed_mixed()

    rows = list_incidents("t1", severity="critical")

    assert [r["thread_id"] for r in rows] == ["inc-2"]


def test_filter_by_status(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed_mixed()

    rows = list_incidents("t1", status="closed")

    assert [r["thread_id"] for r in rows] == ["inc-3"]


def test_filter_by_search_is_case_insensitive_substring(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed_mixed()

    rows = list_incidents("t1", search="malware")

    assert [r["thread_id"] for r in rows] == ["inc-2"]


def test_filters_combine_with_and_semantics(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed_mixed()

    rows = list_incidents("t1", severity="high", search="brute")
    assert [r["thread_id"] for r in rows] == ["inc-1"]

    rows2 = list_incidents("t1", severity="high", search="malware")
    assert rows2 == []


def test_search_special_characters_are_escaped_not_treated_as_wildcards(monkeypatch, tmp_path):
    """A literal '%' or '_' in the search text must be matched literally,
    not treated as a SQL LIKE wildcard — otherwise searching for "100%"
    would match every description."""
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    upsert_incident_summary("t1", _state("inc-1", "CPU at 100% utilization"))
    upsert_incident_summary("t1", _state("inc-2", "CPU at 100X utilization"))

    rows = list_incidents("t1", search="100%")

    assert [r["thread_id"] for r in rows] == ["inc-1"]


def test_no_filters_returns_everything(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed_mixed()

    rows = list_incidents("t1")

    assert len(rows) == 3


# ---------- get_incident_stats ----------


def test_stats_on_empty_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))

    stats = get_incident_stats("t1")

    assert stats == {
        "total": 0,
        "open": 0,
        "pending_approval": 0,
        "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    }


def test_stats_reflect_seeded_incidents(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed_mixed()

    stats = get_incident_stats("t1")

    assert stats["total"] == 3
    assert stats["pending_approval"] == 1  # inc-2
    assert stats["open"] == 2  # inc-1 (open), inc-2 (pending_approval) -- inc-3 is closed
    assert stats["by_severity"] == {"low": 1, "medium": 0, "high": 1, "critical": 1}


def test_stats_scoped_per_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_DATA_DIR", str(tmp_path))
    _seed_mixed(tenant="t1")
    upsert_incident_summary("t2", _state("inc-x", "unrelated tenant's incident", severity="critical"))

    stats_t1 = get_incident_stats("t1")
    stats_t2 = get_incident_stats("t2")

    assert stats_t1["total"] == 3
    assert stats_t2["total"] == 1
