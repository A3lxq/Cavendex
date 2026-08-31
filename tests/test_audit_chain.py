"""Tests utils/audit_chain.py's hash-chain tamper-evidence: the chain
hash is deterministic and sensitive to any edit/reorder/deletion, the
ledger is a genuine append-only record on disk, and verification
correctly distinguishes "never recorded" from "tampered" from "matches".
"""

import json
import os

import pytest

from utils.audit_chain import (
    _ledger_path,
    compute_chain_hash,
    latest_recorded_entry,
    record_chain,
    verify_incident_audit_log,
)


def test_ledger_path_sanitizes_a_path_traversal_tenant_id(monkeypatch, tmp_path):
    """Security regression: an unsanitized tenant_id (e.g. reaching here
    from an API caller who supplies ".." in a /tenants/{tenant_id}/...
    URL segment) must never escape CAVENDEX_DATA_DIR by one directory
    level -- every other tenant-scoped module already sanitizes; this
    one didn't."""
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path / "data"))
    path = _ledger_path("..")
    assert ".." not in path.split(os.sep)
    assert path == str(tmp_path / "data" / "default" / "audit_chain_ledger.jsonl")


def test_chain_hash_is_deterministic():
    entries = ["Triage Agent -> escalated", "Responder Agent -> proposed action"]
    assert compute_chain_hash(entries) == compute_chain_hash(list(entries))


def test_chain_hash_changes_if_an_entry_is_edited():
    original = ["Triage Agent -> escalated"]
    edited = ["Triage Agent -> closed"]
    assert compute_chain_hash(original) != compute_chain_hash(edited)


def test_chain_hash_changes_if_entries_are_reordered():
    a = ["first", "second"]
    b = ["second", "first"]
    assert compute_chain_hash(a) != compute_chain_hash(b)


def test_chain_hash_changes_if_an_entry_is_deleted():
    full = ["first", "second", "third"]
    truncated = ["first", "third"]
    assert compute_chain_hash(full) != compute_chain_hash(truncated)


def test_chain_hash_changes_if_an_entry_is_appended():
    before = ["first"]
    after = ["first", "second"]
    assert compute_chain_hash(before) != compute_chain_hash(after)


def test_empty_audit_log_has_a_stable_genesis_hash():
    assert compute_chain_hash([]) == compute_chain_hash([])


def test_record_chain_writes_an_append_only_ledger_entry(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))

    record_chain("acme", "inc-1", ["entry one"])
    record_chain("acme", "inc-1", ["entry one", "entry two"])

    ledger_path = tmp_path / "acme" / "audit_chain_ledger.jsonl"
    lines = ledger_path.read_text().strip().splitlines()
    assert len(lines) == 2  # both calls appended, neither overwrote the other
    assert json.loads(lines[0])["audit_log_length"] == 1
    assert json.loads(lines[1])["audit_log_length"] == 2


def test_latest_recorded_entry_returns_the_most_recent_one(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    record_chain("acme", "inc-1", ["a"])
    record_chain("acme", "inc-1", ["a", "b"])

    latest = latest_recorded_entry("acme", "inc-1")

    assert latest["audit_log_length"] == 2
    assert latest["chain_hash"] == compute_chain_hash(["a", "b"])


def test_latest_recorded_entry_scoped_per_thread(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    record_chain("acme", "inc-1", ["a"])
    record_chain("acme", "inc-2", ["z", "y"])

    assert latest_recorded_entry("acme", "inc-1")["audit_log_length"] == 1
    assert latest_recorded_entry("acme", "inc-2")["audit_log_length"] == 2


def test_verify_returns_no_record_when_never_recorded(tmp_path, monkeypatch):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    result = verify_incident_audit_log("acme", "never-recorded", ["x"])
    assert result["status"] == "no_record"


def test_verify_returns_verified_when_unchanged(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    audit_log = ["Triage Agent -> escalated", "Responder Agent -> proposed action"]
    record_chain("acme", "inc-1", audit_log)

    result = verify_incident_audit_log("acme", "inc-1", audit_log)

    assert result["status"] == "verified"


def test_verify_detects_a_tampered_entry(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    record_chain("acme", "inc-1", ["Triage Agent -> escalated"])

    tampered = ["Triage Agent -> closed (no threat found)"]  # edited after the fact
    result = verify_incident_audit_log("acme", "inc-1", tampered)

    assert result["status"] == "MISMATCH"


def test_verify_detects_a_deleted_entry(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    record_chain("acme", "inc-1", ["entry one", "Human Reviewer (j.smith) -> approved 1 action(s)"])

    with_entry_removed = ["entry one"]
    result = verify_incident_audit_log("acme", "inc-1", with_entry_removed)

    assert result["status"] == "MISMATCH"


def test_latest_recorded_entry_survives_ledger_rotation(monkeypatch, tmp_path):
    """The ledger rotates like any other log (utils/log_rotation.py) --
    confirm a thread's true latest entry is still found even after it's
    been pushed into a rotated-out backup file, not just the active one.
    """
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CAVENDEX_LOG_MAX_BYTES", "1")  # force rotation on every write
    monkeypatch.setenv("CAVENDEX_LOG_BACKUP_COUNT", "5")

    record_chain("acme", "inc-1", ["first entry"])
    record_chain("acme", "inc-2", ["unrelated incident, written after inc-1"])
    record_chain("acme", "inc-1", ["first entry", "second entry"])  # inc-1's true latest

    latest = latest_recorded_entry("acme", "inc-1")

    assert latest["audit_log_length"] == 2
    assert latest["chain_hash"] == compute_chain_hash(["first entry", "second entry"])


def test_verify_still_works_correctly_after_rotation(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CAVENDEX_LOG_MAX_BYTES", "1")
    monkeypatch.setenv("CAVENDEX_LOG_BACKUP_COUNT", "5")

    audit_log = ["a", "b", "c"]
    record_chain("acme", "inc-1", ["a"])
    record_chain("acme", "inc-1", ["a", "b"])
    record_chain("acme", "inc-1", audit_log)

    assert verify_incident_audit_log("acme", "inc-1", audit_log)["status"] == "verified"
    assert verify_incident_audit_log("acme", "inc-1", ["a", "b"])["status"] == "MISMATCH"


def test_record_chain_never_raises_when_data_dir_is_unwritable(monkeypatch, tmp_path):
    blocker = tmp_path / "blocks-the-directory"
    blocker.write_text("x")
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(blocker))

    record_chain("acme", "inc-1", ["entry"])  # must not raise
