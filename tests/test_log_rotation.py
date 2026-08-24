"""Tests utils/log_rotation.py's size-based rotation — the fix for the
three previously-unbounded JSONL logs (ingestion_log.jsonl,
auth_failures.jsonl, audit_chain_ledger.jsonl) growing forever."""

import os

from utils.log_rotation import append_line


def test_appends_without_rotating_when_under_the_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELOS_LOG_MAX_BYTES", "1000000")
    path = str(tmp_path / "log.jsonl")

    append_line(path, "line one")
    append_line(path, "line two")

    assert not os.path.exists(f"{path}.1")
    assert open(path).read().splitlines() == ["line one", "line two"]


def test_rotates_once_the_size_threshold_is_crossed(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELOS_LOG_MAX_BYTES", "10")  # tiny, forces rotation fast
    monkeypatch.setenv("SENTINELOS_LOG_BACKUP_COUNT", "3")
    path = str(tmp_path / "log.jsonl")

    for i in range(5):
        append_line(path, f"entry-{i}" * 3)  # long enough to cross 10 bytes quickly

    assert os.path.exists(f"{path}.1")
    # The active file always has the most recent write, never empty.
    assert open(path).read().strip() != ""


def test_backup_count_is_respected(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELOS_LOG_MAX_BYTES", "1")  # rotate on every single write
    monkeypatch.setenv("SENTINELOS_LOG_BACKUP_COUNT", "2")
    path = str(tmp_path / "log.jsonl")

    for i in range(6):
        append_line(path, f"entry-{i}")

    assert os.path.exists(f"{path}.1")
    assert os.path.exists(f"{path}.2")
    assert not os.path.exists(f"{path}.3")  # oldest ones dropped, never accumulate forever


def test_rotation_preserves_chronological_order_across_files(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELOS_LOG_MAX_BYTES", "1")  # rotate on every write
    monkeypatch.setenv("SENTINELOS_LOG_BACKUP_COUNT", "5")
    path = str(tmp_path / "log.jsonl")

    for i in range(4):
        append_line(path, f"entry-{i}")

    # entry-3 is newest -> active file; entry-2 -> .1 (next newest); etc.
    assert open(path).read().strip() == "entry-3"
    assert open(f"{path}.1").read().strip() == "entry-2"
    assert open(f"{path}.2").read().strip() == "entry-1"
    assert open(f"{path}.3").read().strip() == "entry-0"


def test_rotation_disabled_by_zero_max_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELOS_LOG_MAX_BYTES", "0")
    path = str(tmp_path / "log.jsonl")

    for i in range(20):
        append_line(path, f"entry-{i}" * 10)

    assert not os.path.exists(f"{path}.1")
    assert len(open(path).read().splitlines()) == 20


def test_zero_backup_count_truncates_instead_of_growing_forever(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELOS_LOG_MAX_BYTES", "1")
    monkeypatch.setenv("SENTINELOS_LOG_BACKUP_COUNT", "0")
    path = str(tmp_path / "log.jsonl")

    for i in range(5):
        append_line(path, f"entry-{i}")

    assert not os.path.exists(f"{path}.1")
    # Only ever the single most recent line -- old data dropped, not kept.
    assert open(path).read().strip() == "entry-4"


def test_never_raises_when_the_directory_cannot_be_created(tmp_path):
    blocker = tmp_path / "blocks-the-directory"
    blocker.write_text("x")
    bad_path = str(blocker / "sub" / "log.jsonl")

    append_line(bad_path, "entry")  # must not raise
