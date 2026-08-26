"""Tests playbooks/loader.py: unconfigured/missing/malformed all degrade
to "no playbooks" (never an exception), a directory of valid files
loads, one broken file among several valid ones is skipped without
affecting the rest, and edits are picked up via mtime without a process
restart — mirrors tests/test_asset_inventory.py's conventions for the
same "small config file(s), reloaded on mtime change" shape."""

import json
import os
import time

from playbooks.loader import load_playbooks, reset_for_tests


def setup_function():
    reset_for_tests()


def _write_playbook(path, **overrides):
    defaults = dict(
        id="test-playbook",
        name="Test Playbook",
        match={"severities": ["critical"]},
        steps=[{"action_type": "block_ip", "action": "Block IP", "target_template": "{ioc}", "rationale": "r"}],
    )
    defaults.update(overrides)
    path.write_text(json.dumps(defaults))


def test_returns_empty_when_unconfigured(monkeypatch):
    monkeypatch.delenv("SENTINELOS_PLAYBOOKS_DIR", raising=False)
    assert load_playbooks() == []


def test_returns_empty_when_directory_does_not_exist(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_PLAYBOOKS_DIR", str(tmp_path / "missing"))
    assert load_playbooks() == []


def test_returns_empty_for_directory_with_no_json_files(monkeypatch, tmp_path):
    (tmp_path / "readme.txt").write_text("not a playbook")
    monkeypatch.setenv("SENTINELOS_PLAYBOOKS_DIR", str(tmp_path))
    assert load_playbooks() == []


def test_loads_a_single_valid_playbook(monkeypatch, tmp_path):
    _write_playbook(tmp_path / "ransomware.json")
    monkeypatch.setenv("SENTINELOS_PLAYBOOKS_DIR", str(tmp_path))

    playbooks = load_playbooks()
    assert len(playbooks) == 1
    assert playbooks[0].id == "test-playbook"


def test_loads_multiple_valid_playbooks(monkeypatch, tmp_path):
    _write_playbook(tmp_path / "a.json", id="pb-a")
    _write_playbook(tmp_path / "b.json", id="pb-b")
    monkeypatch.setenv("SENTINELOS_PLAYBOOKS_DIR", str(tmp_path))

    ids = {p.id for p in load_playbooks()}
    assert ids == {"pb-a", "pb-b"}


def test_malformed_json_file_is_skipped_valid_ones_still_load(monkeypatch, tmp_path):
    _write_playbook(tmp_path / "good.json", id="pb-good")
    (tmp_path / "bad.json").write_text("not valid json{{{")
    monkeypatch.setenv("SENTINELOS_PLAYBOOKS_DIR", str(tmp_path))

    playbooks = load_playbooks()
    assert len(playbooks) == 1
    assert playbooks[0].id == "pb-good"


def test_schema_invalid_file_is_skipped_valid_ones_still_load(monkeypatch, tmp_path):
    _write_playbook(tmp_path / "good.json", id="pb-good")
    _write_playbook(tmp_path / "bad.json", id="pb-bad", steps=[])  # empty steps -> fails validation
    monkeypatch.setenv("SENTINELOS_PLAYBOOKS_DIR", str(tmp_path))

    playbooks = load_playbooks()
    assert len(playbooks) == 1
    assert playbooks[0].id == "pb-good"


def test_colliding_id_across_files_is_rejected_not_last_file_wins(monkeypatch, tmp_path):
    """Security regression: `id` is relied on as a stable key elsewhere
    (matcher tie-break, resolve_proposed_actions' halt/continue lookup)
    -- a second file silently reusing an id must be rejected, not
    silently let "last-listed file wins" happen."""
    _write_playbook(tmp_path / "a-first.json", id="dup-id", priority=1)
    _write_playbook(tmp_path / "b-second.json", id="dup-id", priority=99)
    monkeypatch.setenv("SENTINELOS_PLAYBOOKS_DIR", str(tmp_path))

    playbooks = load_playbooks()
    assert len(playbooks) == 1
    assert playbooks[0].priority == 1  # the first-loaded (alphabetically) file wins, not silently the second


def test_reload_picks_up_a_new_file_via_mtime(monkeypatch, tmp_path):
    _write_playbook(tmp_path / "a.json", id="pb-a")
    monkeypatch.setenv("SENTINELOS_PLAYBOOKS_DIR", str(tmp_path))

    assert {p.id for p in load_playbooks()} == {"pb-a"}

    time.sleep(0.01)
    _write_playbook(tmp_path / "b.json", id="pb-b")
    os.utime(tmp_path / "b.json", None)

    assert {p.id for p in load_playbooks()} == {"pb-a", "pb-b"}


def test_reload_picks_up_an_edit_via_mtime(monkeypatch, tmp_path):
    path = tmp_path / "a.json"
    _write_playbook(path, id="pb-a", priority=0)
    monkeypatch.setenv("SENTINELOS_PLAYBOOKS_DIR", str(tmp_path))

    assert load_playbooks()[0].priority == 0

    time.sleep(0.01)
    _write_playbook(path, id="pb-a", priority=5)
    os.utime(path, None)

    assert load_playbooks()[0].priority == 5
