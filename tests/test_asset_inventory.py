"""Tests utils/asset_inventory.py's local alias -> canonical-identity map:
unconfigured/missing/malformed all degrade to "no inventory", a valid
mapping resolves, and edits to the file are picked up via mtime without
a process restart."""

import json

from utils.asset_inventory import reset_for_tests, resolve_asset_identity


def setup_function():
    reset_for_tests()


def test_returns_none_when_unconfigured(monkeypatch):
    monkeypatch.delenv("SENTINELOS_ASSET_INVENTORY_PATH", raising=False)
    assert resolve_asset_identity("WEB-01") is None


def test_returns_none_when_file_does_not_exist(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELOS_ASSET_INVENTORY_PATH", str(tmp_path / "missing.json"))
    assert resolve_asset_identity("WEB-01") is None


def test_returns_none_for_malformed_json(monkeypatch, tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text("not valid json{{{")
    monkeypatch.setenv("SENTINELOS_ASSET_INVENTORY_PATH", str(path))
    assert resolve_asset_identity("WEB-01") is None


def test_returns_none_for_non_object_json(monkeypatch, tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(["WEB-01", "asset-042"]))
    monkeypatch.setenv("SENTINELOS_ASSET_INVENTORY_PATH", str(path))
    assert resolve_asset_identity("WEB-01") is None


def test_resolves_a_valid_mapping(monkeypatch, tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"WEB-01": "asset-042", "WEB-01-RENAMED": "asset-042"}))
    monkeypatch.setenv("SENTINELOS_ASSET_INVENTORY_PATH", str(path))

    assert resolve_asset_identity("WEB-01") == "asset-042"
    assert resolve_asset_identity("WEB-01-RENAMED") == "asset-042"


def test_unknown_name_returns_none(monkeypatch, tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"WEB-01": "asset-042"}))
    monkeypatch.setenv("SENTINELOS_ASSET_INVENTORY_PATH", str(path))

    assert resolve_asset_identity("NOT-IN-THE-FILE") is None


def test_lookup_is_exact_string_not_case_folded(monkeypatch, tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"WEB-01": "asset-042"}))
    monkeypatch.setenv("SENTINELOS_ASSET_INVENTORY_PATH", str(path))

    assert resolve_asset_identity("web-01") is None


def test_reload_picks_up_edits_via_mtime(monkeypatch, tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"WEB-01": "asset-042"}))
    monkeypatch.setenv("SENTINELOS_ASSET_INVENTORY_PATH", str(path))

    assert resolve_asset_identity("DC-01") is None

    import os
    import time

    time.sleep(0.01)
    path.write_text(json.dumps({"WEB-01": "asset-042", "DC-01": "asset-001"}))
    os.utime(path, None)

    assert resolve_asset_identity("DC-01") == "asset-001"
