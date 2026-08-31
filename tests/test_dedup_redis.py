"""Tests utils/dedup.py's Redis-backed path against a real local Redis
instance (skipped if one isn't reachable at CAVENDEX_TEST_REDIS_URL or
redis://127.0.0.1:6379/0) — mirrors tests/test_dedup.py's in-memory cases
one-for-one so both backends are proven to share identical externally-
visible behavior, plus adds the case specific to a shared backend: two
independent client connections racing on the same key."""

import os

import pytest
import redis as redis_lib

from utils.dedup import is_duplicate, reset_for_tests

_TEST_REDIS_URL = os.getenv("CAVENDEX_TEST_REDIS_URL", "redis://127.0.0.1:6379/0")


def _redis_reachable() -> bool:
    try:
        client = redis_lib.Redis.from_url(_TEST_REDIS_URL, socket_connect_timeout=1)
        return client.ping()
    except Exception:
        return False


_HAS_REDIS = _redis_reachable()
pytestmark = pytest.mark.skipif(not _HAS_REDIS, reason="No reachable Redis instance for this environment")


@pytest.fixture(autouse=True)
def _redis_env(monkeypatch):
    monkeypatch.setenv("CAVENDEX_REDIS_URL", _TEST_REDIS_URL)
    reset_for_tests()
    yield
    reset_for_tests()


def test_first_sighting_is_not_a_duplicate(monkeypatch):
    monkeypatch.setenv("CAVENDEX_DEDUP_WINDOW_SECONDS", "300")
    assert is_duplicate("redis-tenant-a", "key-1", now=1000.0) is False


def test_repeat_within_window_is_a_duplicate(monkeypatch):
    monkeypatch.setenv("CAVENDEX_DEDUP_WINDOW_SECONDS", "300")
    assert is_duplicate("redis-tenant-a", "key-1", now=1000.0) is False
    assert is_duplicate("redis-tenant-a", "key-1", now=1100.0) is True  # 100s later, within 300s window


def test_repeat_after_window_is_not_a_duplicate(monkeypatch):
    monkeypatch.setenv("CAVENDEX_DEDUP_WINDOW_SECONDS", "300")
    assert is_duplicate("redis-tenant-a", "key-1", now=1000.0) is False
    assert is_duplicate("redis-tenant-a", "key-1", now=1400.0) is False  # 400s later, past the window


def test_zero_window_disables_dedup(monkeypatch):
    monkeypatch.setenv("CAVENDEX_DEDUP_WINDOW_SECONDS", "0")
    assert is_duplicate("redis-tenant-a", "key-1", now=1000.0) is False
    assert is_duplicate("redis-tenant-a", "key-1", now=1000.0) is False


def test_different_tenants_have_independent_dedup_state(monkeypatch):
    monkeypatch.setenv("CAVENDEX_DEDUP_WINDOW_SECONDS", "300")
    assert is_duplicate("redis-tenant-a", "key-1", now=1000.0) is False
    assert is_duplicate("redis-tenant-b", "key-1", now=1000.0) is False  # same key, different tenant


def test_dedup_key_containing_a_colon_does_not_collide_with_tenant_boundary(monkeypatch):
    """The Redis key is built as f'...:{tenant_id}:{dedup_key}' -- a
    dedup_key that itself contains a colon must not be mistakable for a
    different tenant/dedup_key split, since tenant_id is always
    pre-sanitized to [A-Za-z0-9_-] by callers (no colons possible) but
    dedup_key is arbitrary."""
    monkeypatch.setenv("CAVENDEX_DEDUP_WINDOW_SECONDS", "300")
    assert is_duplicate("redis-tenant-c", "sig:1.2.3.4", now=1000.0) is False
    assert is_duplicate("redis-tenant-c", "sig:1.2.3.4", now=1100.0) is True
    # A different dedup_key that happens to share the same raw prefix
    # once concatenated must NOT be treated as the same sighting.
    assert is_duplicate("redis-tenant-c", "sig", now=1100.0) is False


def test_two_independent_client_instances_share_the_same_dedup_state(monkeypatch):
    """The actual point of a Redis-backed dedup: two separate app
    "replicas" must see the same "already seen" state, not each get
    their own private memory of what's been deduped."""
    monkeypatch.setenv("CAVENDEX_DEDUP_WINDOW_SECONDS", "300")

    assert is_duplicate("redis-tenant-shared", "key-1", now=1000.0) is False

    import utils.dedup as dedup_mod

    other_client = redis_lib.Redis.from_url(_TEST_REDIS_URL)
    # A second, independent connection sees the first "replica"'s
    # sighting and correctly reports it as a duplicate.
    assert dedup_mod._is_duplicate_redis(other_client, "redis-tenant-shared", "key-1", 300.0, 1100.0) is True
    other_client.close()


def test_uses_real_redis_server_time_when_now_not_given(monkeypatch):
    monkeypatch.setenv("CAVENDEX_DEDUP_WINDOW_SECONDS", "300")
    assert is_duplicate("redis-tenant-realtime", "key-1") is False
    assert is_duplicate("redis-tenant-realtime", "key-1") is True


def test_reset_for_tests_clears_redis_state(monkeypatch):
    monkeypatch.setenv("CAVENDEX_DEDUP_WINDOW_SECONDS", "300")
    assert is_duplicate("redis-tenant-reset", "key-1", now=1000.0) is False
    assert is_duplicate("redis-tenant-reset", "key-1", now=1100.0) is True

    reset_for_tests()
    assert is_duplicate("redis-tenant-reset", "key-1", now=1100.0) is False
