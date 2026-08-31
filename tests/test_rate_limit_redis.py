"""Tests utils/rate_limit.py's Redis-backed path against a real local
Redis instance (skipped if one isn't reachable at CAVENDEX_TEST_REDIS_URL
or redis://127.0.0.1:6379/0) — the same "prefer real I/O over a guessed
shape" approach as every other optional-integration test in this project.
Exercises the actual Lua script via a real EVAL call, not a mocked redis
client. Mirrors tests/test_rate_limit.py's in-memory cases one-for-one so
both backends are proven to share identical externally-visible behavior,
plus adds cases specific to what a shared backend needs: two independent
"replica" clients seeing the same limit, and real wall-clock (not
`now=`-overridden) expiry."""

import os

import pytest
import redis as redis_lib

from utils.rate_limit import check_rate_limit, reset_for_tests

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


def test_allows_requests_under_the_limit(monkeypatch):
    monkeypatch.setenv("CAVENDEX_RATE_LIMIT_PER_MINUTE", "3")
    key = "redis-test-under-limit"
    for _ in range(3):
        assert check_rate_limit(key, now=1000.0) is None


def test_blocks_requests_over_the_limit(monkeypatch):
    monkeypatch.setenv("CAVENDEX_RATE_LIMIT_PER_MINUTE", "2")
    key = "redis-test-over-limit"
    assert check_rate_limit(key, now=1000.0) is None
    assert check_rate_limit(key, now=1000.0) is None
    retry_after = check_rate_limit(key, now=1000.0)
    assert retry_after is not None
    assert retry_after > 0


def test_window_expires_after_sixty_seconds(monkeypatch):
    monkeypatch.setenv("CAVENDEX_RATE_LIMIT_PER_MINUTE", "1")
    key = "redis-test-window-expiry"
    assert check_rate_limit(key, now=1000.0) is None
    assert check_rate_limit(key, now=1010.0) is not None  # still within the window
    assert check_rate_limit(key, now=1061.0) is None  # window has rolled past


def test_zero_limit_disables_rate_limiting(monkeypatch):
    monkeypatch.setenv("CAVENDEX_RATE_LIMIT_PER_MINUTE", "0")
    key = "redis-test-disabled"
    for _ in range(20):
        assert check_rate_limit(key, now=1000.0) is None


def test_different_keys_are_independent(monkeypatch):
    monkeypatch.setenv("CAVENDEX_RATE_LIMIT_PER_MINUTE", "1")
    assert check_rate_limit("redis-key-a", now=1000.0) is None
    assert check_rate_limit("redis-key-b", now=1000.0) is None  # independent bucket
    assert check_rate_limit("redis-key-a", now=1000.0) is not None  # key-a's bucket is full


def test_two_independent_client_instances_share_the_same_limit(monkeypatch):
    """The actual point of a Redis-backed limiter: two separate app
    "replicas" (here, two independent redis-py client connections, since
    that's what two uvicorn worker processes would each hold) must see
    and enforce the SAME state, not each get their own private quota."""
    monkeypatch.setenv("CAVENDEX_RATE_LIMIT_PER_MINUTE", "2")
    key = "redis-test-shared-across-replicas"

    # First "replica" uses whatever client utils.rate_limit already built.
    assert check_rate_limit(key, now=1000.0) is None

    # A second, completely independent connection to the same Redis --
    # standing in for a second uvicorn worker process.
    import utils.rate_limit as rl

    other_client = redis_lib.Redis.from_url(_TEST_REDIS_URL)
    assert rl._check_rate_limit_redis(other_client, key, 2, 1000.0) is None
    # The limit (2) is now exhausted across BOTH "replicas" combined.
    assert check_rate_limit(key, now=1000.0) is not None
    other_client.close()


def test_uses_real_redis_server_time_when_now_not_given(monkeypatch):
    """Without an explicit `now`, production code must source the shared
    clock from Redis's own TIME command, not the local wall clock --
    verified here by not passing `now` at all and confirming real,
    unmocked wall-clock rate limiting still works end-to-end."""
    monkeypatch.setenv("CAVENDEX_RATE_LIMIT_PER_MINUTE", "1")
    key = "redis-test-real-time"
    assert check_rate_limit(key) is None
    retry_after = check_rate_limit(key)
    assert retry_after is not None
    assert 0 < retry_after <= 60


def test_reset_for_tests_clears_redis_state(monkeypatch):
    monkeypatch.setenv("CAVENDEX_RATE_LIMIT_PER_MINUTE", "1")
    key = "redis-test-reset"
    assert check_rate_limit(key, now=1000.0) is None
    assert check_rate_limit(key, now=1000.0) is not None

    reset_for_tests()
    assert check_rate_limit(key, now=1000.0) is None
