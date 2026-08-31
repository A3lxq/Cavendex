"""Alert deduplication — in-process by default, or Redis-backed (opt-in,
`CAVENDEX_REDIS_URL`, the same switch utils/rate_limit.py uses) so a
multi-replica deployment shares one real dedup window across every
process instead of each replica tracking "last seen" independently,
which would let the same alert slip through as a fresh incident on every
replica it happens to land on via round-robin.

Suppresses repeat alerts sharing the same (tenant, dedup_key) within a
short window, so a single ongoing scan/attack producing dozens of
near-identical events doesn't spawn dozens of independent incidents (and
LLM pipeline runs) for the same thing Cavendex already knows about.

Unconfigured (the default), this is exactly what it always was: stdlib
only, "good enough for a single process." Set CAVENDEX_REDIS_URL and
this switches to a real Redis-backed implementation — same public
function signature and semantics, callers never know the difference.
See utils/rate_limit.py's own docstring for why a Redis command/
connection failure is deliberately never swallowed here either, and why
`now` (test-only) is treated as authoritative while production
(`now=None`) sources the shared clock from Redis's own `TIME` command
rather than each replica's local wall clock.
"""

import os
import threading
import time
from typing import Optional

_lock = threading.Lock()
_last_seen: dict = {}

_redis_client = None

# GETSET-then-compare, done as one atomic script so two replicas racing
# on the same key can't both read "no prior sighting" and both decide
# "not a duplicate" — the actual failure mode a real distributed dedup
# needs to close, not just "works most of the time" from separate
# GET/SET calls.
_DEDUP_SCRIPT = """
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[1])
local last = redis.call('GET', KEYS[1])
redis.call('SET', KEYS[1], ARGV[1])
if window > 0 then
    redis.call('EXPIRE', KEYS[1], math.ceil(window))
end
if window <= 0 then
    return 0
end
if last == false then
    return 0
end
if (now - tonumber(last)) < window then
    return 1
end
return 0
"""


def _redis_url() -> str:
    return os.getenv("CAVENDEX_REDIS_URL", "").strip()


def _get_redis_client():
    global _redis_client
    url = _redis_url()
    if not url:
        return None
    if _redis_client is None:
        import redis

        _redis_client = redis.Redis.from_url(url)
    return _redis_client


def _is_duplicate_redis(client, tenant_id: str, dedup_key: str, window: float, now: Optional[float]) -> bool:
    key = f"cavendex:dedup:{tenant_id}:{dedup_key}"
    if now is None:
        seconds, microseconds = client.time()
        now = seconds + microseconds / 1_000_000
    return bool(int(client.eval(_DEDUP_SCRIPT, 1, key, str(now), str(window))))


def _window_seconds() -> float:
    try:
        return float(os.getenv("CAVENDEX_DEDUP_WINDOW_SECONDS", "300"))
    except ValueError:
        return 300.0


def is_duplicate(tenant_id: str, dedup_key: str, now: Optional[float] = None) -> bool:
    """Record this (tenant, dedup_key) sighting and return True if an
    identical one was already seen within the dedup window, or False if
    this is new (or the window has expired) — either way, this sighting
    becomes the new "last seen" timestamp.

    A window of 0 (or negative) disables deduplication entirely, for
    either backend.
    """
    window = _window_seconds()

    client = _get_redis_client()
    if client is not None:
        return _is_duplicate_redis(client, tenant_id, dedup_key, window, now)

    now = time.monotonic() if now is None else now
    key = (tenant_id, dedup_key)

    with _lock:
        last_seen = _last_seen.get(key)
        _last_seen[key] = now
        if window <= 0:
            return False
        return last_seen is not None and (now - last_seen) < window


def reset_for_tests() -> None:
    """Clear all dedup state, in-memory and (if a client was ever
    constructed) Redis — and drop the cached Redis client itself, the
    same reasoning as utils/rate_limit.py:reset_for_tests(). Test-only.
    """
    global _redis_client
    with _lock:
        _last_seen.clear()
    if _redis_client is not None:
        try:
            for k in _redis_client.scan_iter("cavendex:dedup:*"):
                _redis_client.delete(k)
        except Exception:
            pass
    _redis_client = None
