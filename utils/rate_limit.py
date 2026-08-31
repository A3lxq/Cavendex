"""Sliding-window rate limiter — in-process by default, or Redis-backed
(opt-in, `CAVENDEX_REDIS_URL`) so a multi-replica deployment shares one
real limit across every process instead of each replica enforcing its
own independently (which lets a client multiply its effective quota by
the number of replicas simply by round-robin-hitting all of them).

Guards the LLM-triggering API endpoints (incident/hunt creation) against
a client hammering them into many expensive LLM calls back to back —
and, via ingestion/pipeline.py's own call into check_rate_limit(), the
shared ingestion gate itself, so syslog_listener.py/poll_connector.py/
ingest_watch.py's in-process paths (which never go through the API layer
at all) get the same protection, not just HTTP callers. That gap — a
network-reachable syslog listener with attacker-controlled severity/
dedup_key fields and zero rate limiting on the in-process path — was a
real, live-caught issue, not a hypothetical one.

Unconfigured (the default), this is exactly what it always was: stdlib
only, "good enough for a single-process local/internal deployment," not
a distributed rate limiter. Set CAVENDEX_REDIS_URL and both this
module and utils/dedup.py switch to a real Redis-backed implementation —
same public function signature, same semantics, callers never know the
difference.

The Redis path deliberately never swallows a connection/command error:
a rate limiter exists specifically to hold up under exactly the kind of
load spike (or attack) that correlates with the infrastructure it
depends on coming under strain, and failing open here — silently
admitting every request because Redis hiccuped — would defeat the whole
point. Every caller of check_rate_limit() already has a sensible
response to an exception surfacing from it: api.py's dependency lets
FastAPI turn it into a 500 (loud, visible, not a silent bypass);
ingestion/pipeline.py's callers (syslog_listener.py, poll_connector.py)
already wrap their per-message/per-poll work in try/except and log-and-
continue.

`now` (given only by tests, for determinism) is treated as an already-
authoritative timestamp for either backend. In production
(`now=None`), the in-memory backend uses `time.monotonic()` as before;
the Redis backend calls the Redis server's own `TIME` command instead
of the *local* wall clock — the whole point of centralizing rate-limit
state in Redis is to have one shared decision, and comparing a
sliding-window score written by clock A against a cutoff computed by
clock B (two different replica hosts, potentially skewed) would
reintroduce exactly the kind of inconsistency this feature exists to
remove.
"""

import os
import threading
import time
from collections import defaultdict, deque
from typing import Optional

_WINDOW_SECONDS = 60.0

_lock = threading.Lock()
_requests: dict = defaultdict(deque)

_redis_client = None

# Sliding-window log: prune anything older than the window, then either
# admit (recording this request) or reject (reporting how long until the
# oldest entry ages out). The `:seq` counter gives each entry within the
# same key a unique sorted-set member even when two requests land on the
# exact same score (a fixed `now` in tests, or two requests in the same
# microsecond in production) — a plain score-as-member scheme would
# silently collapse those into one entry and undercount.
_RATE_LIMIT_SCRIPT = """
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[1])
local limit = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local count = redis.call('ZCARD', KEYS[1])
if count >= limit then
    local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
    local retry_after = window - (now - tonumber(oldest[2]))
    if retry_after < 1 then retry_after = 1 end
    return tostring(retry_after)
end
local seq = redis.call('INCR', KEYS[1] .. ':seq')
redis.call('ZADD', KEYS[1], now, tostring(now) .. '-' .. tostring(seq))
local ttl = math.ceil(window) + 1
redis.call('EXPIRE', KEYS[1], ttl)
redis.call('EXPIRE', KEYS[1] .. ':seq', ttl)
return '0'
"""


def _redis_url() -> str:
    return os.getenv("CAVENDEX_REDIS_URL", "").strip()


def _get_redis_client():
    """Lazily constructs and caches a real redis-py client the first
    time a URL is configured — never imports `redis` at all when it
    isn't, keeping that dependency's presence irrelevant to a deployment
    that doesn't use it. A connection/command failure surfaces from the
    actual EVAL call in _check_rate_limit_redis, not here.
    """
    global _redis_client
    url = _redis_url()
    if not url:
        return None
    if _redis_client is None:
        import redis

        _redis_client = redis.Redis.from_url(url)
    return _redis_client


def _check_rate_limit_redis(client, key: str, limit: int, now: Optional[float]) -> Optional[float]:
    zkey = f"cavendex:ratelimit:{key}"
    if now is None:
        seconds, microseconds = client.time()
        now = seconds + microseconds / 1_000_000
    result = float(client.eval(_RATE_LIMIT_SCRIPT, 1, zkey, str(now), str(_WINDOW_SECONDS), str(limit)))
    return None if result == 0 else result


def _limit_per_minute() -> int:
    try:
        return int(os.getenv("CAVENDEX_RATE_LIMIT_PER_MINUTE", "10"))
    except ValueError:
        return 10


def check_rate_limit(key: str, now: float = None, limit: Optional[int] = None) -> Optional[float]:
    """Record one request for `key` and return None if it's allowed, or the
    number of seconds until the caller should retry if it's not.

    `limit` overrides CAVENDEX_RATE_LIMIT_PER_MINUTE for this call — used
    by ingestion/pipeline.py, which needs its own (typically higher, since
    real alert volume is expected) limit than the analyst-facing API
    routes, while sharing this same sliding-window implementation instead
    of duplicating it.

    A limit of 0 (or negative) disables rate limiting entirely, for
    either backend.
    """
    limit = _limit_per_minute() if limit is None else limit
    if limit <= 0:
        return None

    client = _get_redis_client()
    if client is not None:
        return _check_rate_limit_redis(client, key, limit, now)

    now = time.monotonic() if now is None else now

    with _lock:
        bucket = _requests[key]
        while bucket and now - bucket[0] > _WINDOW_SECONDS:
            bucket.popleft()

        if len(bucket) >= limit:
            retry_after = _WINDOW_SECONDS - (now - bucket[0])
            return max(1.0, retry_after)

        bucket.append(now)
        return None


def reset_for_tests() -> None:
    """Clear all rate-limit state, in-memory and (if a client was ever
    constructed) Redis — and drop the cached Redis client itself, so the
    next check_rate_limit() call re-reads CAVENDEX_REDIS_URL fresh
    rather than reusing a connection built under a different test's
    configuration. Test-only; application code never calls this.
    """
    global _redis_client
    with _lock:
        _requests.clear()
    if _redis_client is not None:
        try:
            for pattern in ("cavendex:ratelimit:*",):
                for k in _redis_client.scan_iter(pattern):
                    _redis_client.delete(k)
        except Exception:
            pass
    _redis_client = None
