"""In-process sliding-window rate limiter.

Guards the LLM-triggering API endpoints (incident/hunt creation) against a
client hammering them into many expensive LLM calls back to back — and,
via ingestion/pipeline.py's own call into check_rate_limit(), the shared
ingestion gate itself, so syslog_listener.py/poll_connector.py/
ingest_watch.py's in-process paths (which never go through the API layer
at all) get the same protection, not just HTTP callers. That gap — a
network-reachable syslog listener with attacker-controlled severity/
dedup_key fields and zero rate limiting on the in-process path — was a
real, live-caught issue, not a hypothetical one. Stdlib only — no new
dependency for something this simple, and it's explicitly scoped as
"good enough for a single-process local/internal deployment," not a
distributed rate limiter (see README: no rate limiting is listed as a
gap for anything beyond that).
"""

import os
import threading
import time
from collections import defaultdict, deque
from typing import Optional

_WINDOW_SECONDS = 60.0

_lock = threading.Lock()
_requests: dict = defaultdict(deque)


def _limit_per_minute() -> int:
    try:
        return int(os.getenv("SENTINELOS_RATE_LIMIT_PER_MINUTE", "10"))
    except ValueError:
        return 10


def check_rate_limit(key: str, now: float = None, limit: Optional[int] = None) -> Optional[float]:
    """Record one request for `key` and return None if it's allowed, or the
    number of seconds until the caller should retry if it's not.

    `limit` overrides SENTINELOS_RATE_LIMIT_PER_MINUTE for this call — used
    by ingestion/pipeline.py, which needs its own (typically higher, since
    real alert volume is expected) limit than the analyst-facing API
    routes, while sharing this same sliding-window implementation instead
    of duplicating it.

    A limit of 0 (or negative) disables rate limiting entirely.
    """
    limit = _limit_per_minute() if limit is None else limit
    if limit <= 0:
        return None

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
    """Clear all rate-limit state. Test-only — application code never
    calls this; it exists so tests using real (non-fixed) keys like a
    TestClient's shared pseudo-IP don't leak state between test functions.
    """
    with _lock:
        _requests.clear()
