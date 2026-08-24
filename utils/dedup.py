"""In-process alert deduplication.

Suppresses repeat alerts sharing the same (tenant, dedup_key) within a
short window, so a single ongoing scan/attack producing dozens of
near-identical events doesn't spawn dozens of independent incidents (and
LLM pipeline runs) for the same thing SentinelOS already knows about.
Same "good enough for a single process, not distributed" scope as
utils/rate_limit.py — a real fleet deployment would need shared state
(Redis or similar).
"""

import os
import threading
import time
from typing import Optional

_lock = threading.Lock()
_last_seen: dict = {}


def _window_seconds() -> float:
    try:
        return float(os.getenv("SENTINELOS_DEDUP_WINDOW_SECONDS", "300"))
    except ValueError:
        return 300.0


def is_duplicate(tenant_id: str, dedup_key: str, now: Optional[float] = None) -> bool:
    """Record this (tenant, dedup_key) sighting and return True if an
    identical one was already seen within the dedup window, or False if
    this is new (or the window has expired) — either way, this sighting
    becomes the new "last seen" timestamp.

    A window of 0 (or negative) disables deduplication entirely.
    """
    window = _window_seconds()
    now = time.monotonic() if now is None else now
    key = (tenant_id, dedup_key)

    with _lock:
        last_seen = _last_seen.get(key)
        _last_seen[key] = now
        if window <= 0:
            return False
        return last_seen is not None and (now - last_seen) < window


def reset_for_tests() -> None:
    """Clear all dedup state. Test-only."""
    with _lock:
        _last_seen.clear()
