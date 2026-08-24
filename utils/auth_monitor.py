"""Watches for repeated authentication failures against the API and
fires a webhook alert if they cross a threshold within a short window —
closing a real gap: SentinelOS alerts on the threat data it ingests, but
had no way to notice a burst of failed API keys against itself.

In-process, in-memory state, the same as utils/rate_limit.py and
utils/dedup.py — correct for the single-uvicorn-process topology this
project already documents as the only supported one (see DEPLOYMENT.md
section 4), not for multiple replicas behind a load balancer.

Never raises, never blocks a request — a broken/unreachable webhook (or
a disk write failure) must never turn a legitimate 401 response into a
500, the same never-block-real-processing contract every other
side-effect in this project follows.
"""

import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from utils.log_rotation import append_line

_lock = threading.Lock()
_failures: dict = {}
_alerted_until: dict = {}


def _window_seconds() -> int:
    try:
        return int(os.getenv("SENTINELOS_AUTH_FAILURE_WINDOW_SECONDS", "300"))
    except ValueError:
        return 300


def _alert_threshold() -> int:
    """Failures from the same source within the window that trigger a
    webhook alert. 0 disables alerting (failures are still logged)."""
    try:
        return int(os.getenv("SENTINELOS_AUTH_FAILURE_ALERT_THRESHOLD", "5"))
    except ValueError:
        return 5


def _log_path() -> str:
    return os.path.join(os.getenv("SENTINELOS_DATA_DIR", "data"), "auth_failures.jsonl")


def _log_failure(source_ip: str, path: str, tenant_id: Optional[str]) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "path": path,
        "tenant_id": tenant_id,
    }
    append_line(_log_path(), json.dumps(entry))


def _send_alert(source_ip: str, count: int, window: int) -> None:
    try:
        from notifications.webhook import send_webhook_notification

        send_webhook_notification(
            {
                "text": f"[SentinelOS] {count} failed API key attempts from {source_ip} in the last {window}s.",
                "reason": "auth_failure_burst",
                "source_ip": source_ip,
                "count": count,
                "window_seconds": window,
            }
        )
    except Exception:
        pass


def record_auth_failure(source_ip: str, path: str, tenant_id: Optional[str] = None) -> None:
    """Call on every 401. Always logs the attempt to
    data/auth_failures.jsonl; additionally fires a webhook alert (at most
    once per window, per source) if this source's failures within
    SENTINELOS_AUTH_FAILURE_WINDOW_SECONDS reach
    SENTINELOS_AUTH_FAILURE_ALERT_THRESHOLD.
    """
    _log_failure(source_ip, path, tenant_id)

    threshold = _alert_threshold()
    if threshold <= 0:
        return

    window = _window_seconds()
    now = time.time()
    should_alert = False
    count = 0

    with _lock:
        timestamps = _failures.setdefault(source_ip, deque())
        timestamps.append(now)
        while timestamps and timestamps[0] < now - window:
            timestamps.popleft()
        count = len(timestamps)

        if count >= threshold and _alerted_until.get(source_ip, 0) <= now:
            _alerted_until[source_ip] = now + window
            should_alert = True

    if should_alert:
        _send_alert(source_ip, count, window)


def reset_for_tests() -> None:
    with _lock:
        _failures.clear()
        _alerted_until.clear()
