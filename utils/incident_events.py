"""In-process pub/sub for "something in this tenant's incident index just
changed" notifications, so the dashboard can push-update the incident
list instead of relying only on its polling refresh.

Plain queue.Queue, not asyncio.Queue: workflows/incident_pipeline.py's
_persist() (the single publish call site) runs from ordinary synchronous
code — FastAPI's sync route handlers, cli.py, main.py — matching the
rest of this fully-synchronous codebase rather than mixing an async-only
primitive in. The SSE route that reads from these queues (api.py) is the
one place that bridges to async, via loop.run_in_executor.

Deliberately in-process only: subscriptions don't survive a restart and
don't fan out across multiple worker processes. Consistent with every
other piece of process-local state in this project (see DEPLOYMENT.md's
single-worker guidance) — not a distributed pub/sub, just a same-process
shortcut so an open dashboard tab doesn't have to wait for its next poll.
"""

import queue
import threading
from typing import Dict, Set

_lock = threading.Lock()
_subscribers: Dict[str, Set["queue.Queue"]] = {}


def subscribe(tenant_id: str) -> "queue.Queue":
    q: "queue.Queue" = queue.Queue(maxsize=100)
    with _lock:
        _subscribers.setdefault(tenant_id, set()).add(q)
    return q


def unsubscribe(tenant_id: str, q: "queue.Queue") -> None:
    with _lock:
        subs = _subscribers.get(tenant_id)
        if subs is not None:
            subs.discard(q)
            if not subs:
                _subscribers.pop(tenant_id, None)


def publish(tenant_id: str, event: dict) -> None:
    with _lock:
        subs = list(_subscribers.get(tenant_id, ()))
    for q in subs:
        try:
            q.put_nowait(event)
        except queue.Full:
            # A slow/stalled subscriber shouldn't block or lose events for
            # everyone else — it just misses this one and catches up on
            # its next poll-driven refresh.
            pass


def reset_for_tests() -> None:
    with _lock:
        _subscribers.clear()
