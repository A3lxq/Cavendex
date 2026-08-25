"""An optional, operator-maintained local alias -> canonical-identity map
for asset-identity correlation across a renamed host (see
ingestion/identity_correlation.py).

Real CMDB/inventory integration is intentionally out of scope the same
way a vendor-specific SIEM connector is (see "Adding an Ingestion
Source" in README) — there's no single CMDB API shape to build against.
Instead, an operator with a real inventory system exports one small JSON
file mapping any alias they track (an old hostname, a serial number,
whatever their inventory uses) to one canonical ID, and points
SENTINELOS_ASSET_INVENTORY_PATH at it:

    {"WEB-01": "asset-042", "WEB-01-RENAMED": "asset-042", "DC-01": "asset-001"}

"Small file, not a system" — the same philosophy as
utils/incident_index.py. Reloaded whenever its mtime changes (one cheap
stat() call per lookup) so an operator can update the export without
restarting the process, but otherwise cached in memory. No file
configured, a missing file, or malformed JSON all mean "no inventory" —
resolve_asset_identity returns None for everything, the same
graceful-degradation contract every other optional integration in this
project follows.
"""

import json
import os
import threading
from typing import Optional

_lock = threading.Lock()
_cached_path: Optional[str] = None
_cached_mtime: Optional[float] = None
_cached_map: dict = {}


def _load_if_needed() -> dict:
    path = os.getenv("SENTINELOS_ASSET_INVENTORY_PATH")
    if not path:
        return {}

    global _cached_path, _cached_mtime, _cached_map
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}

    with _lock:
        if path == _cached_path and mtime == _cached_mtime:
            return _cached_map
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError):
            return {}
        if not isinstance(raw, dict):
            return {}
        _cached_map = {str(k): str(v) for k, v in raw.items()}
        _cached_path = path
        _cached_mtime = mtime
        return _cached_map


def resolve_asset_identity(name: str) -> Optional[str]:
    """The canonical identity `name` maps to, per the configured
    inventory file, or None if unconfigured or not found. Exact-string
    lookup only, deliberately — a fuzzy or case-insensitive match here
    would reintroduce the exact string-similarity guesswork this feature
    exists to replace with an authoritative answer (see
    ingestion/identity_correlation.py's module docstring).
    """
    return _load_if_needed().get(name)


def reset_for_tests() -> None:
    global _cached_path, _cached_mtime, _cached_map
    with _lock:
        _cached_path = None
        _cached_mtime = None
        _cached_map = {}
