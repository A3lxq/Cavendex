"""Loads playbook definitions from an operator-configured directory —
same "small file(s), not a system" philosophy as utils/asset_inventory.py
and utils/incident_index.py, extended to a directory since an operator
naturally wants one file per incident category (ransomware, phishing,
...) rather than one giant file.

CAVENDEX_PLAYBOOKS_DIR unset (the default) means this feature is
fully inert: load_playbooks() returns [] immediately, at zero cost, and
nothing downstream (workflows/incident_pipeline.py) ever calls into
playbooks/matcher.py or playbooks/expander.py. JSON only, not YAML —
consistent with this project's existing config-file convention
(asset_inventory.json, CAVENDEX_TENANT_API_KEYS) and avoids a new
dependency for a feature this size.

A file that fails to parse or fails schema validation is skipped with a
logged warning, never raised — one broken playbook file must never
break incident ingestion, the same graceful-degradation contract every
other optional integration in this project follows.
"""

import json
import logging
import os
import threading
from typing import List, Optional, Tuple

from pydantic import ValidationError

from playbooks.schema import Playbook

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_cached_dir: Optional[str] = None
_cached_fingerprint: Optional[Tuple[Tuple[str, float], ...]] = None
_cached_playbooks: List[Playbook] = []


def _fingerprint(directory: str) -> Optional[Tuple[Tuple[str, float], ...]]:
    try:
        names = sorted(f for f in os.listdir(directory) if f.endswith(".json"))
        return tuple((name, os.path.getmtime(os.path.join(directory, name))) for name in names)
    except OSError:
        return None


def _load_all(directory: str, names: Tuple[str, ...]) -> List[Playbook]:
    playbooks: List[Playbook] = []
    seen_ids = set()
    for name in names:
        path = os.path.join(directory, name)
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError) as exc:
            logger.warning("Skipping playbook file %s: could not parse JSON (%s)", path, exc)
            continue
        try:
            playbook = Playbook.model_validate(raw)
        except ValidationError as exc:
            logger.warning("Skipping playbook file %s: failed validation (%s)", path, exc)
            continue
        # `id` is relied on as a stable key elsewhere (matcher tie-break,
        # resolve_proposed_actions' playbooks_by_id lookup) -- a second
        # file silently reusing an id already loaded (from an earlier
        # file, alphabetically) would let one playbook's on_failure
        # policy or steps be silently attributed to another's id. Reject
        # the collider rather than letting "last file wins" happen
        # implicitly.
        if playbook.id in seen_ids:
            logger.warning(
                "Skipping playbook file %s: id %r is already used by another loaded playbook file",
                path, playbook.id,
            )
            continue
        seen_ids.add(playbook.id)
        playbooks.append(playbook)
    return playbooks


def load_playbooks() -> List[Playbook]:
    """All currently-valid playbooks in CAVENDEX_PLAYBOOKS_DIR, reloaded
    whenever any *.json file in that directory is added/removed/modified
    (one stat() call per file per lookup — cheap for a config directory
    that's expected to hold a handful of files, not user data). Unset,
    missing, or fully-invalid directory all mean "no playbooks" — an
    empty list, never an exception.
    """
    directory = os.getenv("CAVENDEX_PLAYBOOKS_DIR", "").strip()
    if not directory:
        return []

    global _cached_dir, _cached_fingerprint, _cached_playbooks
    fingerprint = _fingerprint(directory)
    if fingerprint is None:
        return []

    with _lock:
        if directory == _cached_dir and fingerprint == _cached_fingerprint:
            return _cached_playbooks
        names = tuple(name for name, _ in fingerprint)
        _cached_playbooks = _load_all(directory, names)
        _cached_dir = directory
        _cached_fingerprint = fingerprint
        return _cached_playbooks


def reset_for_tests() -> None:
    global _cached_dir, _cached_fingerprint, _cached_playbooks
    with _lock:
        _cached_dir = None
        _cached_fingerprint = None
        _cached_playbooks = []
