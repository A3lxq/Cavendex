"""Tamper-evidence for the audit trail.

`audit_log` and the Obsidian vault report both live in storage an
operator — or an attacker with filesystem or git-remote access — could
edit in place, with no trace. This module doesn't stop that; it makes it
detectable. Every time an incident is persisted (`_persist` in
workflows/incident_pipeline.py), a hash of that incident's entire
`audit_log` at that moment is appended to a per-tenant, append-only
ledger file. Recomputing the hash from the live audit_log and comparing
it to the ledger's last recorded entry for that incident tells you
whether anything has changed since — an edited, reordered, or deleted
entry changes the hash; the ledger itself is never rewritten, only
appended to, so hiding a change now also requires rewriting ledger
history, a materially higher bar than editing the checkpoint or the
vault file alone.

This is NOT unbreakable tamper-proofing — nothing running on a single
host with an attacker who has full filesystem access ever is, without
external immutable storage this project doesn't have (a remote
write-once store, a blockchain anchor, etc.). It converts "silent,
undetectable tampering" into "tampering that also requires rewriting
ledger history," which is real protection worth having, not a claim of
perfection. Back the ledger up alongside CAVENDEX_DATA_DIR and it's at
least as durable as everything else this project already protects that
way.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import List, Optional

from utils.audit_export import send_audit_export
from utils.log_rotation import append_line
from utils.tenancy import sanitize_tenant_id

_GENESIS = "cavendex-audit-chain-v1"


def compute_chain_hash(entries: List[str]) -> str:
    """Deterministic hash of an ordered list of audit_log strings — folds
    each entry into a running SHA-256 so the result changes if any entry
    is edited, removed, reordered, or one is added or missing.
    """
    running = _GENESIS
    for entry in entries:
        running = hashlib.sha256(f"{running}\n{entry}".encode("utf-8")).hexdigest()
    return running


def _ledger_path(tenant_id: str) -> str:
    # Every other tenant-scoped module (graph.tenant_data_dir,
    # utils/user_accounts.py, ingestion/pipeline.py, ...) funnels
    # tenant_id through sanitize_tenant_id before it becomes a
    # filesystem path component; this was the one place that didn't,
    # letting an unsanitized tenant_id (e.g. "..") escape the intended
    # per-tenant data directory by one level. Sanitizing here, the sole
    # chokepoint every function in this module already goes through,
    # closes it regardless of what any current or future caller passes.
    return os.path.join(os.getenv("CAVENDEX_DATA_DIR", "data"), sanitize_tenant_id(tenant_id), "audit_chain_ledger.jsonl")


def _ledger_paths_oldest_first(tenant_id: str) -> List[str]:
    """The active ledger file plus any rotated backups (see
    utils/log_rotation.py), oldest first. Rotation renames the active
    file to `.1`, a prior `.1` to `.2`, and so on — so `.N` is always
    older than `.(N-1)`, which is older than the active file. Tamper-
    evidence has to see the true latest entry for an incident even if it
    happens to have fallen into a rotated-out backup, or a long-lived
    incident could be falsely reported as "never recorded."
    """
    base = _ledger_path(tenant_id)
    backups = []
    n = 1
    while os.path.exists(f"{base}.{n}"):
        backups.append(f"{base}.{n}")
        n += 1
    ordered = list(reversed(backups))
    if os.path.exists(base):
        ordered.append(base)
    return ordered


def record_chain(tenant_id: str, thread_id: str, audit_log: List[str]) -> None:
    """Append the current chain hash for this incident's audit_log to the
    ledger (rotating it first if it's grown past
    CAVENDEX_LOG_MAX_BYTES — see utils/log_rotation.py), then attempt to
    ship the same entry to CAVENDEX_AUDIT_EXPORT_WEBHOOK_URL if configured
    (see utils/audit_export.py) — an external anchor an attacker with only
    this host's filesystem access can't retroactively rewrite. Never
    raises — a ledger write or export failure must never block real
    incident processing, the same contract every other side-effect in
    this project follows (utils/incident_index.py, vault writes).
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "thread_id": thread_id,
        "audit_log_length": len(audit_log),
        "chain_hash": compute_chain_hash(audit_log),
    }
    append_line(_ledger_path(tenant_id), json.dumps(entry))
    try:
        send_audit_export(tenant_id, entry)
    except Exception:
        pass


def latest_recorded_entry(tenant_id: str, thread_id: str) -> Optional[dict]:
    """The most recent ledger entry for this incident across the active
    ledger and any rotated backups, or None if it was never recorded
    (e.g. the ledger predates this feature, or a past write failed)."""
    latest = None
    for path in _ledger_paths_oldest_first(tenant_id):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("thread_id") == thread_id:
                    latest = entry
    return latest


def verify_incident_audit_log(tenant_id: str, thread_id: str, audit_log: List[str]) -> dict:
    """Compares the incident's CURRENT audit_log against the ledger's most
    recently recorded hash for it. Returns a dict describing the result
    rather than a bare bool — "never recorded" and "tampered" are both
    real, different outcomes worth telling apart, not the same failure.
    """
    recorded = latest_recorded_entry(tenant_id, thread_id)
    if recorded is None:
        return {
            "status": "no_record",
            "detail": "No ledger entry exists for this incident — nothing to verify against.",
        }

    current_hash = compute_chain_hash(audit_log)
    if current_hash == recorded["chain_hash"] and len(audit_log) == recorded["audit_log_length"]:
        return {
            "status": "verified",
            "detail": f"Matches the ledger entry recorded at {recorded['timestamp']}.",
        }

    return {
        "status": "MISMATCH",
        "detail": (
            f"Current audit_log ({len(audit_log)} entries) does not match the ledger's last recorded "
            f"hash from {recorded['timestamp']} ({recorded['audit_log_length']} entries then). "
            "The audit trail may have been altered after that point."
        ),
    }
