"""Size-based rotation for the project's append-only JSONL logs
(data/{tenant}/ingestion_log.jsonl, data/auth_failures.jsonl,
data/{tenant}/audit_chain_ledger.jsonl) — all three grow forever with no
rotation, a real gap on a long-lived, actively-used deployment that
nobody would notice until a disk filled up.

A plain rename-based rotation, not a logging framework — the same
"small file, not a system" philosophy as the rest of this project's
persistence layer (utils/incident_index.py). Never raises: a logging
failure must never block real incident/auth/audit processing, the same
contract every other side-effect in this project follows.
"""

import os


def _max_bytes() -> int:
    try:
        return int(os.getenv("SENTINELOS_LOG_MAX_BYTES", str(10 * 1024 * 1024)))
    except ValueError:
        return 10 * 1024 * 1024


def _backup_count() -> int:
    try:
        return max(0, int(os.getenv("SENTINELOS_LOG_BACKUP_COUNT", "3")))
    except ValueError:
        return 3


def _rotate_if_needed(path: str) -> None:
    max_bytes = _max_bytes()
    if max_bytes <= 0:
        return  # 0 disables rotation entirely — unbounded growth, opt-in

    try:
        if not os.path.exists(path) or os.path.getsize(path) < max_bytes:
            return
    except OSError:
        return

    backup_count = _backup_count()
    if backup_count <= 0:
        # No backups wanted — truncate rather than growing forever.
        try:
            os.remove(path)
        except OSError:
            pass
        return

    oldest = f"{path}.{backup_count}"
    if os.path.exists(oldest):
        try:
            os.remove(oldest)
        except OSError:
            pass
    for i in range(backup_count - 1, 0, -1):
        src, dst = f"{path}.{i}", f"{path}.{i + 1}"
        if os.path.exists(src):
            try:
                os.rename(src, dst)
            except OSError:
                pass
    try:
        os.rename(path, f"{path}.1")
    except OSError:
        pass


def append_line(path: str, line: str) -> None:
    """Append one line to `path`, rotating to `path.1`, `path.2`, ... first
    if it's at/over SENTINELOS_LOG_MAX_BYTES (default 10MB; 0 disables
    rotation), keeping at most SENTINELOS_LOG_BACKUP_COUNT (default 3)
    old copies before the oldest is dropped. Never raises.
    """
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        _rotate_if_needed(path)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line if line.endswith("\n") else line + "\n")
    except OSError:
        pass
