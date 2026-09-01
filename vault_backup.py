"""Back up the entire Obsidian vault (every tenant's incident/hunt
reports) to a git remote — the durable, off-box copy of Cavendex's
structured audit trail. Runs on an interval and does its own git
add/commit/push, deliberately as a separate process rather than something
the incident pipeline does inline: a git failure (network blip, auth
issue, merge conflict with something you edited by hand in Obsidian)
must never be able to block or slow down real incident processing, the
same reasoning behind every other "keep this out of the hot path" choice
in this project (utils/incident_index.py's failures are swallowed for
the same reason).

Usage:
    # One-time setup, then run continuously (commits+pushes every 5 min
    # by default):
    python vault_backup.py --remote git@github.com:you/your-vault.git

    # Cron-style, single batch and exit:
    python vault_backup.py --remote git@github.com:you/your-vault.git --once

    # Commit locally without pushing anywhere (e.g. to try this out
    # before picking a remote):
    python vault_backup.py --no-push

Authentication is entirely your own git setup's responsibility — an SSH
key already loaded for the `git@...` form, an HTTPS token embedded in the
remote URL, or a credential helper. This script does not manage
credentials, the same way ingestion/polling.py's PollerConfig never
stores a real secret either.

THE DESTINATION REPOSITORY WILL CONTAIN REAL INCIDENT DATA — descriptions,
IOCs, and affected-asset names from your actual environment. It must be a
private repository. This script does not and cannot enforce that; it's
on you.
"""

import argparse
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import Optional

from dotenv import find_dotenv, load_dotenv

# find_dotenv(usecwd=True): search from the caller's working directory,
# not this file's location — matters once this module is installed
# into site-packages and run as `cavendex backup` from wherever a
# user's .env actually lives.
load_dotenv(find_dotenv(usecwd=True), override=True)

_COMMIT_AUTHOR_NAME = "Cavendex Vault Backup"
_COMMIT_AUTHOR_EMAIL = "vault-backup@cavendex.local"


def _run_git(args, cwd) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def ensure_repo(vault_path: str, remote: Optional[str], branch: str) -> None:
    """Make `vault_path` a git repo on `branch`, with `origin` pointing at
    `remote` if given — idempotent, safe to call on every startup.
    """
    os.makedirs(vault_path, exist_ok=True)

    if not os.path.isdir(os.path.join(vault_path, ".git")):
        result = _run_git(["init", "-b", branch], vault_path)
        if result.returncode != 0:
            # Older git versions don't support `init -b` — fall back to
            # init-then-checkout, which works everywhere.
            _run_git(["init"], vault_path)
            _run_git(["checkout", "-b", branch], vault_path)
        print(f"Initialized a new git repository in {vault_path} (branch: {branch})")

    if remote:
        current = _run_git(["remote", "get-url", "origin"], vault_path)
        if current.returncode != 0:
            _run_git(["remote", "add", "origin", remote], vault_path)
        elif current.stdout.strip() != remote:
            _run_git(["remote", "set-url", "origin", remote], vault_path)


def backup_once(vault_path: str, branch: str, push: bool = True) -> bool:
    """Stage, commit, and (unless `push` is False) push any changes.
    Returns True if there was something to commit, False if the vault
    was already clean — never raises; git failures are printed and
    treated as "nothing more to do this round," not a crash.
    """
    _run_git(["add", "-A"], vault_path)
    status = _run_git(["status", "--porcelain"], vault_path)
    if not status.stdout.strip():
        return False

    message = f"Cavendex vault backup: {datetime.now(timezone.utc).isoformat()}"
    commit = _run_git(
        [
            "-c", f"user.name={_COMMIT_AUTHOR_NAME}",
            "-c", f"user.email={_COMMIT_AUTHOR_EMAIL}",
            "commit", "-m", message,
        ],
        vault_path,
    )
    if commit.returncode != 0:
        print(f"  git commit failed: {commit.stderr.strip()}")
        return False

    if push:
        push_result = _run_git(["push", "-u", "origin", branch], vault_path)
        if push_result.returncode != 0:
            print(f"  git push failed (commit still saved locally): {push_result.stderr.strip()}")

    return True


def main():
    parser = argparse.ArgumentParser(description="Back up the Cavendex Obsidian vault to a git remote")
    parser.add_argument("--vault-path", default=os.getenv("OBSIDIAN_VAULT_PATH", "obsidian_vault"))
    parser.add_argument("--remote", default=None, help="git remote URL, e.g. git@github.com:you/vault.git")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--interval-seconds", type=float, default=300)
    parser.add_argument("--once", action="store_true", help="Back up once and exit — for cron")
    parser.add_argument("--no-push", action="store_true", help="Commit locally only, never push")
    args = parser.parse_args()

    if shutil.which("git") is None:
        print("git is not installed or not on PATH — cannot back up the vault.")
        return

    if args.remote and not args.no_push:
        print(
            "IMPORTANT: the destination repository will contain real incident "
            "descriptions, IOCs, and affected-asset names from your environment. "
            "It must be a PRIVATE repository."
        )

    ensure_repo(args.vault_path, args.remote, args.branch)
    print(f"Watching {args.vault_path} (branch: {args.branch}, push: {not args.no_push})...")

    while True:
        try:
            committed = backup_once(args.vault_path, args.branch, push=not args.no_push)
            print("Backed up new changes." if committed else "No changes to back up.")
        except Exception as exc:
            print(f"Backup iteration failed: {exc}")

        if args.once:
            break
        time.sleep(args.interval_seconds)


if __name__ == "__main__":
    main()
