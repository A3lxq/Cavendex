"""Tests vault_backup.py against a real filesystem and a real local git
repository (a `git init --bare` directory used as the "remote" — git
supports a plain local path as a remote natively) rather than mocking
subprocess — the same "prefer real I/O over a guessed shape" approach
used for test_polling_connector.py's real HTTP server and
syslog_listener.py's real sockets. Every git operation here is a real
`git` subprocess call; nothing about init/add/commit/push is faked.
"""

import subprocess

import pytest

from vault_backup import backup_once, ensure_repo


def _git(args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


@pytest.fixture
def bare_remote(tmp_path):
    remote_path = tmp_path / "remote.git"
    _git(["init", "--bare", str(remote_path)], tmp_path)
    return str(remote_path)


@pytest.fixture
def vault(tmp_path):
    path = tmp_path / "vault"
    path.mkdir()
    return path


def test_ensure_repo_initializes_git(vault):
    assert not (vault / ".git").exists()

    ensure_repo(str(vault), remote=None, branch="main")

    assert (vault / ".git").is_dir()


def test_ensure_repo_is_idempotent(vault):
    ensure_repo(str(vault), remote=None, branch="main")
    (vault / "note.md").write_text("hello")

    # Calling again must not wipe out the working tree or re-init.
    ensure_repo(str(vault), remote=None, branch="main")

    assert (vault / "note.md").read_text() == "hello"


def test_ensure_repo_sets_remote(vault, bare_remote):
    ensure_repo(str(vault), remote=bare_remote, branch="main")

    result = _git(["remote", "get-url", "origin"], vault)
    assert result.stdout.strip() == bare_remote


def test_ensure_repo_updates_remote_url_when_changed(vault, bare_remote, tmp_path):
    ensure_repo(str(vault), remote=bare_remote, branch="main")

    other_remote = str(tmp_path / "other_remote.git")
    _git(["init", "--bare", other_remote], tmp_path)
    ensure_repo(str(vault), remote=other_remote, branch="main")

    result = _git(["remote", "get-url", "origin"], vault)
    assert result.stdout.strip() == other_remote


def test_backup_once_commits_when_there_are_changes(vault):
    ensure_repo(str(vault), remote=None, branch="main")
    (vault / "inc-1.md").write_text("# Incident inc-1")

    committed = backup_once(str(vault), branch="main", push=False)

    assert committed is True
    log = _git(["log", "--oneline"], vault)
    assert log.stdout.strip() != ""


def test_backup_once_returns_false_when_nothing_changed(vault):
    ensure_repo(str(vault), remote=None, branch="main")
    (vault / "inc-1.md").write_text("# Incident inc-1")
    backup_once(str(vault), branch="main", push=False)

    committed_again = backup_once(str(vault), branch="main", push=False)

    assert committed_again is False


def test_backup_once_uses_a_dedicated_commit_identity(vault):
    ensure_repo(str(vault), remote=None, branch="main")
    (vault / "inc-1.md").write_text("# Incident inc-1")

    backup_once(str(vault), branch="main", push=False)

    author = _git(["log", "-1", "--format=%an <%ae>"], vault).stdout.strip()
    assert author == "Cavendex Vault Backup <vault-backup@cavendex.local>"


def test_backup_once_pushes_to_a_real_local_bare_repo(vault, bare_remote):
    ensure_repo(str(vault), remote=bare_remote, branch="main")
    (vault / "inc-1.md").write_text("# Incident inc-1")

    committed = backup_once(str(vault), branch="main", push=True)

    assert committed is True
    remote_log = subprocess.run(
        ["git", "--git-dir", bare_remote, "log", "--oneline", "main"],
        capture_output=True, text=True,
    )
    assert remote_log.returncode == 0
    assert remote_log.stdout.strip() != ""

    remote_content = subprocess.run(
        ["git", "--git-dir", bare_remote, "show", "main:inc-1.md"],
        capture_output=True, text=True,
    )
    assert remote_content.stdout.strip() == "# Incident inc-1"


def test_backup_once_second_run_pushes_only_the_new_commit(vault, bare_remote):
    ensure_repo(str(vault), remote=bare_remote, branch="main")
    (vault / "inc-1.md").write_text("# Incident inc-1")
    backup_once(str(vault), branch="main", push=True)

    (vault / "inc-2.md").write_text("# Incident inc-2")
    committed = backup_once(str(vault), branch="main", push=True)

    assert committed is True
    remote_log = subprocess.run(
        ["git", "--git-dir", bare_remote, "log", "--oneline", "main"],
        capture_output=True, text=True,
    )
    assert len(remote_log.stdout.strip().splitlines()) == 2


def test_backup_once_local_commit_survives_when_push_fails(vault, tmp_path):
    unreachable_remote = str(tmp_path / "does_not_exist.git")
    ensure_repo(str(vault), remote=unreachable_remote, branch="main")
    (vault / "inc-1.md").write_text("# Incident inc-1")

    committed = backup_once(str(vault), branch="main", push=True)

    assert committed is True
    log = _git(["log", "--oneline"], vault)
    assert log.stdout.strip() != ""
