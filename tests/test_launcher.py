"""Tests launcher.py's dispatch logic -- the thing that matters here is
that each mode reconstructs sys.argv exactly the way the delegated
module's own argparse expects, and calls the right function, without
actually launching a server/connector/pipeline. No real subprocess or
network activity should ever occur from this file.
"""

import sys

import pytest

import launcher


def test_no_args_prints_usage_without_crashing(capsys):
    sys.argv = ["cavendex"]
    launcher.main()
    out = capsys.readouterr().out
    assert "cavendex serve" in out
    assert "cavendex ingest" in out


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_flag_prints_usage(capsys, flag):
    sys.argv = ["cavendex", flag]
    launcher.main()
    out = capsys.readouterr().out
    assert "Cavendex" in out


def test_ingest_no_args_lists_connectors(capsys):
    sys.argv = ["cavendex", "ingest"]
    launcher.main()
    out = capsys.readouterr().out
    for name in ("syslog", "watch", "poll", "crowdstrike"):
        assert name in out


def test_ingest_unknown_connector_exits_nonzero(capsys):
    sys.argv = ["cavendex", "ingest", "bogus"]
    with pytest.raises(SystemExit) as exc_info:
        launcher.main()
    assert exc_info.value.code == 2
    assert "bogus" in capsys.readouterr().out


def test_serve_dispatches_to_uvicorn_run(monkeypatch):
    calls = []
    fake_uvicorn = type("FakeUvicorn", (), {"run": staticmethod(lambda *a, **kw: calls.append((a, kw)))})
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)

    sys.argv = ["cavendex", "serve", "--host", "0.0.0.0", "--port", "9000"]
    launcher.main()

    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args == ("api:api",)
    assert kwargs["host"] == "0.0.0.0"
    assert kwargs["port"] == 9000
    assert kwargs["reload"] is False


def test_serve_defaults(monkeypatch):
    calls = []
    fake_uvicorn = type("FakeUvicorn", (), {"run": staticmethod(lambda *a, **kw: calls.append((a, kw)))})
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)

    sys.argv = ["cavendex", "serve"]
    launcher.main()

    _, kwargs = calls[0]
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 8000
    assert kwargs["workers"] is None


@pytest.mark.parametrize(
    "connector,module_name",
    [
        ("syslog", "syslog_listener"),
        ("watch", "ingest_watch"),
        ("poll", "poll_connector"),
        ("crowdstrike", "crowdstrike_connector"),
    ],
)
def test_ingest_delegates_to_correct_connector(monkeypatch, connector, module_name):
    calls = []
    fake_module = type("FakeModule", (), {"main": staticmethod(lambda: calls.append(list(sys.argv)))})
    monkeypatch.setattr(launcher.importlib, "import_module", lambda name: fake_module if name == module_name else pytest.fail(name))

    sys.argv = ["cavendex", "ingest", connector, "--tenant", "acme"]
    launcher.main()

    assert calls == [[module_name, "--tenant", "acme"]]


def test_backup_delegates_to_vault_backup(monkeypatch):
    calls = []
    fake_module = type("FakeModule", (), {"main": staticmethod(lambda: calls.append(list(sys.argv)))})
    monkeypatch.setattr(launcher.importlib, "import_module", lambda name: fake_module if name == "vault_backup" else pytest.fail(name))

    sys.argv = ["cavendex", "backup", "--once", "--no-push"]
    launcher.main()

    assert calls == [["vault_backup", "--once", "--no-push"]]


def test_demo_delegates_to_run_pipeline_demo(monkeypatch):
    calls = []
    fake_module = type("FakeModule", (), {"run_pipeline_demo": staticmethod(lambda: calls.append(list(sys.argv)))})
    monkeypatch.setattr(launcher.importlib, "import_module", lambda name: fake_module if name == "main" else pytest.fail(name))

    sys.argv = ["cavendex", "demo"]
    launcher.main()

    assert calls == [["main"]]


def test_arbitrary_subcommand_falls_through_to_cli(monkeypatch):
    calls = []
    fake_cli = type("FakeCli", (), {"main": staticmethod(lambda: calls.append(list(sys.argv)))})
    monkeypatch.setattr(launcher.importlib, "import_module", lambda name: fake_cli if name == "cli" else pytest.fail(name))

    sys.argv = ["cavendex", "new", "Suspicious login", "--severity", "high"]
    launcher.main()

    assert calls == [["cli", "new", "Suspicious login", "--severity", "high"]]


def test_global_tenant_flag_falls_through_to_cli(monkeypatch):
    calls = []
    fake_cli = type("FakeCli", (), {"main": staticmethod(lambda: calls.append(list(sys.argv)))})
    monkeypatch.setattr(launcher.importlib, "import_module", lambda name: fake_cli if name == "cli" else pytest.fail(name))

    sys.argv = ["cavendex", "--tenant", "acme", "show", "thread-123"]
    launcher.main()

    assert calls == [["cli", "--tenant", "acme", "show", "thread-123"]]
