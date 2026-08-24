"""Tests cli.py's colorized-output helpers -- the one property that
actually matters here is that color codes never leak into non-tty
output (a log file, a script piping our stdout), since garbled escape
codes in redirected output is a real regression class for CLI tools."""

import cli


def test_color_disabled_returns_plain_text(monkeypatch):
    monkeypatch.setattr(cli, "_COLOR_ENABLED", False)
    assert cli._c("hello", "red", "bold") == "hello"


def test_color_enabled_wraps_in_ansi_codes(monkeypatch):
    monkeypatch.setattr(cli, "_COLOR_ENABLED", True)
    result = cli._c("hello", "red")
    assert result == "\033[31mhello\033[0m"
    assert result != "hello"


def test_no_styles_returns_plain_text_even_when_enabled(monkeypatch):
    monkeypatch.setattr(cli, "_COLOR_ENABLED", True)
    assert cli._c("hello") == "hello"


def test_severity_text_uppercases_and_colors(monkeypatch):
    monkeypatch.setattr(cli, "_COLOR_ENABLED", True)
    result = cli._severity_text("critical")
    assert "CRITICAL" in result
    assert result.startswith("\033[")


def test_severity_text_plain_when_color_disabled(monkeypatch):
    monkeypatch.setattr(cli, "_COLOR_ENABLED", False)
    assert cli._severity_text("high") == "HIGH"


def test_unknown_severity_does_not_crash(monkeypatch):
    monkeypatch.setattr(cli, "_COLOR_ENABLED", True)
    # Should still uppercase and return *something* sane, not raise.
    assert cli._severity_text("weird-value") == "WEIRD-VALUE"


def test_status_text_preserves_case(monkeypatch):
    monkeypatch.setattr(cli, "_COLOR_ENABLED", False)
    assert cli._status_text("pending_approval") == "pending_approval"


def _color_enabled_under_a_real_pty(env_extra):
    """cli._COLOR_ENABLED is fixed at import time from sys.stdout.isatty()
    -- pytest's own output capture makes that always False, so the only
    honest way to test the tty-detection path (and that NO_COLOR
    overrides it) is a real pseudo-terminal, not a monkeypatched guess.
    """
    import os
    import pty
    import subprocess

    master, slave = pty.openpty()
    env = dict(os.environ)
    env.update(env_extra)
    proc = subprocess.Popen(
        ["python3", "-c", "import cli; print(cli._COLOR_ENABLED)"],
        stdout=slave, stderr=subprocess.STDOUT, env=env, close_fds=True,
    )
    os.close(slave)
    proc.wait(timeout=10)
    output = b""
    try:
        while True:
            chunk = os.read(master, 1024)
            if not chunk:
                break
            output += chunk
    except OSError:
        pass
    os.close(master)
    return output.decode().strip()


def test_color_enabled_under_a_real_terminal_with_no_color_unset():
    assert _color_enabled_under_a_real_pty({}) == "True"


def test_no_color_env_var_disables_color_even_on_a_real_terminal():
    assert _color_enabled_under_a_real_pty({"NO_COLOR": "1"}) == "False"
