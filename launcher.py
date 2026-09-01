"""Unified `cavendex` command-line entry point.

This is a thin dispatcher, not a reimplementation: every existing
entry-point module (`cli.py`, `vault_backup.py`, the four ingestion
connectors, `main.py`'s demo) already has its own argparse parser that
reads `sys.argv[1:]`. This module just decides, from the first token,
which module to import and call, after rewriting `sys.argv` so that
module sees exactly the argv shape it already expects — so every
module's own `-h`/error handling/defaults keep working unchanged,
just reachable as `cavendex <thing>` instead of `python <thing>.py`.

Usage:
    cavendex serve [--host] [--port] [--reload] [--workers]
    cavendex backup [vault_backup.py's own flags]
    cavendex ingest syslog [syslog_listener.py's own flags]
    cavendex ingest watch [ingest_watch.py's own flags]
    cavendex ingest poll [poll_connector.py's own flags]
    cavendex ingest crowdstrike [crowdstrike_connector.py's own flags]
    cavendex demo
    cavendex new/show/approve/deny/hunt/verify-audit/create-user/list-playbooks/...
                                                        (falls through to cli.py)
"""

import importlib
import sys

_INGEST_MODULES = {
    "syslog": "syslog_listener",
    "watch": "ingest_watch",
    "poll": "poll_connector",
    "crowdstrike": "crowdstrike_connector",
}

_USAGE = """\
Cavendex — AI-driven SOC incident response platform.

Usage:
    cavendex serve [--host HOST] [--port PORT] [--reload] [--workers N]
        Run the FastAPI dashboard/API server (uvicorn).

    cavendex ingest {syslog,watch,poll,crowdstrike} [options]
        Run an ingestion connector. See `cavendex ingest <name> --help`.

    cavendex backup [options]
        Back up the Obsidian vault to a git remote. See `cavendex backup --help`.

    cavendex demo
        Run the bundled incident-pipeline demo end-to-end.

    cavendex <new|show|approve|deny|hunt|verify-audit|create-user|list-playbooks> ...
        Analyst CLI. See `cavendex --help` after any of these, or run
        with no arguments for the full subcommand list.
"""


def _delegate(module_name: str, argv_tail: list, func_name: str = "main") -> None:
    module = importlib.import_module(module_name)
    sys.argv = [module_name] + argv_tail
    getattr(module, func_name)()


def _cmd_serve(argv_tail: list) -> None:
    import argparse

    parser = argparse.ArgumentParser(prog="cavendex serve", description="Run the Cavendex API/dashboard server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true", help="Auto-reload on code changes (development only)")
    parser.add_argument("--workers", type=int, default=None)
    args = parser.parse_args(argv_tail)

    import uvicorn

    uvicorn.run("api:api", host=args.host, port=args.port, reload=args.reload, workers=args.workers)


def _cmd_ingest(argv_tail: list) -> None:
    if not argv_tail or argv_tail[0] in ("-h", "--help"):
        print("usage: cavendex ingest {syslog,watch,poll,crowdstrike} [options]")
        print("\nRun `cavendex ingest <name> --help` for that connector's own options.")
        return

    connector, rest = argv_tail[0], argv_tail[1:]
    module_name = _INGEST_MODULES.get(connector)
    if module_name is None:
        print(f"cavendex ingest: unknown connector {connector!r} — choose from: {', '.join(_INGEST_MODULES)}")
        sys.exit(2)

    _delegate(module_name, rest)


def main() -> None:
    argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help"):
        print(_USAGE)
        return

    command, rest = argv[0], argv[1:]

    if command == "serve":
        _cmd_serve(rest)
    elif command == "ingest":
        _cmd_ingest(rest)
    elif command == "backup":
        _delegate("vault_backup", rest)
    elif command == "demo":
        _delegate("main", rest, func_name="run_pipeline_demo")
    else:
        _delegate("cli", argv)


if __name__ == "__main__":
    main()
