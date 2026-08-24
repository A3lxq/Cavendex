"""SentinelOS command-line interface.

Usage:
    python cli.py new "Multiple failed logins from 1.2.3.4" --severity high --assets DC-01,WEB-01
    python cli.py show <thread_id>
    python cli.py approve <thread_id> --by "j.smith"
    python cli.py deny <thread_id> --by "j.smith"
    python cli.py hunt "any signs of a broader credential-stuffing campaign?"
    python cli.py verify-audit <thread_id>

    # --by records who approved/denied — set SENTINELOS_ANALYST_NAME once
    # instead of typing --by every time:
    export SENTINELOS_ANALYST_NAME="j.smith"
    python cli.py approve <thread_id>

    # --tenant scopes the incident DB, vault, and memory to a specific org
    # (default tenant is "default"). It's a global flag, so it goes before
    # the subcommand:
    python cli.py --tenant acme-corp new "Suspicious login from 1.2.3.4"
    python cli.py --tenant acme-corp show <thread_id>

    # --stream prints each agent's finding as it completes, live, instead
    # of waiting for the whole pipeline to finish:
    python cli.py new "Suspicious login from 1.2.3.4" --stream
"""

import argparse
import os
import sys

from dotenv import load_dotenv

load_dotenv(override=True)

_PROVIDER_KEYS = ["GROQ_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "OLLAMA_MODEL"]

# Colorized output, but only when it's actually safe: a real terminal, and
# the caller hasn't opted out via the standard NO_COLOR convention
# (https://no-color.org/). Piped/redirected output (a log file, a script
# parsing our stdout) must never get raw escape codes mixed into it.
_COLOR_ENABLED = sys.stdout.isatty() and not os.getenv("NO_COLOR")

_ANSI = {
    "reset": "\033[0m", "bold": "\033[1m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "cyan": "\033[36m", "gray": "\033[90m", "bright_red": "\033[91m",
}

_SEVERITY_STYLE = {"low": ("gray",), "medium": ("yellow",), "high": ("red",), "critical": ("bright_red", "bold")}
_STATUS_STYLE = {
    "pending_approval": ("yellow",), "contained": ("green",), "closed": ("green",),
    "investigating": ("cyan",), "open": ("cyan",),
}


def _c(text, *styles):
    if not _COLOR_ENABLED or not styles:
        return text
    return "".join(_ANSI[s] for s in styles) + text + _ANSI["reset"]


def _severity_text(severity):
    return _c(severity.upper(), *_SEVERITY_STYLE.get(severity, ()))


def _status_text(status):
    return _c(status, *_STATUS_STYLE.get(status, ()))


def _error_text(message):
    return _c(message, "bright_red", "bold")


def _section(title):
    return _c(title, "cyan", "bold")


def _require_provider():
    if not any(os.getenv(k) for k in _PROVIDER_KEYS):
        print(
            "No LLM provider configured. Copy .env.example to .env and set one of: "
            + ", ".join(_PROVIDER_KEYS)
        )
        sys.exit(1)


def _msg_name_content(msg):
    if isinstance(msg, dict):
        return msg.get("name") or msg.get("role", "assistant"), msg.get("content", "")
    return getattr(msg, "name", None) or "Agent", getattr(msg, "content", "")


def _print_state(state):
    if not state:
        print("No such incident.")
        return

    incident = state.get("incident")
    if incident:
        print(f"Incident {incident.id}")
        print(f"  Severity: {_severity_text(incident.severity)}")
        print(f"  Status:   {_status_text(incident.status)}")
        print(f"  Source:   {incident.source}")
        print(f"  Assets:   {', '.join(incident.affected_assets) or 'none'}")
        print(f"  IOCs:     {', '.join(incident.iocs) or 'none'}")

    print(f"\n{_section('Agent Findings:')}")
    for msg in state.get("messages", []) or []:
        name, content = _msg_name_content(msg)
        print(f"\n[{name}]\n{content}")

    proposed = state.get("proposed_actions", []) or []
    if proposed:
        print(f"\n{_section('Proposed Actions:')}")
        for a in proposed:
            if a.approved is True:
                status = _c("approved", "green", "bold")
            elif a.approved is False:
                status = _c("denied", "red", "bold")
            else:
                status = _c("PENDING APPROVAL", "yellow", "bold")
            print(f"  - {a.action} → {a.target} ({a.rationale}) [{status}]")

    threat_intel = state.get("threat_intel") or []
    if threat_intel:
        print(f"\n{_section('Threat Intelligence:')}")
        for r in threat_intel:
            print(f"  - {r['indicator']} ({r['indicator_type']}) — {r['source']}: {r['verdict']} — {r['detail']}")

    attack_technique = state.get("attack_technique")
    if attack_technique:
        tag = _c("verified", "green") if attack_technique.get("verified") else _c("UNVERIFIED", "bright_red", "bold")
        name = attack_technique.get("name") or "not found in local dataset"
        print(f"\n{_section('ATT&CK Technique:')} {attack_technique['id']} — {name} [{tag}]")

    usage = state.get("token_usage") or {}
    if usage:
        print(f"\n{_section('Token Usage:')} {usage.get('total_tokens', 0)} total "
              f"({usage.get('input_tokens', 0)} in / {usage.get('output_tokens', 0)} out)")
        for agent_name, agent_usage in (usage.get("by_agent") or {}).items():
            print(f"  - {agent_name}: {agent_usage.get('total_tokens', 0)} tokens")

    print(f"\n{_section('Audit Log:')}")
    for entry in state.get("audit_log", []) or []:
        print(f"  • {entry}")


def cmd_new(args):
    assets = [a for a in args.assets.split(",") if a] if args.assets else []
    iocs = [i for i in args.iocs.split(",") if i] if args.iocs else []
    tenant_flag = f"--tenant {args.tenant} " if args.tenant != "default" else ""

    if args.stream:
        from workflows.incident_pipeline import run_new_incident_stream

        thread_id = None
        final_event = None
        for event in run_new_incident_stream(
            description=args.description,
            severity=args.severity,
            affected_assets=assets,
            iocs=iocs,
            source=args.source,
            tenant_id=args.tenant,
        ):
            if event["event"] == "started":
                thread_id = event["thread_id"]
                print(f"Incident created: {thread_id}\n")
            elif event["event"] == "agent_step":
                print(f"[{event['agent']}]\n{event['content']}\n")
            elif event["event"] == "complete":
                final_event = event

        if final_event and final_event.get("proposed_actions"):
            print(
                f"Run `python cli.py {tenant_flag}approve {thread_id}` or "
                f"`python cli.py {tenant_flag}deny {thread_id}` to resolve."
            )
        if final_event:
            usage = final_event.get("token_usage") or {}
            if usage:
                print(f"\nToken Usage: {usage.get('total_tokens', 0)} total")
        print("\n📓 Obsidian vault report written.")
        return

    from workflows.incident_pipeline import run_new_incident

    state = run_new_incident(
        description=args.description,
        severity=args.severity,
        affected_assets=assets,
        iocs=iocs,
        source=args.source,
        tenant_id=args.tenant,
    )
    incident = state.get("incident")
    print(f"Incident created: {incident.id}\n")
    _print_state(state)
    proposed = state.get("proposed_actions", []) or []
    if proposed:
        print(
            f"\nRun `python cli.py {tenant_flag}approve {incident.id}` or "
            f"`python cli.py {tenant_flag}deny {incident.id}` to resolve."
        )
    print("\n📓 Obsidian vault report written.")


def cmd_show(args):
    from workflows.incident_pipeline import get_incident_state

    _print_state(get_incident_state(args.thread_id, tenant_id=args.tenant))


def _resolve_approved_by(args) -> str:
    approved_by = args.by or os.getenv("SENTINELOS_ANALYST_NAME")
    if not approved_by:
        print(
            "Warning: no --by given and SENTINELOS_ANALYST_NAME is unset — this decision "
            "will be recorded as 'unspecified' in the audit trail.\n"
        )
    return approved_by


def cmd_approve(args):
    from workflows.incident_pipeline import resolve_proposed_actions

    approved_by = _resolve_approved_by(args)
    try:
        state = resolve_proposed_actions(args.thread_id, approve=True, tenant_id=args.tenant, approved_by=approved_by)
    except ValueError as exc:
        print(_error_text(f"Error: {exc}"))
        sys.exit(1)
    print("Actions approved.\n")
    _print_state(state)


def cmd_deny(args):
    from workflows.incident_pipeline import resolve_proposed_actions

    approved_by = _resolve_approved_by(args)
    try:
        state = resolve_proposed_actions(args.thread_id, approve=False, tenant_id=args.tenant, approved_by=approved_by)
    except ValueError as exc:
        print(_error_text(f"Error: {exc}"))
        sys.exit(1)
    print("Actions denied.\n")
    _print_state(state)


def cmd_verify_audit(args):
    from utils.audit_chain import verify_incident_audit_log
    from workflows.incident_pipeline import get_incident_state

    state = get_incident_state(args.thread_id, tenant_id=args.tenant)
    if state is None:
        print(f"No incident found for thread_id={args.thread_id}")
        sys.exit(1)

    result = verify_incident_audit_log(args.tenant, args.thread_id, state.get("audit_log", []))
    if result["status"] == "verified":
        status_text = _c("verified", "green", "bold")
    elif result["status"] == "MISMATCH":
        status_text = _c("MISMATCH", "bright_red", "bold")
    else:
        status_text = _c(result["status"], "yellow")
    print(f"{status_text}: {result['detail']}")
    if result["status"] == "MISMATCH":
        sys.exit(1)


def cmd_hunt(args):
    from workflows.incident_pipeline import run_threat_hunt

    state = run_threat_hunt(args.query, tenant_id=args.tenant)
    _print_state(state)
    print("\n📓 Obsidian vault hunt report written.")


_REQUIRES_PROVIDER = {"new", "hunt"}


def main():
    parser = argparse.ArgumentParser(prog="sentinelos", description="SentinelOS CLI")
    parser.add_argument(
        "--tenant",
        default="default",
        help="Tenant ID — scopes the incident DB, vault, and memory (default: 'default')",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_new = sub.add_parser("new", help="Submit a new incident and run it through the agent pipeline")
    p_new.add_argument("description")
    p_new.add_argument("--severity", default="medium", choices=["low", "medium", "high", "critical"])
    p_new.add_argument("--assets", default="", help="Comma-separated affected assets")
    p_new.add_argument("--iocs", default="", help="Comma-separated IOCs")
    p_new.add_argument("--source", default=None)
    p_new.add_argument(
        "--stream",
        action="store_true",
        help="Print each agent's finding as it completes instead of waiting for the full pipeline",
    )
    p_new.set_defaults(func=cmd_new)

    p_show = sub.add_parser("show", help="Show an incident's current state")
    p_show.add_argument("thread_id")
    p_show.set_defaults(func=cmd_show)

    p_approve = sub.add_parser("approve", help="Approve a Responder Agent's proposed actions")
    p_approve.add_argument("thread_id")
    p_approve.add_argument(
        "--by", default=None, help="Who's approving — recorded in the audit trail (default: SENTINELOS_ANALYST_NAME)"
    )
    p_approve.set_defaults(func=cmd_approve)

    p_deny = sub.add_parser("deny", help="Deny a Responder Agent's proposed actions")
    p_deny.add_argument("thread_id")
    p_deny.add_argument(
        "--by", default=None, help="Who's denying — recorded in the audit trail (default: SENTINELOS_ANALYST_NAME)"
    )
    p_deny.set_defaults(func=cmd_deny)

    p_hunt = sub.add_parser("hunt", help="Run a standalone, analyst-initiated threat hunt")
    p_hunt.add_argument("query")
    p_hunt.set_defaults(func=cmd_hunt)

    p_verify = sub.add_parser(
        "verify-audit",
        help="Check an incident's audit_log against its tamper-evidence ledger entry",
    )
    p_verify.add_argument("thread_id")
    p_verify.set_defaults(func=cmd_verify_audit)

    args = parser.parse_args()
    # approve/deny/show are pure state transitions/reads — no LLM call —
    # so only gate the commands that actually invoke an agent.
    if args.command in _REQUIRES_PROVIDER:
        _require_provider()
    args.func(args)


if __name__ == "__main__":
    main()
