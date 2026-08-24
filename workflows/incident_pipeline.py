"""Shared incident-response orchestration used by main.py, cli.py, and api.py.

Wraps the compiled LangGraph app with convenience functions: create and run
a new incident through the full agent pipeline, inspect a checkpointed
incident's state, approve/deny a Responder Agent's proposed actions (the
human-in-the-loop gate — nothing the Responder proposes ever executes
without going through resolve_proposed_actions), and run a standalone,
analyst-initiated threat hunt. Every function is tenant-scoped: each tenant
gets its own SQLite checkpoint DB (graph.get_app), its own ChromaDB
collection (memory.vector_store), and its own Obsidian vault subfolder
(utils.obsidian) — full isolation, not a shared store with a tenant column.
"""

import os
import uuid
from typing import List, Optional

from graph import get_app
from notifications.pipeline import notify_if_needed
from state import SEVERITY_RANK, Incident, SentinelState
from utils.audit_chain import record_chain
from utils.incident_index import upsert_incident_summary
from utils.llm import accumulate_usage
from utils.obsidian import write_incident_report
from utils.tenancy import DEFAULT_TENANT, sanitize_tenant_id


def _config(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id}}


def _persist(state: SentinelState, report_type: str = "incident") -> None:
    """Write the vault report, update the dashboard's list index, and
    record this audit_log's current tamper-evidence hash into the
    append-only chain ledger (see utils/audit_chain.py) — everything a
    finished pipeline run/decision needs to durably land. Index and
    ledger failures are swallowed (neither is part of the actual incident
    record itself) so a bug in either can never break the pipeline.
    """
    write_incident_report(state, report_type=report_type)
    try:
        upsert_incident_summary(state.get("tenant_id") or DEFAULT_TENANT, state, report_type=report_type)
    except Exception:
        pass

    incident = state.get("incident")
    if incident is not None:
        record_chain(state.get("tenant_id") or DEFAULT_TENANT, incident.id, state.get("audit_log", []))


def _new_incident_state(
    description: str,
    severity: str,
    affected_assets: Optional[List[str]],
    iocs: Optional[List[str]],
    source: Optional[str],
    thread_id: str,
    tenant_id: str,
) -> SentinelState:
    return {
        "messages": [],
        "incident": Incident(
            id=thread_id,
            description=description,
            severity=severity,
            affected_assets=affected_assets or [],
            iocs=iocs or [],
            source=source,
        ),
        "long_term_summary": "",
        "audit_log": [],
        "next_agent": None,
        "proposed_actions": [],
        "token_usage": {},
        "tenant_id": tenant_id,
        "threat_intel": [],
        "attack_technique": None,
    }


def run_new_incident(
    description: str,
    severity: str = "medium",
    affected_assets: Optional[List[str]] = None,
    iocs: Optional[List[str]] = None,
    source: Optional[str] = None,
    thread_id: Optional[str] = None,
    tenant_id: str = DEFAULT_TENANT,
    seed_usage: Optional[dict] = None,
) -> SentinelState:
    """Create a new incident and run it through the full agent pipeline.

    `seed_usage`, if given, is folded into the new incident's token_usage
    under "Correlation Judge" before Triage even runs — for the case where
    ingestion/semantic_correlation.py already spent a real LLM call
    checking whether this alert belonged to an existing incident, decided
    it didn't, and is now promoting it as a new one. That check's cost
    still happened on this incident's behalf and shouldn't disappear from
    the ledger just because it came back negative.
    """
    tenant_id = sanitize_tenant_id(tenant_id)
    thread_id = thread_id or str(uuid.uuid4())
    initial_state = _new_incident_state(
        description, severity, affected_assets, iocs, source, thread_id, tenant_id
    )
    if seed_usage:
        accumulate_usage(initial_state, "Correlation Judge", seed_usage)

    app = get_app(tenant_id)
    final_state = app.invoke(initial_state, config=_config(thread_id))
    _persist(final_state)
    notify_if_needed(final_state, reason="new_incident")
    return final_state


def _message_agent_and_content(message):
    if isinstance(message, dict):
        return message.get("name") or message.get("role", "Agent"), message.get("content", "")
    return getattr(message, "name", None) or "Agent", getattr(message, "content", "")


def run_new_incident_stream(
    description: str,
    severity: str = "medium",
    affected_assets: Optional[List[str]] = None,
    iocs: Optional[List[str]] = None,
    source: Optional[str] = None,
    thread_id: Optional[str] = None,
    tenant_id: str = DEFAULT_TENANT,
    seed_usage: Optional[dict] = None,
):
    """Like run_new_incident, but yields one progress event per completed
    agent step via LangGraph's .stream() instead of blocking until the
    whole pipeline finishes — this is the "live view" counterpart: a
    caller (the SSE API endpoint, or `cli.py new --stream`) can show each
    agent's finding as it happens rather than only the final result.

    See run_new_incident for what `seed_usage` is for.

    The caller must fully consume the generator — the incident's Obsidian
    vault report is only written after the last event, once the pipeline
    has actually finished.
    """
    tenant_id = sanitize_tenant_id(tenant_id)
    thread_id = thread_id or str(uuid.uuid4())
    initial_state = _new_incident_state(
        description, severity, affected_assets, iocs, source, thread_id, tenant_id
    )
    if seed_usage:
        accumulate_usage(initial_state, "Correlation Judge", seed_usage)

    app = get_app(tenant_id)
    config = _config(thread_id)

    yield {"event": "started", "thread_id": thread_id, "tenant_id": tenant_id}

    for update in app.stream(initial_state, config=config, stream_mode="updates"):
        for node_name, partial in update.items():
            messages = partial.get("messages") or []
            agent_name, content = (
                _message_agent_and_content(messages[0]) if messages else (node_name, "")
            )
            yield {
                "event": "agent_step",
                "node": node_name,
                "agent": agent_name,
                "content": content,
                "next_agent": partial.get("next_agent"),
            }

    final_state = app.get_state(config).values
    _persist(final_state)
    notify_if_needed(final_state, reason="new_incident")

    incident = final_state.get("incident")
    yield {
        "event": "complete",
        "thread_id": thread_id,
        "status": incident.status if incident else None,
        "proposed_actions": [
            {"action": a.action, "target": a.target, "rationale": a.rationale}
            for a in (final_state.get("proposed_actions") or [])
        ],
        "token_usage": final_state.get("token_usage") or {},
    }


def merge_correlated_alert(
    thread_id: str,
    description: str,
    severity: str,
    affected_assets: Optional[List[str]],
    iocs: Optional[List[str]],
    source: Optional[str],
    tenant_id: str = DEFAULT_TENANT,
    match_reason: str = "shared indicator",
    usage: Optional[dict] = None,
) -> SentinelState:
    """Fold a newly-ingested alert into an already-open incident instead of
    starting a new pipeline run for it — the other half of "correlation"
    alongside ingestion/correlation.py, which decided `thread_id` is a
    match and why (`match_reason`). Deliberately does not re-invoke the
    agent graph: the point of grouping related alerts is to avoid an extra
    LLM run per alert, not add one. The new evidence (IOCs, affected
    assets, an audit entry naming the match reason, a visible message)
    still lands on the incident so an analyst sees every alert that fed
    into it and *why* it was judged related — important since a fuzzy or
    semantic match is a real, if smaller, false-positive risk compared to
    an exact one. Severity only ever escalates, never drops, since a
    merged alert is additional evidence, not a correction.

    `usage`, if given, is the real token cost of the LLM call that
    produced this match — only ever populated by
    ingestion/semantic_correlation.py's judgment call (the free exact/fuzzy
    tiers never spend a token) — and is folded into this incident's
    token_usage under "Correlation Judge" rather than going unaccounted.
    """
    tenant_id = sanitize_tenant_id(tenant_id)
    app = get_app(tenant_id)
    config = _config(thread_id)
    state = app.get_state(config).values
    if not state:
        raise ValueError(f"No incident found for thread_id={thread_id}")

    incident = state.get("incident")
    if incident is None:
        raise ValueError(f"Incident {thread_id} has no incident record")

    merged_iocs = list(dict.fromkeys(list(incident.iocs) + list(iocs or [])))[:50]
    merged_assets = list(dict.fromkeys(list(incident.affected_assets) + list(affected_assets or [])))[:50]
    merged_severity = incident.severity
    if SEVERITY_RANK.get(severity, 1) > SEVERITY_RANK.get(incident.severity, 1):
        merged_severity = severity

    incident = incident.model_copy(
        update={"iocs": merged_iocs, "affected_assets": merged_assets, "severity": merged_severity}
    )

    audit_entries = list(state.get("audit_log", []))
    audit_entries.append(
        f"Correlation -> merged related alert from {source or 'ingestion'} into incident {thread_id} "
        f"({match_reason}): {description[:200]}"
    )

    # `messages` uses add_messages — pass only the new message, never the
    # full accumulated list, or the prior history gets double-counted.
    new_message = {
        "role": "system",
        "name": "Correlation",
        "content": (
            f"Correlated alert merged from {source or 'ingestion'} (severity: {severity}) — {match_reason}:\n"
            f"{description}"
        ),
    }

    update = {
        "incident": incident,
        "audit_log": audit_entries,
        "messages": [new_message],
    }
    if usage:
        accumulate_usage(state, "Correlation Judge", usage)
        update["token_usage"] = state["token_usage"]

    app.update_state(config, update)

    final_state = app.get_state(config).values
    _persist(final_state)
    notify_if_needed(final_state, reason="correlated_merge")
    return final_state


def get_incident_state(thread_id: str, tenant_id: str = DEFAULT_TENANT) -> Optional[SentinelState]:
    app = get_app(tenant_id)
    snapshot = app.get_state(_config(thread_id))
    return snapshot.values or None


def _require_approved_by() -> bool:
    return os.getenv("SENTINELOS_REQUIRE_APPROVED_BY", "false").strip().lower() in ("1", "true", "yes")


def resolve_proposed_actions(
    thread_id: str, approve: bool, tenant_id: str = DEFAULT_TENANT, approved_by: Optional[str] = None
) -> SentinelState:
    """Approve or deny a Responder Agent's proposed actions for an incident.

    This is the human-in-the-loop gate: the Responder Agent only ever
    *proposes* actions and always stops (see graph.py). Nothing is marked
    approved/executed until this function is called by a human via the CLI
    or API.

    `approved_by` is an analyst-supplied identifier — the CLI's `--by`
    flag (or SENTINELOS_ANALYST_NAME), the API's `approved_by` request
    field, or the dashboard's "Approved by" input — recorded on every
    decided ProposedAction and in the audit log/message. It is NOT an
    authenticated identity (there's no per-user login yet — see README
    Known Gaps): a caller can put anything here, or nothing. That's a
    real, visible limitation, not a solved one — but it's strictly better
    than the previous behavior, where the audit trail for the single most
    consequential action in this whole system could never say who took it.
    """
    app = get_app(tenant_id)
    snapshot = app.get_state(_config(thread_id))
    state = snapshot.values
    if not state:
        raise ValueError(f"No incident found for thread_id={thread_id}")

    incident = state.get("incident")
    proposed_actions = state.get("proposed_actions", [])
    if not proposed_actions:
        raise ValueError(f"Incident {thread_id} has no pending proposed actions")

    if _require_approved_by() and not approved_by:
        raise ValueError(
            "SENTINELOS_REQUIRE_APPROVED_BY is set — this approve/deny call must include "
            "an analyst name (CLI --by, the API's approved_by field, or the dashboard's "
            "Analyst name field)."
        )

    decided = [
        action.model_copy(update={"approved": approve, "approved_by": approved_by})
        for action in proposed_actions
    ]

    verb = "approved" if approve else "denied"
    reviewer_label = f"Human Reviewer ({approved_by})" if approved_by else "Human Reviewer (unspecified)"
    audit_entries = list(state.get("audit_log", []))
    audit_entries.append(
        f"{reviewer_label} -> {verb} {len(decided)} proposed action(s) for incident {thread_id}"
    )

    if incident is not None:
        incident = incident.model_copy(update={"status": "contained" if approve else "closed"})

    action_lines = "\n".join(f"- {a.action} → {a.target} [{verb}]" for a in decided)
    # `messages` uses add_messages — pass only the new message, never the
    # full accumulated list, or the prior history gets double-counted.
    new_message = {
        "role": "human",
        "name": reviewer_label,
        "content": f"Reviewer {verb} the proposed actions:\n{action_lines}",
    }

    app.update_state(
        _config(thread_id),
        {
            "incident": incident,
            "proposed_actions": decided,
            "audit_log": audit_entries,
            "messages": [new_message],
        },
    )

    final_state = app.get_state(_config(thread_id)).values
    _persist(final_state)
    return final_state


def run_threat_hunt(
    query: str, thread_id: Optional[str] = None, tenant_id: str = DEFAULT_TENANT
) -> SentinelState:
    """Run a standalone, analyst-initiated threat hunt (not incident-triggered).

    Unlike a hunt reached automatically from the Investigator Agent, this
    lets a SOC analyst ask "is there a broader campaign behind X?" directly,
    without an incident already existing. Not part of the checkpointed
    graph (it's a single agent call, not a multi-step pipeline), but still
    tenant-scoped for memory recall and the vault report.
    """
    from agents.threat_hunter_agent import threat_hunter_agent

    tenant_id = sanitize_tenant_id(tenant_id)
    thread_id = thread_id or f"hunt-{uuid.uuid4()}"
    state: SentinelState = {
        "messages": [],
        "incident": Incident(
            id=thread_id,
            description=query,
            severity="low",
            status="investigating",
            source="analyst-initiated hunt",
        ),
        "long_term_summary": "",
        "audit_log": [],
        "next_agent": None,
        "proposed_actions": [],
        "token_usage": {},
        "tenant_id": tenant_id,
        "threat_intel": [],
        "attack_technique": None,
    }
    result = threat_hunter_agent(state)
    _persist(result, report_type="hunt")
    return result
