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
import threading
import uuid
from typing import List, Optional

from graph import get_app
from notifications.case_sync import sync_incident as sync_jira_issue
from notifications.pipeline import notify_if_needed
from state import SEVERITY_RANK, Incident, CavendexState
from utils.audit_chain import record_chain
from utils.incident_events import publish as publish_incident_event
from utils.incident_index import upsert_incident_summary
from utils.llm import accumulate_usage
from utils.obsidian import write_incident_report
from utils.tenancy import DEFAULT_TENANT, sanitize_tenant_id

# Per-(tenant_id, thread_id) locks guarding every read-modify-write cycle
# against a single incident's checkpoint (app.get_state -> compute ->
# app.update_state). LangGraph's SqliteSaver has no compare-and-swap —
# two concurrent calls (e.g. a double-submitted Approve click, or two
# analysts approving the same incident at once) would otherwise race:
# the loser's update_state silently overwrites the winner's already-
# committed state, erasing whichever audit_log entries/decisions/
# remediation results were written in between. Scoped to this one
# process, matching this project's default single-uvicorn-process
# deployment model (see README's "Distributed Rate Limiting and Dedup"
# for the same in-process-by-default framing) — a multi-worker/multi-
# replica deployment needs a real distributed lock instead, the same
# honest limitation already documented for the in-process SSE pub/sub.
_incident_locks: dict = {}
_incident_locks_registry_lock = threading.Lock()


def _incident_lock(tenant_id: str, thread_id: str) -> threading.Lock:
    key = (tenant_id, thread_id)
    with _incident_locks_registry_lock:
        lock = _incident_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _incident_locks[key] = lock
        return lock


def _config(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id}}


def _playbooks_mode() -> str:
    mode = os.getenv("CAVENDEX_PLAYBOOKS_MODE", "append").strip().lower()
    return mode if mode in ("append", "replace") else "append"


def _apply_playbook(app, config: dict, state: CavendexState) -> CavendexState:
    """Deterministic, non-LLM post-processing step run once after the
    agent graph finishes (see run_new_incident/run_new_incident_stream):
    if a configured playbook (playbooks/loader.py) matches this
    incident (playbooks/matcher.py), its steps are rendered into real
    ProposedActions (playbooks/expander.py) and folded into
    proposed_actions per CAVENDEX_PLAYBOOKS_MODE — "append" (default)
    alongside whatever the Responder Agent already proposed, or
    "replace" instead of it.

    A standalone function (not inlined into its callers) so a test can
    call it directly against a state seeded via app.update_state,
    without needing a real LLM run — the same reason
    resolve_proposed_actions below is tested that way.

    No playbooks configured, nothing matches, or nothing was renderable
    for this incident: returns `state` completely unchanged (not even a
    no-op app.update_state call), so this feature costs nothing when
    CAVENDEX_PLAYBOOKS_DIR is unset.
    """
    incident = state.get("incident")
    if incident is None:
        return state

    from playbooks.loader import load_playbooks
    from playbooks.matcher import match_playbook
    from playbooks.expander import expand_playbook_actions

    playbooks = load_playbooks()
    if not playbooks:
        return state

    playbook = match_playbook(incident, playbooks)
    if playbook is None:
        return state

    new_actions, skipped = expand_playbook_actions(playbook, incident)
    if not new_actions:
        return state

    tenant_id = state.get("tenant_id") or DEFAULT_TENANT
    with _incident_lock(tenant_id, incident.id):
        # Re-read state under the lock — it may have changed since the
        # snapshot passed in (e.g. a concurrent merge_correlated_alert)
        # — and re-derive proposed_actions/audit_log from that current
        # state, not the possibly-stale copy captured before the lock.
        current = app.get_state(config).values or state
        existing = current.get("proposed_actions", [])
        proposed_actions = new_actions if _playbooks_mode() == "replace" else list(existing) + new_actions

        audit_entries = list(current.get("audit_log", []))
        summary = f"Playbook -> matched '{playbook.name}' ({playbook.id}): added {len(new_actions)} step(s)"
        if skipped:
            summary += f", skipped {len(skipped)} unrenderable step(s) ({'; '.join(skipped)})"
        audit_entries.append(summary)

        # Mirrors agents/responder_agent.py's own "there are now proposed
        # actions awaiting a human" transition — a playbook match is just
        # another source of proposed actions, not a different status shape.
        updated_incident = (current.get("incident") or incident).model_copy(update={"status": "pending_approval"})

        app.update_state(
            config,
            {
                "incident": updated_incident,
                "proposed_actions": proposed_actions,
                "audit_log": audit_entries,
            },
        )
        return app.get_state(config).values


def _persist(state: CavendexState, report_type: str = "incident") -> None:
    """Write the vault report, update the dashboard's list index, record
    this audit_log's current tamper-evidence hash into the append-only
    chain ledger (see utils/audit_chain.py), and sync a Jira issue if
    configured (see notifications/case_sync.py — creates one the first
    time an incident is seen, adds a progress comment on every later
    call) — everything a finished pipeline run/decision needs to durably
    land. Index, ledger, and Jira-sync failures are all swallowed (none
    is part of the actual incident record itself) so a bug in any of
    them can never break the pipeline.
    """
    write_incident_report(state, report_type=report_type)
    tenant_id = state.get("tenant_id") or DEFAULT_TENANT
    try:
        upsert_incident_summary(tenant_id, state, report_type=report_type)
    except Exception:
        pass

    incident = state.get("incident")
    if incident is not None:
        record_chain(tenant_id, incident.id, state.get("audit_log", []))
        try:
            sync_jira_issue(tenant_id, incident)
        except Exception:
            pass

    try:
        publish_incident_event(tenant_id, {"type": "incident_updated", "thread_id": incident.id if incident else None})
    except Exception:
        pass


def _new_incident_state(
    description: str,
    severity: str,
    affected_assets: Optional[List[str]],
    iocs: Optional[List[str]],
    source: Optional[str],
    thread_id: str,
    tenant_id: str,
) -> CavendexState:
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
) -> CavendexState:
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
    config = _config(thread_id)
    final_state = app.invoke(initial_state, config=config)
    final_state = _apply_playbook(app, config, final_state)
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
    final_state = _apply_playbook(app, config, final_state)
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
) -> CavendexState:
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

    # Locked: a busy ingestion pipeline can plausibly deliver several
    # alerts that all correlate into the SAME open incident at nearly
    # the same time (e.g. a burst of related events) — without this,
    # two concurrent merges could race on the same read-modify-write
    # cycle and one's merged IOCs/audit entry would silently overwrite
    # the other's (LangGraph's SqliteSaver has no compare-and-swap).
    with _incident_lock(tenant_id, thread_id):
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


def get_incident_state(thread_id: str, tenant_id: str = DEFAULT_TENANT) -> Optional[CavendexState]:
    app = get_app(tenant_id)
    snapshot = app.get_state(_config(thread_id))
    return snapshot.values or None


def _require_approved_by() -> bool:
    return os.getenv("CAVENDEX_REQUIRE_APPROVED_BY", "false").strip().lower() in ("1", "true", "yes")


def resolve_proposed_actions(
    thread_id: str, approve: bool, tenant_id: str = DEFAULT_TENANT, approved_by: Optional[str] = None
) -> CavendexState:
    """Approve or deny a Responder Agent's proposed actions for an incident.

    This is the human-in-the-loop gate: the Responder Agent only ever
    *proposes* actions and always stops (see graph.py). Nothing is marked
    approved/executed until this function is called by a human via the CLI
    or API. On approval, an action whose action_type is currently eligible
    (see remediation/executor.py — opt-in, disabled by default, and
    "other" is never eligible regardless of configuration) is handed to
    remediation/pipeline.py:execute_if_eligible for real execution; a
    denial never reaches that at all.

    `approved_by` is an analyst-supplied identifier — the CLI's `--by`
    flag (or CAVENDEX_ANALYST_NAME), the API's `approved_by` request
    field, or the dashboard's "Approved by" input — recorded on every
    decided ProposedAction and in the audit log/message. It is NOT an
    authenticated identity (there's no per-user login yet — see README
    Known Gaps): a caller can put anything here, or nothing. That's a
    real, visible limitation, not a solved one — but it's strictly better
    than the previous behavior, where the audit trail for the single most
    consequential action in this whole system could never say who took it.
    """
    app = get_app(tenant_id)

    # Locked for the whole read-modify-write cycle: two concurrent
    # approve/deny calls on the same incident (a double-submitted click,
    # two analysts, or a retried request) would otherwise race — the
    # loser's app.update_state silently overwrites the winner's already-
    # committed decision/audit entries/remediation results, since
    # LangGraph's SqliteSaver has no compare-and-swap.
    with _incident_lock(tenant_id, thread_id):
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
                "CAVENDEX_REQUIRE_APPROVED_BY is set — this approve/deny call must include "
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

        # Real remediation execution only ever runs on approval, and only
        # for an action whose type is currently eligible (see
        # remediation/executor.py:is_automatable) — a denial never reaches
        # this at all. Attempted per action rather than per incident, since
        # a mixed batch (one automatable, one not) is a real, expected case.
        if approve and incident is not None:
            from remediation.pipeline import execute_if_eligible

            # Keyed by playbook_id, populated only once a real attempted
            # send for one of that playbook's steps actually fails (not
            # merely "not automatable" — see the executed is False check
            # below). A halted chain's remaining steps are skipped rather
            # than attempted, in the order decided already preserves —
            # nothing else in this codebase reorders proposed_actions after
            # playbooks/expander.py assigns chain_step, so a simple
            # in-order walk is enough for correct halt semantics.
            #
            # on_failure is read from the action itself (pinned by
            # playbooks/expander.py at the time the chain was generated),
            # never by re-resolving playbook_id against a fresh
            # load_playbooks() call here — an incident can sit
            # pending_approval for minutes to days, and re-reading the
            # policy from current disk state at approval time would let a
            # playbook file edited (or a colliding id introduced) during
            # that window silently change the safety semantics an analyst
            # already reviewed and approved. Falls back to "halt" (the safe
            # default) only for an old checkpoint persisted before this
            # field existed.
            halted_chains = set()

            remediated = []
            for action in decided:
                if action.playbook_id is not None and action.playbook_id in halted_chains:
                    action = action.model_copy(
                        update={
                            "executed": None,
                            "execution_detail": "skipped: an earlier step in this playbook chain failed",
                        }
                    )
                    remediated.append(action)
                    continue

                executed, detail = execute_if_eligible(incident, action, tenant_id)
                if executed is not None:
                    action = action.model_copy(update={"executed": executed, "execution_detail": detail})
                    audit_entries.append(f"Remediation -> {action.action_type} on {action.target!r}: {detail}")
                if executed is False and action.playbook_id is not None:
                    on_failure = action.on_failure or "halt"
                    if on_failure == "halt":
                        halted_chains.add(action.playbook_id)
                remediated.append(action)
            decided = remediated

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
) -> CavendexState:
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
    state: CavendexState = {
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
