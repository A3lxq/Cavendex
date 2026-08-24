from langchain_core.prompts import ChatPromptTemplate

from agents.schemas import TriageAssessment
from enrichment.pipeline import enrich_iocs, format_for_prompt
from memory.vector_store import recall_similar_incidents, remember_incident
from state import SentinelState
from utils.llm import accumulate_usage, get_llm, invoke_structured, usage_from_exception
from utils.tenancy import DEFAULT_TENANT

prompt = ChatPromptTemplate.from_template(
    """You are the Sentinel Triage Agent — a senior SOC analyst with 15+ years of experience.

Current Incident:
{incident}

Organizational Context / Similar Past Incidents:
{long_term_summary}

Verified Threat Intelligence (real provider lookups, not your own recall —
trust this over any assumption you'd otherwise make about these indicators):
{threat_intel}

Conversation History:
{messages}

Assess the incident's severity, give concise reasoning, and decide whether it
needs escalation to the Investigator Agent or is resolved at triage."""
)


def triage_agent(state: SentinelState) -> SentinelState:
    incident = state.get("incident")
    tenant_id = state.get("tenant_id") or DEFAULT_TENANT

    long_term_summary = state.get("long_term_summary", "") or ""
    if incident is not None:
        try:
            recalled = recall_similar_incidents(incident.description, tenant_id=tenant_id)
        except Exception:
            recalled = []
        if recalled:
            long_term_summary = (
                long_term_summary + "\n\nSimilar past incidents:\n"
                + "\n".join(f"- {r}" for r in recalled)
            ).strip()
            state["long_term_summary"] = long_term_summary

    threat_intel_results = []
    if incident is not None and incident.iocs:
        try:
            threat_intel_results = enrich_iocs(incident.iocs)
        except Exception:
            threat_intel_results = []
    state["threat_intel"] = [r.model_dump() for r in threat_intel_results]
    threat_intel_text = format_for_prompt(threat_intel_results)

    try:
        # get_llm() raises RuntimeError if no provider is configured — that
        # has to land inside this try too, not just the invoke below, or a
        # missing key crashes the whole graph run (and, via the API, the
        # whole HTTP request) with an unhandled exception instead of the
        # clean in-band error this except block is meant to produce.
        llm = get_llm(temperature=0)
        chain = prompt | llm.with_structured_output(TriageAssessment, include_raw=True)
        result: TriageAssessment
        result, usage = invoke_structured(
            chain,
            {
                "incident": incident,
                "long_term_summary": long_term_summary or "None on file.",
                "threat_intel": threat_intel_text,
                "messages": state.get("messages", []),
            },
        )
        accumulate_usage(state, "Triage Agent", usage)
    except Exception as exc:
        accumulate_usage(state, "Triage Agent", usage_from_exception(exc))
        error_message = f"Triage Agent failed to reach the LLM provider: {exc}"
        # `messages` uses LangGraph's add_messages reducer, which merges
        # whatever we return here on top of the existing history — return
        # only the new message(s), never the full accumulated list, or the
        # prior history gets double-counted.
        state["messages"] = [{"role": "assistant", "name": "Triage Agent", "content": error_message}]
        state["audit_log"].append(f"Triage Agent -> ERROR: {exc}")
        state["next_agent"] = None
        return state

    content = (
        f"**Severity:** {result.severity}\n"
        f"**Reasoning:** {result.reasoning}\n"
        f"**Decision:** {result.decision}\n\n"
        f"**Threat Intelligence:**\n{threat_intel_text}"
    )
    state["messages"] = [{"role": "assistant", "name": "Triage Agent", "content": content}]

    if incident is not None:
        incident.severity = result.severity
        incident.status = (
            "investigating" if result.decision == "escalate_to_investigation" else "closed"
        )
        try:
            remember_incident(
                incident_id=incident.id,
                description=incident.description,
                summary=f"[{result.severity}] {incident.description} — {result.reasoning}",
                severity=result.severity,
                tenant_id=tenant_id,
            )
        except Exception:
            pass

    state["next_agent"] = (
        "investigator" if result.decision == "escalate_to_investigation" else None
    )
    state["audit_log"].append(f"Triage Agent -> severity={result.severity}, decision={result.decision}")
    if threat_intel_results:
        state["audit_log"].append(
            f"Triage Agent -> threat intel: {len(threat_intel_results)} verified lookup(s) "
            f"({', '.join(sorted({r.source for r in threat_intel_results}))})"
        )

    return state
