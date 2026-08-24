from langchain_core.prompts import ChatPromptTemplate

from agents.schemas import InvestigationFindings
from enrichment.mitre_attack import validate_technique_citation
from state import SentinelState
from utils.llm import accumulate_usage, get_llm, invoke_structured, usage_from_exception

prompt = ChatPromptTemplate.from_template(
    """You are the Sentinel Investigator Agent — you perform deeper analysis on
incidents escalated by Triage.

Current Incident:
{incident}

Organizational Context / Similar Past Incidents:
{long_term_summary}

Conversation History:
{messages}

Investigate the incident: propose a root-cause hypothesis, list any additional
IOCs implied by the evidence, cite a MITRE ATT&CK technique ID only if one
clearly applies (leave it blank rather than guessing), and decide the next step:
- "investigation_complete" if no further action is needed
- "requires_threat_hunt" if this may be part of a broader campaign worth hunting for
- "requires_response" if concrete remediation actions should be proposed now"""
)


def investigator_agent(state: SentinelState) -> SentinelState:
    incident = state.get("incident")

    try:
        # get_llm() must be inside this try — see triage_agent.py for why.
        llm = get_llm(temperature=0)
        chain = prompt | llm.with_structured_output(InvestigationFindings, include_raw=True)
        result: InvestigationFindings
        result, usage = invoke_structured(
            chain,
            {
                "incident": incident,
                "long_term_summary": state.get("long_term_summary", "") or "None on file.",
                "messages": state.get("messages", []),
            },
        )
        accumulate_usage(state, "Investigator Agent", usage)
    except Exception as exc:
        accumulate_usage(state, "Investigator Agent", usage_from_exception(exc))
        error_message = f"Investigator Agent failed to reach the LLM provider: {exc}"
        # `messages` uses add_messages — return only the new message(s),
        # never the full accumulated list, or history double-counts.
        state["messages"] = [{"role": "assistant", "name": "Investigator Agent", "content": error_message}]
        state["audit_log"].append(f"Investigator Agent -> ERROR: {exc}")
        state["next_agent"] = None
        return state

    attack_technique = validate_technique_citation(result.attack_technique_id)
    state["attack_technique"] = attack_technique
    if attack_technique is None:
        technique_line = "none cited"
    elif attack_technique["verified"]:
        technique_line = f"{attack_technique['id']} — {attack_technique['name']} ({attack_technique['tactic']}) [verified]"
    else:
        technique_line = f"{attack_technique['id']} — NOT FOUND in local ATT&CK dataset, treat with caution [unverified]"

    content = (
        f"**Summary:** {result.summary}\n"
        f"**Root Cause Hypothesis:** {result.root_cause_hypothesis}\n"
        f"**Additional IOCs:** {', '.join(result.additional_iocs) or 'none'}\n"
        f"**ATT&CK Technique:** {technique_line}\n"
        f"**Decision:** {result.decision}"
    )
    state["messages"] = [{"role": "assistant", "name": "Investigator Agent", "content": content}]

    if incident is not None:
        # incident.iocs is a plain list once inside the model — .append()
        # bypasses Pydantic's field validation entirely, so the ShortStr /
        # max_length constraints on Incident.iocs don't protect this loop
        # by themselves. Clamp explicitly: an LLM output is not guaranteed
        # bounded, and this loop runs once per Investigator turn.
        for ioc in result.additional_iocs:
            if len(incident.iocs) >= 50:
                break
            ioc = ioc[:300]
            if ioc not in incident.iocs:
                incident.iocs.append(ioc)
        if result.decision == "investigation_complete":
            incident.status = "closed"

    routing = {
        "requires_threat_hunt": "threat_hunter",
        "requires_response": "responder",
        "investigation_complete": None,
    }
    state["next_agent"] = routing[result.decision]
    state["audit_log"].append(f"Investigator Agent -> decision={result.decision}")
    if attack_technique is not None:
        verified_tag = "verified" if attack_technique["verified"] else "UNVERIFIED"
        state["audit_log"].append(
            f"Investigator Agent -> cited ATT&CK {attack_technique['id']} ({verified_tag})"
        )

    return state
