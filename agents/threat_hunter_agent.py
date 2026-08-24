from langchain_core.prompts import ChatPromptTemplate

from agents.schemas import ThreatHuntFindings
from enrichment.mitre_attack import validate_technique_citation
from state import SentinelState
from utils.llm import accumulate_usage, get_llm, invoke_structured, usage_from_exception

prompt = ChatPromptTemplate.from_template(
    """You are the Sentinel Threat Hunter Agent — you proactively look for signs
that an incident is part of a broader, undetected campaign.

Current Incident:
{incident}

Organizational Context / Similar Past Incidents:
{long_term_summary}

Conversation History:
{messages}

Hunt for a broader campaign hypothesis connecting this incident to the
organization's history. Cite a MITRE ATT&CK technique ID only if one clearly
applies (leave it blank rather than guessing). State your confidence and
decide the next step:
- "hunt_complete" if no broader campaign is indicated
- "requires_response" if the findings warrant proposing concrete remediation actions"""
)


def threat_hunter_agent(state: SentinelState) -> SentinelState:
    incident = state.get("incident")

    try:
        # get_llm() must be inside this try — see triage_agent.py for why.
        llm = get_llm(temperature=0)
        chain = prompt | llm.with_structured_output(ThreatHuntFindings, include_raw=True)
        result: ThreatHuntFindings
        result, usage = invoke_structured(
            chain,
            {
                "incident": incident,
                "long_term_summary": state.get("long_term_summary", "") or "None on file.",
                "messages": state.get("messages", []),
            },
        )
        accumulate_usage(state, "Threat Hunter Agent", usage)
    except Exception as exc:
        accumulate_usage(state, "Threat Hunter Agent", usage_from_exception(exc))
        error_message = f"Threat Hunter Agent failed to reach the LLM provider: {exc}"
        # `messages` uses add_messages — return only the new message(s),
        # never the full accumulated list, or history double-counts.
        state["messages"] = [{"role": "assistant", "name": "Threat Hunter Agent", "content": error_message}]
        state["audit_log"].append(f"Threat Hunter Agent -> ERROR: {exc}")
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
        f"**Related Campaign Hypothesis:** {result.related_campaign_hypothesis}\n"
        f"**ATT&CK Technique:** {technique_line}\n"
        f"**Confidence:** {result.confidence}\n"
        f"**Decision:** {result.decision}"
    )
    state["messages"] = [{"role": "assistant", "name": "Threat Hunter Agent", "content": content}]

    if incident is not None and result.decision == "hunt_complete":
        incident.status = "closed"

    state["next_agent"] = "responder" if result.decision == "requires_response" else None
    state["audit_log"].append(
        f"Threat Hunter Agent -> decision={result.decision}, confidence={result.confidence}"
    )
    if attack_technique is not None:
        verified_tag = "verified" if attack_technique["verified"] else "UNVERIFIED"
        state["audit_log"].append(
            f"Threat Hunter Agent -> cited ATT&CK {attack_technique['id']} ({verified_tag})"
        )

    return state
