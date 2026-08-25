from langchain_core.prompts import ChatPromptTemplate

from agents.schemas import ResponsePlan
from state import ProposedAction, SentinelState
from utils.llm import accumulate_usage, get_llm, invoke_structured, usage_from_exception

prompt = ChatPromptTemplate.from_template(
    """You are the Sentinel Responder Agent — you propose concrete remediation
actions for an incident. You NEVER execute anything yourself: every action you
propose requires explicit human approval before anything happens.

Current Incident:
{incident}

Organizational Context / Similar Past Incidents:
{long_term_summary}

Conversation History:
{messages}

Propose the minimal set of remediation actions needed (e.g. block an IP,
isolate a host, reset credentials, disable an account). For each action give
the action, its target, your rationale, and its action_type category."""
)


def responder_agent(state: SentinelState) -> SentinelState:
    incident = state.get("incident")

    try:
        # get_llm() must be inside this try — see triage_agent.py for why.
        llm = get_llm(temperature=0)
        chain = prompt | llm.with_structured_output(ResponsePlan, include_raw=True)
        result: ResponsePlan
        result, usage = invoke_structured(
            chain,
            {
                "incident": incident,
                "long_term_summary": state.get("long_term_summary", "") or "None on file.",
                "messages": state.get("messages", []),
            },
        )
        accumulate_usage(state, "Responder Agent", usage)
    except Exception as exc:
        accumulate_usage(state, "Responder Agent", usage_from_exception(exc))
        error_message = f"Responder Agent failed to reach the LLM provider: {exc}"
        # `messages` uses add_messages — return only the new message(s),
        # never the full accumulated list, or history double-counts.
        state["messages"] = [{"role": "assistant", "name": "Responder Agent", "content": error_message}]
        state["audit_log"].append(f"Responder Agent -> ERROR: {exc}")
        state["next_agent"] = None
        return state

    actions_text = (
        "\n".join(f"- {a.action} → {a.target} ({a.rationale})" for a in result.proposed_actions)
        or "No actions proposed."
    )
    content = (
        f"**Summary:** {result.summary}\n"
        f"**Proposed Actions (pending human approval):**\n{actions_text}"
    )
    state["messages"] = [{"role": "assistant", "name": "Responder Agent", "content": content}]

    # Wrap each LLM-produced draft into a full ProposedAction — `approved`
    # always starts unset (None) here; only resolve_proposed_actions can
    # set it, once a human has actually decided.
    proposed_actions = [
        ProposedAction(action=a.action, target=a.target, rationale=a.rationale, action_type=a.action_type)
        for a in result.proposed_actions
    ]
    state["proposed_actions"] = proposed_actions
    state["next_agent"] = None

    if incident is not None:
        incident.status = "pending_approval"

    state["audit_log"].append(
        f"Responder Agent -> proposed {len(proposed_actions)} action(s), awaiting human approval"
    )

    return state
