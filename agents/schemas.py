"""Structured output schemas for each agent.

Every agent forces its LLM call through one of these Pydantic models
via `llm.with_structured_output(...)` instead of parsing free-text —
routing decisions are read from a typed `decision` field, not guessed
from keyword substrings in prose.
"""

from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from state import ActionType

_ATTACK_TECHNIQUE_DESCRIPTION = (
    "A MITRE ATT&CK technique ID (e.g. 'T1110' or 'T1110.001') that best matches "
    "this incident's behavior, if one clearly applies — leave this null/empty if "
    "you are not confident, rather than guessing. Whatever you cite is checked "
    "against a local technique database and flagged if it doesn't match, so an "
    "invented or misremembered ID will be caught, not silently trusted."
)


class TriageAssessment(BaseModel):
    severity: Literal["low", "medium", "high", "critical"]
    reasoning: str = Field(description="Concise, actionable reasoning for the severity call")
    decision: Literal["triage_complete", "escalate_to_investigation"]


class InvestigationFindings(BaseModel):
    summary: str
    root_cause_hypothesis: str
    additional_iocs: List[str] = Field(
        default_factory=list,
        description=(
            "Short, atomic indicators only — an IP, hash, domain, account name, "
            "or event ID (e.g. '10.0.0.5', 'svc_backup', 'Event ID 4625'). One "
            "concrete value per entry. Never a descriptive sentence or clause — "
            "narrative context belongs in root_cause_hypothesis instead."
        ),
    )
    attack_technique_id: Optional[str] = Field(
        default=None, description=_ATTACK_TECHNIQUE_DESCRIPTION
    )
    decision: Literal[
        "investigation_complete", "requires_threat_hunt", "requires_response"
    ]


class ThreatHuntFindings(BaseModel):
    summary: str
    related_campaign_hypothesis: str
    attack_technique_id: Optional[str] = Field(
        default=None, description=_ATTACK_TECHNIQUE_DESCRIPTION
    )
    confidence: Literal["low", "medium", "high"]
    decision: Literal["hunt_complete", "requires_response"]


class ProposedActionDraft(BaseModel):
    """What the Responder Agent's LLM call actually produces.

    Deliberately excludes `approved` (state.ProposedAction's tri-state
    approval field) — the LLM has no business setting it, and a nullable
    boolean in a nested-object schema was empirically unreliable for
    structured output on at least one local model (Ollama/qwen3.6). The
    agent wraps each draft into a full ProposedAction afterward.
    """

    action: str
    target: str
    rationale: str
    action_type: ActionType = Field(
        default="other",
        description=(
            "Classify `action` into one of these categories so an approved action can "
            "potentially be executed automatically (see remediation/executor.py) instead "
            "of only ever being a text description a human has to act on by hand. Use "
            "'other' whenever no category clearly fits — that's the safe default, not a "
            "failure: an 'other' action is never eligible for automated execution "
            "regardless of configuration, so guessing wrong toward 'other' costs nothing "
            "except the analyst doing that one step manually, while guessing wrong toward "
            "a specific category could mean the wrong kind of action gets attempted "
            "automatically."
        ),
    )


class ResponsePlan(BaseModel):
    summary: str
    proposed_actions: List[ProposedActionDraft] = Field(default_factory=list)
