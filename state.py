from typing import Annotated, List, Literal, Optional, TypedDict

from langgraph.graph.message import add_messages
from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["low", "medium", "high", "critical"]
IncidentStatus = Literal["open", "investigating", "pending_approval", "contained", "closed"]

# Shared ordering so ingestion (severity prefilter) and correlation (does a
# related alert escalate the incident it merges into?) agree on what
# "higher severity" means, instead of each keeping its own copy.
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Incidents an analyst still has open — correlation only ever groups a new
# alert into one of these, never into something already contained/closed.
OPEN_STATUSES = ("open", "investigating", "pending_approval")

# Reused for free-text fields that come from external input (CLI args, API
# requests) — bounds both individual field size and, for list fields, the
# per-item size, as defense against unbounded-input resource exhaustion.
ShortStr = Annotated[str, Field(max_length=300)]


class Incident(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    id: str = Field(max_length=200)
    description: str = Field(max_length=4000)
    severity: Severity = "medium"
    status: IncidentStatus = "open"
    iocs: List[ShortStr] = Field(default_factory=list, max_length=50)
    affected_assets: List[ShortStr] = Field(default_factory=list, max_length=50)
    source: Optional[ShortStr] = None


class ProposedAction(BaseModel):
    action: str = Field(max_length=500)
    target: str = Field(max_length=500)
    rationale: str = Field(max_length=1000)
    # None = awaiting human decision, True = approved, False = denied
    approved: Optional[bool] = None
    # Who made that decision — an analyst-supplied identifier (CLI --by,
    # the API's approved_by field, or the dashboard's "Approved by" input),
    # not an authenticated identity (see README Known Gaps: no per-user
    # accounts yet). None until a decision is made, and still None after
    # one if the caller didn't supply anything — that's a real, visible
    # accountability gap in the vault/audit log, not silently hidden as
    # "Human Reviewer" the way it used to be for every decision.
    approved_by: Optional[ShortStr] = None


class SentinelState(TypedDict):
    messages: Annotated[list, add_messages]
    incident: Optional[Incident]
    long_term_summary: str
    audit_log: List[str]
    next_agent: Optional[str]
    proposed_actions: List[ProposedAction]
    # {"input_tokens": int, "output_tokens": int, "total_tokens": int,
    #  "by_agent": {agent_name: {same three keys}}} — accumulated across
    # every agent call for this incident via utils.llm.accumulate_usage().
    token_usage: dict
    # Set once at incident creation, read by every agent node (via
    # memory.vector_store) and by utils.obsidian.write_incident_report —
    # this is how tenant scoping reaches code that only ever receives
    # `state`, not an explicit function argument.
    tenant_id: str
    # List of enrichment.schemas.EnrichmentResult.model_dump() — real
    # provider lookups (AbuseIPDB/VirusTotal) Triage ran on the incident's
    # IOCs, not LLM recall. Empty if nothing was lookupable or no provider
    # API key is configured.
    threat_intel: List[dict]
    # {"id": str, "name": str|None, "tactic": str|None, "verified": bool}
    # if Investigator/Threat Hunter cited a MITRE ATT&CK technique ID —
    # `verified=False` means the ID wasn't found in our curated dataset,
    # a real (documented) LLM failure mode this flags rather than trusts.
    # None if no technique was cited.
    attack_technique: Optional[dict]
