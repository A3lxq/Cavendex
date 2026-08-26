"""Playbook definition schema — validated at load time (see
playbooks/loader.py) so a malformed operator-authored file is rejected
early with a clear reason, rather than producing a broken match or a
half-rendered action later.
"""

from typing import List, Literal, Optional

from pydantic import BaseModel, Field, model_validator

from state import ActionType, Severity, ShortStr


class MatchRule(BaseModel):
    """All specified conditions are ANDed — there's no OR/nested logic in
    this first version (a documented limitation, not an oversight; see
    README's Known Gaps). At least one condition must be set: an empty
    match rule would otherwise silently match every incident, which is
    almost certainly not what an operator authoring a playbook file
    intended.
    """

    # List-length bounds mirror Incident.iocs/affected_assets' own
    # max_length=50 (state.py) — consistency with how every other
    # externally-influenced list field in this project is bounded, even
    # though a playbook file is local operator config, not attacker-
    # reachable, so this is defense-in-depth/hardening rather than a
    # response to a real exploit path.
    severities: Optional[List[Severity]] = Field(default=None, max_length=50)
    sources: Optional[List[ShortStr]] = Field(default=None, max_length=50)
    # Case-insensitive substring match against any of the incident's IOCs.
    ioc_contains: Optional[List[ShortStr]] = Field(default=None, max_length=50)

    @model_validator(mode="after")
    def _at_least_one_condition(self):
        if not (self.severities or self.sources or self.ioc_contains):
            raise ValueError(
                "a playbook's match rule must set at least one of "
                "severities/sources/ioc_contains — an empty rule would "
                "match every incident"
            )
        return self


class PlaybookStep(BaseModel):
    action_type: ActionType
    action: ShortStr
    # "{ioc}" -> incident's first IOC, "{asset}" -> incident's first
    # affected asset, anything else is a literal string — see
    # playbooks/expander.py for the fixed-whitelist substitution. Never
    # eval'd or interpreted as a format string beyond that whitelist.
    target_template: ShortStr
    # Plain str, not ShortStr -- ShortStr already carries its own
    # Field(max_length=300); Pydantic merges an Annotated type's own
    # constraint with a field-level override by taking the STRICTER of
    # the two, so `ShortStr = Field(max_length=1000)` was silently still
    # enforcing 300, not the 1000 this declaration claimed.
    rationale: str = Field(max_length=1000)


class Playbook(BaseModel):
    id: str = Field(max_length=200)
    name: ShortStr
    description: str = Field(default="", max_length=1000)
    # Tie-break when more than one playbook matches the same incident —
    # higher wins; ties broken by `id` (alphabetically lowest) for a
    # deterministic result regardless of file load order.
    priority: int = 0
    match: MatchRule
    steps: List[PlaybookStep] = Field(min_length=1, max_length=50)
    # Whether a real attempted-and-failed remediation send for one step
    # skips the rest of this playbook's remaining steps ("halt", the
    # safer default) or lets them proceed independently ("continue") —
    # see workflows/incident_pipeline.py:resolve_proposed_actions.
    on_failure: Literal["halt", "continue"] = "halt"
