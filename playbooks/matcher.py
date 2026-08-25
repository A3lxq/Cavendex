"""Deterministic playbook selection — a pure function over an already-
finished incident and the currently-loaded playbooks, with no I/O and
no LLM call, so it's trivially unit-testable and auditable: the same
incident + the same playbook files always match the same way.
"""

from typing import List, Optional

from state import Incident
from playbooks.schema import MatchRule, Playbook


def _rule_matches(rule: MatchRule, incident: Incident) -> bool:
    if rule.severities is not None and incident.severity not in rule.severities:
        return False
    if rule.sources is not None and incident.source not in rule.sources:
        return False
    if rule.ioc_contains is not None:
        haystack = [ioc.lower() for ioc in incident.iocs]
        if not any(needle.lower() in ioc for needle in rule.ioc_contains for ioc in haystack):
            return False
    return True


def match_playbook(incident: Incident, playbooks: List[Playbook]) -> Optional[Playbook]:
    """The single best-matching playbook for `incident`, or None if no
    playbook's match rule is satisfied. Exactly one playbook is ever
    selected per incident (this project's V1 scope — no multi-playbook
    composition, see README's Known Gaps): the highest `priority` among
    matches, with ties broken by the lowest `id` alphabetically so the
    result never depends on file load order.
    """
    matches = [p for p in playbooks if _rule_matches(p.match, incident)]
    if not matches:
        return None
    return sorted(matches, key=lambda p: (-p.priority, p.id))[0]
