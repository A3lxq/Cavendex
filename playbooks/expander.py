"""Renders a matched playbook's steps into real ProposedActions against
one incident's data. Template substitution is a fixed whitelist, never
`eval` or a general format-string interpreter: {ioc} -> the incident's
first IOC, {asset} -> its first affected asset, anything else is passed
through as a literal target (e.g. a playbook author hardcoding a known
internal quarantine VLAN name).

A step whose template references a field the incident doesn't actually
have (e.g. {ioc} on an incident with no IOCs) is skipped rather than
rendered with a broken/empty target — the caller is told which steps
were skipped so it can note that honestly in the audit log instead of
silently proposing an action nobody could actually carry out.
"""

from typing import List, Tuple

from state import Incident, ProposedAction
from playbooks.schema import Playbook


def _render_target(template: str, incident: Incident) -> Tuple[bool, str]:
    if template == "{ioc}":
        if not incident.iocs:
            return False, template
        return True, incident.iocs[0]
    if template == "{asset}":
        if not incident.affected_assets:
            return False, template
        return True, incident.affected_assets[0]
    return True, template


def expand_playbook_actions(
    playbook: Playbook, incident: Incident
) -> Tuple[List[ProposedAction], List[str]]:
    """(actions, skipped_step_descriptions) — actions are in step order,
    each stamped with playbook_id and a 1-based chain_step. Execution
    order (see workflows/incident_pipeline.py:resolve_proposed_actions)
    relies on this list preserving that order end to end — nothing else
    in this codebase reorders proposed_actions after this point.
    """
    actions: List[ProposedAction] = []
    skipped: List[str] = []
    chain_step = 0
    for step in playbook.steps:
        chain_step += 1
        ok, target = _render_target(step.target_template, incident)
        if not ok:
            skipped.append(f"step {chain_step} ({step.action}): could not render {target!r} for this incident")
            continue
        actions.append(
            ProposedAction(
                action=step.action,
                target=target,
                rationale=step.rationale,
                action_type=step.action_type,
                playbook_id=playbook.id,
                chain_step=chain_step,
            )
        )
    return actions, skipped
