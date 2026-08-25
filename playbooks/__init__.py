"""Declarative, deterministic response playbooks (roadmap item #104).

A playbook is a match rule plus an ordered list of remediation steps —
see playbooks/schema.py for the exact shape. This package is entirely
non-LLM: matching and template expansion are pure functions over an
already-finished incident, run as a post-processing step after the
agent graph (see workflows/incident_pipeline.py:_apply_playbook), never
a change to what the agents themselves do or how they're prompted.
"""
