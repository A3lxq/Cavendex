"""Obsidian vault reporting — Cavendex's structured, durable logging layer.

Every pipeline run (and every human approve/deny decision) is rendered as a
linked set of Markdown notes instead of a flat log line: one note per
incident, plus auto-created stub notes per IOC and affected asset that
backlink to every incident referencing them. Point Obsidian at
OBSIDIAN_VAULT_PATH and the graph view shows the real relationship network
between incidents, assets, and indicators.
"""

import html
import json
import os
import re
from datetime import datetime, timezone

from utils.tenancy import DEFAULT_TENANT, sanitize_tenant_id


def _vault_root(tenant_id: str = DEFAULT_TENANT) -> str:
    # Read lazily (not at import time) so OBSIDIAN_VAULT_PATH can be set
    # via load_dotenv() or monkeypatched in tests after this module is
    # first imported. Each tenant gets its own subfolder — full isolation,
    # not just a shared vault with a tenant tag on each note.
    base = os.getenv("OBSIDIAN_VAULT_PATH", "obsidian_vault")
    return os.path.join(base, sanitize_tenant_id(tenant_id))


_MAX_SLUG_LENGTH = 100


def _slugify(text: str) -> str:
    text = str(text).strip()
    slug = re.sub(r'[\\/:*?"<>|]', "-", text) or "untitled"
    # Defensive cap: an LLM-generated IOC/asset name is free text and can
    # in principle be arbitrarily long, and most filesystems cap filenames
    # around 255 bytes — truncate well under that regardless of what the
    # model produces.
    if len(slug) > _MAX_SLUG_LENGTH:
        slug = slug[: _MAX_SLUG_LENGTH - 1].rstrip() + "…"
    return slug


_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f]")


def _escape(text) -> str:
    """Neutralize raw HTML in content that ultimately originates from an
    incident description (external input) or an LLM completion (which a
    prompt-injected description could influence). Obsidian's reading view —
    and GitHub-flavored Markdown, if this vault is ever pushed to a repo —
    both render inline HTML by default, so an unescaped `<img onerror=...>`
    or `<iframe src=...>` in a note is a real content-injection risk to
    whoever opens it. quote=False keeps normal quote characters readable in
    prose; only angle brackets and bare ampersands actually trigger HTML
    parsing.

    Also strips C0 control characters (including newlines/carriage
    returns) before escaping — content that's meant to render as one
    Markdown line (an audit_log entry, an analyst name, an ingested
    alert's description/source) but contains an embedded newline could
    otherwise break out of its intended single bullet/line and inject
    arbitrary new Markdown structure (a fake bullet, a fake heading, a
    misleading "approved by" line) into the vault report — the same
    untrusted-input class this project already treats carefully for
    prompt injection, applied here to Markdown structure instead of an
    LLM prompt.
    """
    text = _CONTROL_CHARS_RE.sub(" ", str(text))
    return html.escape(text, quote=False)


def _format_usage(token_usage) -> str:
    """Render the per-incident token-usage total plus a per-agent
    breakdown. Token counts only, not a dollar estimate — pricing varies
    by provider/model and changes over time, so an estimated cost here
    would risk asserting a number that's stale or wrong. Local Ollama
    calls are effectively free regardless.
    """
    if not token_usage:
        return "_No usage recorded._"

    total = token_usage.get("total_tokens", 0)
    input_t = token_usage.get("input_tokens", 0)
    output_t = token_usage.get("output_tokens", 0)
    lines = [f"**Total:** {total} tokens ({input_t} in / {output_t} out)"]

    by_agent = token_usage.get("by_agent") or {}
    if by_agent:
        lines.append("")
        for agent_name, usage in by_agent.items():
            lines.append(
                f"- {_escape(agent_name)}: {usage.get('total_tokens', 0)} tokens "
                f"({usage.get('input_tokens', 0)} in / {usage.get('output_tokens', 0)} out)"
            )
    return "\n".join(lines)


def _format_threat_intel(results) -> str:
    """Real provider lookups (AbuseIPDB/VirusTotal), not LLM recall — kept
    as its own vault section so an analyst can see at a glance which
    claims in the agent findings above are backed by an actual lookup.
    """
    if not results:
        return "_No verified threat-intel lookups for this incident (no lookupable IOCs, or no provider API key configured)._"

    lines = []
    for r in results:
        indicator, indicator_type, source, verdict, detail, link = (
            _field(r, "indicator"), _field(r, "indicator_type"), _field(r, "source"),
            _field(r, "verdict"), _field(r, "detail"), _field(r, "link"),
        )
        line = f"- **{_escape(indicator)}** ({indicator_type}) — {source}: `{verdict}` — {_escape(detail)}"
        if link:
            line += f" ([source]({link}))"
        lines.append(line)
    return "\n".join(lines)


def _format_attack_technique(attack_technique) -> str:
    """Whether an ATT&CK technique an agent cited actually exists in our
    curated local dataset — flags a hallucinated ID rather than trusting it.
    """
    if not attack_technique:
        return "_No ATT&CK technique cited._"

    technique_id, name, tactic, verified = (
        _field(attack_technique, "id"), _field(attack_technique, "name"),
        _field(attack_technique, "tactic"), _field(attack_technique, "verified"),
    )
    if verified:
        return f"**{_escape(technique_id)}** — {_escape(name)} ({_escape(tactic)}) ✅ verified against local ATT&CK dataset"
    return (
        f"**{_escape(technique_id)}** — ⚠️ NOT FOUND in local ATT&CK dataset. "
        "May be a hallucinated/misremembered ID, a real technique outside our curated subset, "
        f"or a typo — verify manually at https://attack.mitre.org/techniques/{_escape(technique_id).replace('.', '/')}"
    )


def _message_agent_and_content(msg):
    if isinstance(msg, dict):
        return msg.get("name") or msg.get("role", "assistant"), msg.get("content", "")
    name = getattr(msg, "name", None)
    if not name:
        name = "Human Reviewer" if getattr(msg, "type", "") == "human" else "Agent"
    return name, getattr(msg, "content", "")


def _field(obj, name):
    return getattr(obj, name) if hasattr(obj, name) else obj.get(name)


def _ensure_dirs(tenant_id: str = DEFAULT_TENANT):
    for sub in ("Incidents", "Assets", "IOCs", "Hunts"):
        os.makedirs(os.path.join(_vault_root(tenant_id), sub), exist_ok=True)


def _safe_note_path(folder: str, note_name: str, tenant_id: str = DEFAULT_TENANT) -> str:
    """Join a note filename under the vault root and verify it didn't
    escape — defense in depth beyond _slugify(). Every value that reaches
    here (asset/IOC names, incident IDs) can originate from an LLM or an
    API caller; a single missed character in _slugify() should not be
    enough to let a note land outside the vault.
    """
    root = os.path.abspath(_vault_root(tenant_id))
    path = os.path.abspath(os.path.join(root, folder, f"{note_name}.md"))
    if os.path.commonpath([root, path]) != root:
        raise ValueError(f"Refusing to write note outside the vault: {note_name!r}")
    return path


def _write_stub_note(
    kind: str, name: str, incident_note_name: str, incident_title: str, tenant_id: str = DEFAULT_TENANT
) -> None:
    """Create/update an Asset or IOC stub note that backlinks to this incident."""
    folder = "Assets" if kind == "Asset" else "IOCs"
    slug = _slugify(name)
    path = _safe_note_path(folder, f"{kind} - {slug}", tenant_id)

    # incident_note_name is already the slugified filename (safe as a link
    # target); incident_title is a raw description snippet — escape it.
    link_line = f"- [[{incident_note_name}]] — {_escape(incident_title)}"

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            existing = f.read()
        if link_line in existing:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(existing.rstrip("\n") + "\n" + link_line + "\n")
        return

    content = (
        f"---\ntags: [{kind.lower()}]\n---\n\n"
        f"# {kind}: {_escape(name)}\n\n"
        f"## Related Incidents\n{link_line}\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _update_index(folder: str, label: str, tenant_id: str = DEFAULT_TENANT) -> None:
    folder_path = os.path.join(_vault_root(tenant_id), folder)
    if not os.path.isdir(folder_path):
        return
    names = sorted(
        f[:-3] for f in os.listdir(folder_path) if f.endswith(".md") and f != "_Index.md"
    )
    lines = ["---\ntags: [index]\n---\n", f"# Cavendex {label} Index\n"]
    lines += [f"- [[{n}]]" for n in names] if names else ["_None yet._"]
    with open(os.path.join(folder_path, "_Index.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def write_incident_report(state, report_type: str = "incident") -> str:
    """Write/overwrite an incident's Markdown report in the Obsidian vault.

    Called after every pipeline run and every human approve/deny decision,
    so the note always reflects the latest state. Returns the path written
    (empty string if there was nothing to write).
    """
    if not state:
        return ""

    incident = state.get("incident")
    if incident is None:
        return ""

    tenant_id = sanitize_tenant_id(state.get("tenant_id"))

    _ensure_dirs(tenant_id)

    folder = "Hunts" if report_type == "hunt" else "Incidents"
    title_prefix = "Hunt" if report_type == "hunt" else "Incident"
    # incident.id ultimately reaches here from workflows/incident_pipeline.py
    # (normally a generated UUID, but that function accepts a caller-supplied
    # thread_id too) — slugify it for the filename rather than trusting it,
    # since any future caller that exposes thread_id externally would
    # otherwise hand an attacker direct control over a filesystem path.
    note_name = f"{title_prefix} - {_slugify(incident.id)}"
    path = _safe_note_path(folder, note_name, tenant_id)

    # Link targets must match the slugified filenames _write_stub_note()
    # actually creates — using the raw name here would both break link
    # resolution for any asset/IOC with special characters and leave raw
    # HTML unescaped inside the link text.
    asset_links = (
        "\n".join(f"- [[Asset - {_slugify(a)}]]" for a in incident.affected_assets) or "- none"
    )
    ioc_links = "\n".join(f"- [[IOC - {_slugify(i)}]]" for i in incident.iocs) or "- none"

    findings_sections = []
    for msg in state.get("messages", []) or []:
        agent_name, content = _message_agent_and_content(msg)
        findings_sections.append(f"### {_escape(agent_name)}\n{_escape(content)}")
    findings_text = "\n\n".join(findings_sections) or "_No agent findings yet._"

    proposed_actions = state.get("proposed_actions", []) or []
    if proposed_actions:
        lines = []
        for a in proposed_actions:
            action, target, rationale, approved = (
                _field(a, "action"), _field(a, "target"), _field(a, "rationale"), _field(a, "approved")
            )
            status = "approved" if approved is True else "denied" if approved is False else "pending approval"
            box = "x" if approved is True else " "
            lines.append(
                f"- [{box}] **{_escape(action)}** → `{_escape(target)}` — {_escape(rationale)} _({status})_"
            )
        actions_text = "\n".join(lines)
    else:
        actions_text = "_No actions proposed._"

    audit_text = (
        "\n".join(f"- {_escape(entry)}" for entry in state.get("audit_log", []) or []) or "_Empty._"
    )

    usage_text = _format_usage(state.get("token_usage"))
    threat_intel_text = _format_threat_intel(state.get("threat_intel"))
    attack_technique_text = _format_attack_technique(state.get("attack_technique"))

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # `source` is free text (CLI --source / API `source` field) — a colon
    # or newline in it would otherwise corrupt the YAML frontmatter block.
    # json.dumps() produces a double-quoted scalar that's valid YAML too.
    source_display = incident.source or "unknown"
    source_yaml = json.dumps(source_display)

    body = (
        "---\n"
        f"id: {json.dumps(incident.id)}\n"
        f"type: {report_type}\n"
        f"severity: {incident.severity}\n"
        f"status: {incident.status}\n"
        f"source: {source_yaml}\n"
        f"tenant: {json.dumps(tenant_id)}\n"
        f"updated: {generated_at}\n"
        f"tags: [cavendex, {report_type}]\n"
        "---\n\n"
        f"# {note_name}\n\n"
        f"**Severity:** {incident.severity}  \n"
        f"**Status:** {incident.status}  \n"
        f"**Source:** {_escape(source_display)}  \n"
        f"**Last updated:** {generated_at}\n\n"
        f"## Description\n{_escape(incident.description)}\n\n"
        f"## Affected Assets\n{asset_links}\n\n"
        f"## Indicators of Compromise\n{ioc_links}\n\n"
        f"## Agent Findings\n{findings_text}\n\n"
        f"## Threat Intelligence\n{threat_intel_text}\n\n"
        f"## ATT&CK Mapping\n{attack_technique_text}\n\n"
        f"## Proposed Actions\n{actions_text}\n\n"
        f"## Token Usage\n{usage_text}\n\n"
        f"## Audit Log\n{audit_text}\n"
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(body)

    for asset in incident.affected_assets:
        _write_stub_note("Asset", asset, note_name, incident.description[:80], tenant_id)
    for ioc in incident.iocs:
        _write_stub_note("IOC", ioc, note_name, incident.description[:80], tenant_id)

    _update_index(folder, title_prefix, tenant_id)

    return path
