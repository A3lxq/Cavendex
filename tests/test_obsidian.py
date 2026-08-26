import os

import yaml

from state import Incident, ProposedAction
from utils.obsidian import _escape, _slugify, write_incident_report


def test_slugify_replaces_unsafe_chars():
    assert _slugify("a/b:c*d") == "a-b-c-d"


def test_slugify_empty_becomes_untitled():
    assert _slugify("   ") == "untitled"


def _fake_state():
    incident = Incident(
        id="test-incident-1",
        description="Suspicious login activity",
        severity="high",
        status="pending_approval",
        affected_assets=["WEB-SRV-01"],
        iocs=["1.2.3.4"],
        source="SIEM",
    )
    return {
        "messages": [
            {"role": "assistant", "name": "Triage Agent", "content": "High severity, escalate."}
        ],
        "incident": incident,
        "long_term_summary": "",
        "audit_log": ["Triage Agent -> severity=high, decision=escalate_to_investigation"],
        "next_agent": None,
        "proposed_actions": [
            ProposedAction(action="Block IP", target="1.2.3.4", rationale="malicious", approved=None)
        ],
    }


def test_write_incident_report_creates_linked_notes(tmp_path, monkeypatch):
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(tmp_path))

    path = write_incident_report(_fake_state())

    assert os.path.exists(path)
    content = open(path, encoding="utf-8").read()

    assert "[[Asset - WEB-SRV-01]]" in content
    assert "[[IOC - 1.2.3.4]]" in content
    assert "Block IP" in content
    assert "pending approval" in content

    # No tenant_id set on the fake state -> the "default" tenant subfolder.
    tenant_root = tmp_path / "default"

    asset_note = tenant_root / "Assets" / "Asset - WEB-SRV-01.md"
    assert asset_note.exists()
    assert "[[Incident - test-incident-1]]" in asset_note.read_text(encoding="utf-8")

    ioc_note = tenant_root / "IOCs" / "IOC - 1.2.3.4.md"
    assert ioc_note.exists()
    assert "[[Incident - test-incident-1]]" in ioc_note.read_text(encoding="utf-8")

    index_note = tenant_root / "Incidents" / "_Index.md"
    assert index_note.exists()
    assert "[[Incident - test-incident-1]]" in index_note.read_text(encoding="utf-8")


def test_write_incident_report_isolates_tenants(tmp_path, monkeypatch):
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(tmp_path))

    state_a = _fake_state()
    state_a["tenant_id"] = "tenant-a"
    state_b = _fake_state()
    state_b["tenant_id"] = "tenant-b"

    path_a = write_incident_report(state_a)
    path_b = write_incident_report(state_b)

    assert path_a != path_b
    assert "tenant-a" in path_a
    assert "tenant-b" in path_b
    assert os.path.exists(path_a)
    assert os.path.exists(path_b)


def test_write_incident_report_handles_missing_incident():
    assert write_incident_report({"incident": None}) == ""
    assert write_incident_report(None) == ""


def test_escape_neutralizes_embedded_newlines():
    """Security regression: content meant to render as one Markdown
    line (an audit_log entry, a name, a description) must not be able
    to break out of it via an embedded newline and inject new Markdown
    structure (a fake bullet, a fake heading, a misleading line)."""
    assert "\n" not in _escape("line one\nline two")
    assert "\r" not in _escape("line one\r\nline two")


def test_escape_still_neutralizes_html():
    assert "<script>" not in _escape("<script>alert(1)</script>")


def test_audit_log_entry_with_embedded_newline_cannot_inject_a_fake_bullet(tmp_path, monkeypatch):
    """Security regression: an audit_log entry containing a newline
    (e.g. from an externally-influenced approved_by/description/source
    value folded into it) must render as a single bullet line in the
    vault report, never as multiple lines -- which would let it inject
    an arbitrary extra Markdown line (a fake bullet, a fake heading)
    that reads as if it came from SentinelOS itself."""
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(tmp_path))

    state = _fake_state()
    state["audit_log"] = [
        "Human Reviewer (j.smith) -> approved 1 proposed action(s)\n- **FAKE INJECTED BULLET** — not a real entry"
    ]
    path = write_incident_report(state)
    content = open(path, encoding="utf-8").read()

    # The injected content must appear (harmlessly, as literal text within
    # the one legitimate bullet), but never as its OWN separate bullet line.
    assert "\n- **FAKE INJECTED BULLET**" not in content


def test_path_traversal_in_incident_id_is_contained(tmp_path, monkeypatch):
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(tmp_path))

    for payload in ["../../../../tmp/pwned", "/etc/passwd", "x/../../../../../../etc/passwd"]:
        state = _fake_state()
        state["incident"] = state["incident"].model_copy(update={"id": payload})
        path = write_incident_report(state)
        root = os.path.abspath(str(tmp_path))
        assert os.path.commonpath([root, os.path.abspath(path)]) == root


def test_html_in_description_and_findings_is_escaped(tmp_path, monkeypatch):
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(tmp_path))

    payload = '<img src=x onerror="fetch(1)"><iframe src="http://attacker.example"></iframe>'
    state = _fake_state()
    state["incident"] = state["incident"].model_copy(update={"description": payload})
    state["messages"] = [{"role": "assistant", "name": "Triage Agent", "content": payload}]
    state["audit_log"] = [f"Triage Agent -> {payload}"]

    content = open(write_incident_report(state), encoding="utf-8").read()

    assert "<img src=x" not in content
    assert "<iframe src=" not in content
    assert "&lt;img" in content


def test_yaml_frontmatter_stays_valid_with_special_characters(tmp_path, monkeypatch):
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(tmp_path))

    state = _fake_state()
    state["incident"] = state["incident"].model_copy(
        update={"source": "SIEM: weird source; a: b\nand a newline"}
    )

    content = open(write_incident_report(state), encoding="utf-8").read()
    frontmatter = content.split("---")[1]
    parsed = yaml.safe_load(frontmatter)  # raises if the frontmatter is malformed
    assert parsed["source"] == "SIEM: weird source; a: b\nand a newline"
