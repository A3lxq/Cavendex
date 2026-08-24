"""A curated, offline snapshot of common MITRE ATT&CK Enterprise
techniques — NOT the full framework (hundreds of techniques and
sub-techniques), and NOT live-synced with MITRE's database. It exists to
catch one specific, real failure mode: an LLM confidently citing a
technique ID that doesn't actually exist. A cited ID is looked up here;
if it isn't found, that's flagged as unverified rather than silently
trusted. That does NOT prove the technique is fake — only that it isn't
in this curated ~65-technique subset (covering one or two well-known
techniques per tactic across the full kill chain) or was invented. For
the authoritative, complete, always-current framework, see
https://attack.mitre.org/.
"""

import re
from typing import Optional

# Extracts just the ID token even when a model appends the name inline
# (observed live: "T1110 - Brute Force" instead of a clean "T1110") —
# without this, that's an incorrectly-flagged false negative, not a real
# hallucination, since the underlying citation was actually correct.
_TECHNIQUE_ID_PATTERN = re.compile(r"(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)

_TECHNIQUES = {
    # Reconnaissance
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
    "T1589": {"name": "Gather Victim Identity Information", "tactic": "Reconnaissance"},
    "T1590": {"name": "Gather Victim Network Information", "tactic": "Reconnaissance"},
    "T1598": {"name": "Phishing for Information", "tactic": "Reconnaissance"},
    # Resource Development
    "T1583": {"name": "Acquire Infrastructure", "tactic": "Resource Development"},
    "T1586": {"name": "Compromise Accounts", "tactic": "Resource Development"},
    "T1587": {"name": "Develop Capabilities", "tactic": "Resource Development"},
    "T1588": {"name": "Obtain Capabilities", "tactic": "Resource Development"},
    # Initial Access
    "T1189": {"name": "Drive-by Compromise", "tactic": "Initial Access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access"},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution"},
    "T1204": {"name": "User Execution", "tactic": "Execution"},
    # Persistence
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1136": {"name": "Create Account", "tactic": "Persistence"},
    # Privilege Escalation
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "T1055": {"name": "Process Injection", "tactic": "Privilege Escalation"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    # Defense Evasion
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion"},
    # Credential Access
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.001": {"name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "T1110.002": {"name": "Brute Force: Password Cracking", "tactic": "Credential Access"},
    "T1110.003": {"name": "Brute Force: Password Spraying", "tactic": "Credential Access"},
    "T1110.004": {"name": "Brute Force: Credential Stuffing", "tactic": "Credential Access"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
    "T1556": {"name": "Modify Authentication Process", "tactic": "Credential Access"},
    "T1621": {"name": "Multi-Factor Authentication Request Generation", "tactic": "Credential Access"},
    # Discovery
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": "Discovery"},
    "T1049": {"name": "System Network Connections Discovery", "tactic": "Discovery"},
    "T1518": {"name": "Software Discovery", "tactic": "Discovery"},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.001": {"name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "T1021.002": {"name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1021.004": {"name": "Remote Services: SSH", "tactic": "Lateral Movement"},
    "T1080": {"name": "Taint Shared Content", "tactic": "Lateral Movement"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "Lateral Movement"},
    # Collection
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection"},
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},
    "T1114": {"name": "Email Collection", "tactic": "Collection"},
    # Command and Control
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1219": {"name": "Remote Access Software", "tactic": "Command and Control"},
    "T1090": {"name": "Proxy", "tactic": "Command and Control"},
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control"},
    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1489": {"name": "Service Stop", "tactic": "Impact"},
    "T1485": {"name": "Data Destruction", "tactic": "Impact"},
    "T1498": {"name": "Network Denial of Service", "tactic": "Impact"},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact"},
}


def _extract_technique_id(raw: str) -> Optional[str]:
    match = _TECHNIQUE_ID_PATTERN.search(raw)
    return match.group(1).upper() if match else None


def lookup_technique(technique_id: Optional[str]) -> Optional[dict]:
    """Look up a technique ID in the curated dataset. Tolerant of a model
    appending the name inline (e.g. "T1110 - Brute Force") — only the
    T#### / T####.### token is actually matched. Falls back to the parent
    technique if a cited sub-technique isn't separately listed — the
    parent's tactic/name context still holds. Returns None if nothing
    matches at all.
    """
    if not technique_id:
        return None

    extracted = _extract_technique_id(technique_id.strip())
    if extracted is None:
        return None
    base_id = extracted.split(".")[0]

    entry = _TECHNIQUES.get(extracted) or _TECHNIQUES.get(base_id)
    if entry is None:
        return None
    return {"id": extracted, "name": entry["name"], "tactic": entry["tactic"]}


def validate_technique_citation(technique_id: Optional[str]) -> Optional[dict]:
    """Given a technique ID an agent cited, return a dict describing
    whether it matched this curated dataset — always a dict (never None)
    if a non-empty ID was cited, so the caller can render "verified" vs
    "not recognized in our curated dataset" either way. Returns None only
    if the agent didn't cite a technique at all.
    """
    if not technique_id or not technique_id.strip():
        return None

    match = lookup_technique(technique_id)
    if match is not None:
        return {**match, "verified": True}

    # No dataset match — still prefer a cleanly-extracted ID token over the
    # raw citation for display, if one was present (e.g. "T9999 - Made Up
    # Technique" should surface as "T9999", not the whole phrase).
    extracted = _extract_technique_id(technique_id.strip())
    display_id = extracted or technique_id.strip().upper()
    return {"id": display_id, "name": None, "tactic": None, "verified": False}
