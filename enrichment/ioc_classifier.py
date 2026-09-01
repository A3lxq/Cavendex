"""Classifies a free-text IOC string as ip/domain/hash/url/cve/process/
cmdline/parent_process/unknown so the enrichment pipeline knows which
provider(s), if any, can look it up.

Most "IOCs" an LLM proposes are actually descriptive phrases ("Suricata
rule ID and payload signature indicating banner-grabbing behavior") —
those are correctly classified as "unknown" and never sent to an external
API; only real lookupable indicators cost an API call.

process/cmdline/parent_process are the one exception to this module's own
"classify from the bare string" approach: a raw process name
("svchost.exe") or command line has no fixed grammar that reliably tells
it apart from an ordinary hostname or descriptive phrase, so these are
recognized only by the explicit `process:`/`cmdline:`/`parent:` prefix
ingestion/schemas.py:NormalizedAlert applies when a normalizer supplies
that EDR-native context — never inferred from an unprefixed string. No
threat-intel provider answers a lookup for these today (they're not
ip/domain/hash/url/cve), so they classify distinctly from "unknown"
purely so correlation/the dashboard can label them correctly, not to
route them to enrichment.
"""

import ipaddress
import re

_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

_PREFIX_TYPES = {
    "process:": "process",
    "cmdline:": "cmdline",
    "parent:": "parent_process",
}


def classify_ioc(value: str) -> str:
    value = value.strip()

    for prefix, ioc_type in _PREFIX_TYPES.items():
        if value.startswith(prefix) and len(value) > len(prefix):
            return ioc_type

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if _CVE_RE.match(value):
        return "cve"

    if value.lower().startswith(("http://", "https://")):
        return "url"

    if _HEX_RE.match(value) and len(value) in _HASH_LENGTHS:
        return "hash"

    if _DOMAIN_RE.match(value):
        last_label = value.rsplit(".", 1)[-1]
        if not last_label.isdigit():  # real TLDs are never all-digit
            return "domain"

    return "unknown"
