"""Classifies a free-text IOC string as ip/domain/hash/unknown so the
enrichment pipeline knows which provider(s), if any, can look it up.

Most "IOCs" an LLM proposes are actually descriptive phrases ("Suricata
rule ID and payload signature indicating banner-grabbing behavior") —
those are correctly classified as "unknown" and never sent to an external
API; only real lookupable indicators cost an API call.
"""

import ipaddress
import re

_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


def classify_ioc(value: str) -> str:
    value = value.strip()

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if _HEX_RE.match(value) and len(value) in _HASH_LENGTHS:
        return "hash"

    if _DOMAIN_RE.match(value):
        last_label = value.rsplit(".", 1)[-1]
        if not last_label.isdigit():  # real TLDs are never all-digit
            return "domain"

    return "unknown"
