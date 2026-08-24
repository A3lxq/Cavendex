"""Combines IOC classification with the available provider lookups. This
is what agents actually call: hand it a list of raw IOC strings, get back
real, verified evidence for the ones that are lookupable — anything
classified "unknown" (most LLM-proposed "IOCs" are descriptive phrases,
not real indicators) is skipped and never costs an API call, and a
disabled/unconfigured provider (no API key, or — for Shodan specifically,
which needs none — SENTINELOS_SHODAN_ENABLED left off) is silently
skipped too.
"""

from typing import List

from enrichment.ioc_classifier import classify_ioc
from enrichment.providers import (
    lookup_domain_virustotal,
    lookup_hash_virustotal,
    lookup_ip_abuseipdb,
    lookup_ip_shodan,
    lookup_ip_virustotal,
)
from enrichment.schemas import EnrichmentResult

# Bounds real API calls per incident regardless of how many IOCs an
# LLM lists — a runaway list shouldn't translate into a runaway number
# of external requests (cost, latency, and free-tier quota all care).
_MAX_LOOKUPS_PER_INCIDENT = 10


def enrich_iocs(iocs: List[str]) -> List[EnrichmentResult]:
    results: List[EnrichmentResult] = []

    for ioc in iocs:
        if len(results) >= _MAX_LOOKUPS_PER_INCIDENT:
            break

        kind = classify_ioc(ioc)
        if kind == "ip":
            for lookup in (lookup_ip_abuseipdb, lookup_ip_virustotal, lookup_ip_shodan):
                result = lookup(ioc)
                if result is not None:
                    results.append(result)
        elif kind == "domain":
            result = lookup_domain_virustotal(ioc)
            if result is not None:
                results.append(result)
        elif kind == "hash":
            result = lookup_hash_virustotal(ioc)
            if result is not None:
                results.append(result)
        # "unknown" -> not a real lookupable indicator, skip entirely.

    return results


def format_for_prompt(results: List[EnrichmentResult]) -> str:
    if not results:
        return (
            "No verified threat-intel lookups available (no IOCs matched a "
            "lookupable type, no provider API key is configured — see "
            "ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY — or Shodan enrichment "
            "isn't enabled — see SENTINELOS_SHODAN_ENABLED)."
        )
    lines = [
        f"- [{r.source}] {r.indicator} ({r.indicator_type}): {r.verdict} — {r.detail}"
        for r in results
    ]
    return "\n".join(lines)
