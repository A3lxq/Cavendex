"""Combines IOC classification with the available provider lookups. This
is what agents actually call: hand it a list of raw IOC strings, get back
real, verified evidence for the ones that are lookupable — anything
classified "unknown" (most LLM-proposed "IOCs" are descriptive phrases,
not real indicators) is skipped and never costs an API call, and a
disabled/unconfigured provider (no API key, or — for Shodan specifically,
which needs none — CAVENDEX_SHODAN_ENABLED left off) is silently
skipped too.
"""

import os
from concurrent.futures import ThreadPoolExecutor
from typing import List

from enrichment.ioc_classifier import classify_ioc
from enrichment.providers import (
    lookup_domain_metadefender,
    lookup_domain_otx,
    lookup_domain_threatfox,
    lookup_domain_virustotal,
    lookup_hash_malwarebazaar,
    lookup_hash_metadefender,
    lookup_hash_otx,
    lookup_hash_threatfox,
    lookup_hash_virustotal,
    lookup_hash_xforce,
    lookup_ip_abuseipdb,
    lookup_ip_censys,
    lookup_ip_greynoise,
    lookup_ip_metadefender,
    lookup_ip_otx,
    lookup_ip_shodan,
    lookup_ip_threatfox,
    lookup_ip_virustotal,
    lookup_ip_xforce,
    lookup_url_metadefender,
    lookup_url_threatfox,
    lookup_url_urlhaus,
    lookup_url_xforce,
)
from enrichment.schemas import EnrichmentResult

# Every provider capable of looking up a given IOC type, by *name* (not
# direct function reference) — resolved fresh via globals() on every
# enrich_iocs() call (see _dispatch_for) rather than captured once at
# import time, so tests that monkeypatch e.g.
# "enrichment.pipeline.lookup_ip_abuseipdb" (this module's existing,
# established test convention) still take effect. Order matters only as
# a tie-break for which providers get skipped once the per-incident cap
# below is nearly exhausted (see enrich_iocs).
_DISPATCH_NAMES = {
    "ip": (
        "lookup_ip_abuseipdb", "lookup_ip_virustotal", "lookup_ip_shodan",
        "lookup_ip_otx", "lookup_ip_greynoise", "lookup_ip_xforce",
        "lookup_ip_metadefender", "lookup_ip_censys",
    ),
    "domain": ("lookup_domain_virustotal", "lookup_domain_otx", "lookup_domain_threatfox", "lookup_domain_metadefender"),
    "hash": (
        "lookup_hash_virustotal", "lookup_hash_otx", "lookup_hash_malwarebazaar",
        "lookup_hash_threatfox", "lookup_hash_xforce", "lookup_hash_metadefender",
    ),
    "url": ("lookup_url_threatfox", "lookup_url_urlhaus", "lookup_url_xforce", "lookup_url_metadefender"),
}

# Widest fan-out any single IOC type can trigger today — bounds the
# thread pool so a busy incident can't spawn an unbounded number of
# worker threads.
_MAX_WORKERS = max(len(v) for v in _DISPATCH_NAMES.values())


def _dispatch_for(kind: str):
    names = _DISPATCH_NAMES.get(kind)
    if not names:
        return None
    return [globals()[name] for name in names]

_DEFAULT_MAX_LOOKUPS_PER_INCIDENT = 30


def _max_lookups_per_incident() -> int:
    try:
        return int(os.getenv("CAVENDEX_ENRICHMENT_MAX_LOOKUPS_PER_INCIDENT", str(_DEFAULT_MAX_LOOKUPS_PER_INCIDENT)))
    except ValueError:
        return _DEFAULT_MAX_LOOKUPS_PER_INCIDENT


def enrich_iocs(iocs: List[str]) -> List[EnrichmentResult]:
    """Real, verified evidence for every lookupable IOC in `iocs`, fanned
    out to every provider that supports its type in parallel (a wider
    fan-out — up to 8 providers for one IP — would otherwise multiply
    Triage's latency several-fold if done sequentially).

    The per-incident cap (CAVENDEX_ENRICHMENT_MAX_LOOKUPS_PER_INCIDENT,
    default 30) bounds actual outbound lookup *attempts*, not just
    results appended — each IOC's provider list is sliced down to
    whatever budget remains before any of them are dispatched. This
    matters for more than cost/latency: an alert with many fabricated-
    looking IOCs (attacker- or LLM-influenced input, the same untrusted-
    input class this project already treats carefully for prompt
    injection) must never be able to turn a wide provider fan-out into
    an effectively unbounded number of real third-party requests. A
    later IOC may honestly get fewer providers checked than an earlier
    one once the budget is nearly spent — a real, bounded tradeoff, not
    a silent one.
    """
    results: List[EnrichmentResult] = []
    cap = _max_lookups_per_incident()

    for ioc in iocs:
        remaining = cap - len(results)
        if remaining <= 0:
            break

        kind = classify_ioc(ioc)
        lookups = _dispatch_for(kind)
        if not lookups:
            continue  # "unknown" -> not a real lookupable indicator.

        lookups = lookups[:remaining]
        with ThreadPoolExecutor(max_workers=min(len(lookups), _MAX_WORKERS)) as executor:
            futures = [executor.submit(lookup, ioc) for lookup in lookups]
            for future in futures:
                result = future.result()
                if result is not None:
                    results.append(result)

    return results


def format_for_prompt(results: List[EnrichmentResult]) -> str:
    if not results:
        return (
            "No verified threat-intel lookups available — no IOCs matched a "
            "lookupable type, or no provider API key is configured for any "
            "matching IOC type (see README's \"Adding a Threat-Intel "
            "Provider\" section for the full list of supported providers "
            "and their env vars)."
        )
    lines = [
        f"- [{r.source}] {r.indicator} ({r.indicator_type}): {r.verdict} — {r.detail}"
        for r in results
    ]
    return "\n".join(lines)
