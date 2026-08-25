"""A free, deterministic identity-based correlation tier — the middle
ground between ingestion/correlation.py's fuzzy signals (grounded in
attacker behavior, no external lookup needed) and
ingestion/semantic_correlation.py's LLM judgment (any relationship, at
the cost of a real call). This tier stays free and deterministic like
the fuzzy tier, but can catch what fuzzy correlation structurally cannot
— a renamed host, or a second-stage domain with no lexical relationship
to the first — by consulting an authoritative external identity source
instead of guessing from the string itself.

Why not just a smarter string-similarity metric? Already tried and
rejected, for exactly this reason — see ingestion/correlation.py's own
docstring: `SequenceMatcher` scores an unrelated same-fleet host
("FIN-SRV-03") *higher* than a genuine rename ("FIN-SRV-02-NEW"). No
threshold fixes a signal pointing the wrong direction half the time; the
fix is an authoritative answer, not a smarter guess.

Two independent signals, each degrading gracefully to "no match" when
unconfigured — the same contract as every other optional integration in
this project:

- **Asset identity** (free, checked whenever an inventory file is
  configured): a raw asset name is resolved to a canonical ID via an
  operator-supplied CMDB/inventory export (utils.asset_inventory). Two
  alerts naming differently-named assets that resolve to the same
  canonical ID are the same asset under a different name.
- **Domain identity** (opt-in via SENTINELOS_CORRELATION_IDENTITY_DNS_ENABLED,
  default off): real passive DNS via VirusTotal's domain-resolutions
  endpoint (enrichment.providers). Two lexically-unrelated domains that
  have both resolved to the same IP are plausibly the same C2
  infrastructure at a different stage. Opt-in and off by default because,
  unlike the asset signal, this spends a real rate-limited API call on
  every alert with a domain IOC, on top of whatever enrichment already
  spends checking that same domain's reputation — an operator with a
  tight VirusTotal free-tier quota shouldn't have it silently doubled.
"""

import os
from typing import List, Optional

from ingestion.correlation import recent_open_candidates
from ingestion.schemas import NormalizedAlert
from utils.asset_inventory import resolve_asset_identity


def _dns_identity_enabled() -> bool:
    return os.getenv("SENTINELOS_CORRELATION_IDENTITY_DNS_ENABLED", "false").strip().lower() in (
        "1",
        "true",
        "yes",
    )


def _first_asset_identity_match(alert_assets: List[str], candidates: List[dict]) -> Optional[dict]:
    alert_identities = {}
    for name in alert_assets:
        canonical = resolve_asset_identity(name)
        if canonical:
            alert_identities.setdefault(canonical, name)

    if not alert_identities:
        return None

    for candidate in candidates:
        for candidate_name in candidate.get("affected_assets") or []:
            canonical = resolve_asset_identity(candidate_name)
            if canonical and canonical in alert_identities:
                alert_name = alert_identities[canonical]
                return {
                    "thread_id": candidate["thread_id"],
                    "match_type": "identity_asset",
                    "reason": (
                        f"{alert_name!r} and {candidate_name!r} both resolve to "
                        f"inventory identity {canonical!r}"
                    ),
                }
    return None


def _first_domain_identity_match(alert_iocs: List[str], candidates: List[dict]) -> Optional[dict]:
    from enrichment.ioc_classifier import classify_ioc
    from enrichment.providers import lookup_domain_resolutions_virustotal

    alert_domains = [v for v in alert_iocs if classify_ioc(v) == "domain"]
    if not alert_domains:
        return None

    alert_ip_sets = {}
    for domain in alert_domains:
        ips = lookup_domain_resolutions_virustotal(domain)
        if ips:
            alert_ip_sets[domain] = set(ips)
    if not alert_ip_sets:
        return None

    for candidate in candidates:
        candidate_domains = [v for v in (candidate.get("iocs") or []) if classify_ioc(v) == "domain"]
        for c_domain in candidate_domains:
            c_ips = lookup_domain_resolutions_virustotal(c_domain)
            if not c_ips:
                continue
            c_ip_set = set(c_ips)
            for a_domain, a_ip_set in alert_ip_sets.items():
                shared = a_ip_set & c_ip_set
                if shared:
                    return {
                        "thread_id": candidate["thread_id"],
                        "match_type": "identity_domain",
                        "reason": (
                            f"{a_domain!r} and {c_domain!r} have both resolved to "
                            f"{next(iter(shared))!r} per passive DNS"
                        ),
                    }
    return None


def find_identity_correlation(
    tenant_id: str, alert: NormalizedAlert, candidates: Optional[List[dict]] = None
) -> Optional[dict]:
    """Look for an identity-based match for `alert` among this tenant's
    open incidents. Returns `{"thread_id", "match_type", "reason"}` — the
    same shape ingestion/correlation.py's tiers return — or `None`.
    Asset identity is checked first (free); domain identity is only
    checked if explicitly enabled, since it spends a real API call.

    `candidates`, when given, skips the recent-open-incidents lookup —
    the same test/reuse seam ingestion/semantic_correlation.py exposes.
    """
    alert_assets = list(dict.fromkeys(alert.affected_assets))
    alert_iocs = list(dict.fromkeys(alert.iocs))
    if not alert_assets and not alert_iocs:
        return None

    pool = recent_open_candidates(tenant_id) if candidates is None else candidates
    if not pool:
        return None

    asset_match = _first_asset_identity_match(alert_assets, pool)
    if asset_match:
        return asset_match

    if _dns_identity_enabled():
        return _first_domain_identity_match(alert_iocs, pool)

    return None
