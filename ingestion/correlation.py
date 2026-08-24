"""Groups a new alert into an existing open incident when it's plainly the
same story, instead of always spawning a new incident.

utils/dedup.py catches exact repeats of the same dedup_key — the same
signature firing on the same source over and over. That's not the same
problem as a NIDS port-scan alert against 10.0.0.5 followed ten minutes
later by an EDR brute-force alert against the same host (different
signature, different dedup_key, same story), and it's also not the same
problem as an attacker rotating through 10.0.0.5, 10.0.0.9, 10.0.0.14 from
the same /24 while scanning, or standing up cdn.evil-c2.com after
mail.evil-c2.com got flagged. This module handles both:

- **Exact tier** — the new alert shares an identical IOC or affected asset
  string with an open incident. Cheapest, most confident, checked first.
- **Fuzzy tier** — only checked if nothing matched exactly. Two signals,
  each grounded in a real attacker behavior pattern rather than generic
  string similarity:
  - *Subnet*: two IPs in the same /24 (IPv4) or /64 (IPv6) — rotating
    source IPs from one attacker-controlled range is a textbook evasion
    of exact-IP dedup/correlation.
  - *Domain family*: two domains sharing a registered (apex) domain, per
    the real Mozilla Public Suffix List (so 'foo.co.uk' and 'bar.co.uk'
    are correctly treated as unrelated, not grouped by a naive
    last-two-labels split) — C2 infrastructure reusing one domain across
    subdomains is equally textbook.

A third fuzzy signal — string-similarity on affected-asset *names*
("FIN-SRV-02" vs "FIN-SRV-02-NEW") — was deliberately left out after
testing it: `SequenceMatcher("FIN-SRV-02", "FIN-SRV-03").ratio()` (a
different host in a sequentially-numbered fleet) scores *higher* (0.90)
than `SequenceMatcher("FIN-SRV-02", "FIN-SRV-02-NEW").ratio()` (an actual
rename, 0.83). Any threshold that catches the rename also catches every
adjacent host in any numbered fleet — which is a far more common naming
convention than the rename case it was meant to catch. That's not a
tunable false-positive rate, it's the signal pointing the wrong direction
half the time; shipping it would make correlation actively worse than
exact-only. See Known Gaps in README for what this still doesn't cover.

Both fuzzy signals are deliberately narrow, deterministic, and only ever
kick in when nothing correlates exactly — the same "cheap gate in front
of the expensive one" philosophy as the rest of ingestion/pipeline.py,
not semantic/ML clustering. Every match — exact or fuzzy — returns a
human-readable reason string, because a fuzzy correlation is a real
(if smaller) false-positive risk and an analyst needs to see why two
alerts were merged, not just that they were.

A third tier — genuine semantic/behavioral matching (a shared MITRE
ATT&CK technique with no shared IOC at all, or a renamed host with no
lexical relationship to its old name) — lives in
`ingestion/semantic_correlation.py`, not here, because it needs an LLM
call and therefore has a fundamentally different cost and reliability
profile than the free, deterministic tiers in this file. It reuses
`recent_open_candidates()` below as its own candidate pool.
"""

import ipaddress
import os
from datetime import datetime, timezone
from typing import List, Optional

import tldextract

from enrichment.ioc_classifier import classify_ioc
from ingestion.schemas import NormalizedAlert
from utils.incident_index import list_open_incidents
from utils.tenancy import DEFAULT_TENANT

_IPV6_GROUPING_PREFIX = 64

# suffix_list_urls=() disables any live fetch of the Mozilla Public
# Suffix List — this tool has to work in an air-gapped/network-restricted
# deployment (see the dashboard's no-CDN design for the same reasoning),
# so domain-family matching falls back to the snapshot bundled inside the
# tldextract package itself. cache_dir=None additionally disables writing
# a local cache file, so this needs no filesystem access either — a
# point-in-time snapshot from whenever this tldextract version was
# released, not live-synced with publicsuffix.org, is the accepted
# tradeoff (the same "curated, not live" choice this project already
# makes for enrichment/mitre_attack.py's ATT&CK dataset).
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def _window_seconds() -> float:
    try:
        return float(os.getenv("SENTINELOS_CORRELATION_WINDOW_SECONDS", "3600"))
    except ValueError:
        return 3600.0


def _fuzzy_enabled() -> bool:
    return os.getenv("SENTINELOS_CORRELATION_FUZZY_ENABLED", "true").strip().lower() not in (
        "0",
        "false",
        "no",
    )


def _subnet_prefix_bits() -> int:
    try:
        bits = int(os.getenv("SENTINELOS_CORRELATION_SUBNET_PREFIX_BITS", "24"))
    except ValueError:
        return 24
    return min(max(bits, 1), 32)


def _network_for(ip_str: str, prefix_bits: int):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    prefix = prefix_bits if addr.version == 4 else _IPV6_GROUPING_PREFIX
    return ipaddress.ip_network(f"{addr}/{prefix}", strict=False)


def _registered_domain(domain: str) -> str:
    """The registered/apex domain per the real Public Suffix List — e.g.
    'cdn.evil-c2.com' -> 'evil-c2.com', and, correctly, 'foo.co.uk' and
    'bar.co.uk' -> two different registered domains, not the same one a
    naive last-two-labels split would produce. Falls back to the
    lowercased input for anything the PSL doesn't recognize as having a
    public suffix at all (e.g. a bare IP or single-label hostname) —
    should never actually happen here, since callers only ever pass
    values `enrichment.ioc_classifier.classify_ioc` already classified as
    "domain," but a safe, unsurprising fallback costs nothing.
    """
    normalized = domain.lower().strip(".")
    registered = _TLD_EXTRACTOR(normalized).top_domain_under_public_suffix
    return registered or normalized


def _within_window(candidate: dict, now: datetime, window: float) -> bool:
    updated_at = candidate.get("updated_at")
    if not updated_at:
        return False
    try:
        last_seen = datetime.fromisoformat(updated_at)
    except ValueError:
        return False
    return (now - last_seen).total_seconds() <= window


def recent_open_candidates(tenant_id: str, window_seconds: Optional[float] = None) -> List[dict]:
    """Open incidents for `tenant_id`, updated within the correlation
    window — the shared candidate pool every correlation tier (exact,
    fuzzy, and the semantic tier in ingestion/semantic_correlation.py)
    starts from, so "is this incident recent enough to plausibly still be
    the same story" is answered exactly once, the same way, everywhere.

    Defaults to SENTINELOS_CORRELATION_WINDOW_SECONDS if `window_seconds`
    isn't given; a window of 0 (or negative) returns no candidates at all.
    """
    window = _window_seconds() if window_seconds is None else window_seconds
    if window <= 0:
        return []
    now = datetime.now(timezone.utc)
    return [c for c in list_open_incidents(tenant_id or DEFAULT_TENANT) if _within_window(c, now, window)]


def _first_exact_match(alert_iocs: List[str], alert_assets: List[str], candidates: List[dict]) -> Optional[dict]:
    alert_ioc_set = set(alert_iocs)
    alert_asset_set = set(alert_assets)
    for candidate in candidates:
        shared_iocs = alert_ioc_set & set(candidate.get("iocs") or [])
        if shared_iocs:
            return {
                "thread_id": candidate["thread_id"],
                "match_type": "exact_ioc",
                "reason": f"shares IOC {next(iter(shared_iocs))!r}",
            }
        shared_assets = alert_asset_set & set(candidate.get("affected_assets") or [])
        if shared_assets:
            return {
                "thread_id": candidate["thread_id"],
                "match_type": "exact_asset",
                "reason": f"shares affected asset {next(iter(shared_assets))!r}",
            }
    return None


def _first_fuzzy_match(alert_iocs: List[str], candidates: List[dict]) -> Optional[dict]:
    prefix_bits = _subnet_prefix_bits()
    alert_ips = [v for v in alert_iocs if classify_ioc(v) == "ip"]
    alert_domains = [v for v in alert_iocs if classify_ioc(v) == "domain"]
    if not alert_ips and not alert_domains:
        return None

    for candidate in candidates:
        candidate_iocs = candidate.get("iocs") or []
        candidate_ips = [v for v in candidate_iocs if classify_ioc(v) == "ip"]
        candidate_domains = [v for v in candidate_iocs if classify_ioc(v) == "domain"]

        for a_ip in alert_ips:
            a_net = _network_for(a_ip, prefix_bits)
            if a_net is None:
                continue
            for c_ip in candidate_ips:
                if _network_for(c_ip, prefix_bits) == a_net:
                    return {
                        "thread_id": candidate["thread_id"],
                        "match_type": "subnet",
                        "reason": f"{a_ip!r} and {c_ip!r} are both in {a_net}",
                    }

        for a_dom in alert_domains:
            a_reg = _registered_domain(a_dom)
            for c_dom in candidate_domains:
                if _registered_domain(c_dom) == a_reg:
                    return {
                        "thread_id": candidate["thread_id"],
                        "match_type": "domain_family",
                        "reason": f"{a_dom!r} and {c_dom!r} share registered domain {a_reg!r}",
                    }

    return None


def find_correlated_incident(tenant_id: str, alert: NormalizedAlert) -> Optional[dict]:
    """Find the best-matching open incident for `alert`, or None.

    Returns {"thread_id": str, "match_type": str, "reason": str} — never
    just a bare thread_id, since a fuzzy match especially needs its reason
    surfaced to an analyst (see the audit-log entry merge_correlated_alert
    writes). Exact matches (identical IOC/asset string) are always
    preferred over fuzzy ones (subnet/domain-family); within each tier,
    the most recently updated open incident wins, since candidates come
    back from utils.incident_index.list_open_incidents sorted that way.

    A window of 0 (or negative) disables correlation entirely.
    SENTINELOS_CORRELATION_FUZZY_ENABLED=false disables the fuzzy tier
    only, leaving exact matching active.
    """
    alert_iocs = list(dict.fromkeys(alert.iocs))
    alert_assets = list(dict.fromkeys(alert.affected_assets))
    if not alert_iocs and not alert_assets:
        return None

    candidates = recent_open_candidates(tenant_id)
    if not candidates:
        return None

    exact = _first_exact_match(alert_iocs, alert_assets, candidates)
    if exact:
        return exact

    if not _fuzzy_enabled():
        return None

    return _first_fuzzy_match(alert_iocs, candidates)
