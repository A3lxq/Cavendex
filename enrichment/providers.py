"""Real threat-intel provider lookups — AbuseIPDB (IP reputation),
VirusTotal (IP/domain/hash reputation), and Shodan (exposed-service data
via the free InternetDB endpoint). Every function here follows the same
contract as the rest of this project's external-dependency code
(utils/llm.py's provider fallback, ingestion's normalizers): never raise
into the caller, return None when a lookup can't be answered (disabled,
no API key configured, the provider errored, the network is unreachable),
so a missing/broken threat-intel key degrades an incident's context
instead of crashing the pipeline.

Results are cached in-process for CACHE_TTL_SECONDS — free-tier quotas are
tight (VirusTotal: 4 requests/minute) and the same IOC is looked up again
every time an incident revisits it (e.g. Investigator re-checking what
Triage already checked).
"""

import os
import threading
import time
from typing import Optional

from enrichment.schemas import EnrichmentResult

_CACHE_TTL_SECONDS = 3600.0
_cache_lock = threading.Lock()
_cache: dict = {}


def _cache_get(key) -> Optional[EnrichmentResult]:
    with _cache_lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        result, cached_at = entry
        if time.monotonic() - cached_at > _CACHE_TTL_SECONDS:
            del _cache[key]
            return None
        return result


def _cache_set(key, result: EnrichmentResult) -> None:
    with _cache_lock:
        _cache[key] = (result, time.monotonic())


def lookup_ip_abuseipdb(ip: str) -> Optional[EnrichmentResult]:
    """AbuseIPDB IP reputation. Requires ABUSEIPDB_API_KEY. Returns None
    if no key is configured, or an "error" verdict result (not None) if
    the key is present but the request itself failed — that distinction
    matters for the vault: "not checked" reads very differently from
    "checked and it errored."
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return None

    cache_key = ("abuseipdb", ip)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    import requests

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=10,
        )
    except requests.RequestException as exc:
        return EnrichmentResult(
            indicator=ip, indicator_type="ip", source="abuseipdb", verdict="error",
            detail=f"Request failed: {exc}",
        )

    if response.status_code != 200:
        return EnrichmentResult(
            indicator=ip, indicator_type="ip", source="abuseipdb", verdict="error",
            detail=f"HTTP {response.status_code}: {response.text[:300]}",
        )

    data = (response.json() or {}).get("data") or {}
    score = data.get("abuseConfidenceScore", 0)
    total_reports = data.get("totalReports", 0)
    verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "harmless"

    result = EnrichmentResult(
        indicator=ip,
        indicator_type="ip",
        source="abuseipdb",
        verdict=verdict,
        detail=(
            f"Abuse confidence score {score}/100 across {total_reports} report(s). "
            f"Country: {data.get('countryCode', 'unknown')}. "
            f"ISP: {data.get('isp', 'unknown')}."
        ),
        link=f"https://www.abuseipdb.com/check/{ip}",
    )
    _cache_set(cache_key, result)
    return result


_VT_VERDICT_ENDPOINT = {
    "ip": "https://www.virustotal.com/api/v3/ip_addresses/{}",
    "domain": "https://www.virustotal.com/api/v3/domains/{}",
    "hash": "https://www.virustotal.com/api/v3/files/{}",
}


def _lookup_virustotal(indicator: str, indicator_type: str) -> Optional[EnrichmentResult]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None

    cache_key = ("virustotal", indicator)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    import requests

    url = _VT_VERDICT_ENDPOINT[indicator_type].format(indicator)
    try:
        response = requests.get(url, headers={"x-apikey": api_key}, timeout=10)
    except requests.RequestException as exc:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="virustotal",
            verdict="error", detail=f"Request failed: {exc}",
        )

    if response.status_code == 404:
        result = EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="virustotal",
            verdict="unknown", detail="Not found in VirusTotal.",
        )
        _cache_set(cache_key, result)
        return result

    if response.status_code != 200:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="virustotal",
            verdict="error", detail=f"HTTP {response.status_code}: {response.text[:300]}",
        )

    attributes = ((response.json() or {}).get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)

    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0:
        verdict = "suspicious"
    else:
        verdict = "harmless"

    result = EnrichmentResult(
        indicator=indicator,
        indicator_type=indicator_type,
        source="virustotal",
        verdict=verdict,
        detail=(
            f"{malicious} vendor(s) flagged malicious, {suspicious} suspicious, "
            f"{harmless} harmless (of {malicious + suspicious + harmless} total)."
        ),
        link=f"https://www.virustotal.com/gui/search/{indicator}",
    )
    _cache_set(cache_key, result)
    return result


def lookup_ip_virustotal(ip: str) -> Optional[EnrichmentResult]:
    return _lookup_virustotal(ip, "ip")


def lookup_domain_virustotal(domain: str) -> Optional[EnrichmentResult]:
    return _lookup_virustotal(domain, "domain")


def lookup_hash_virustotal(file_hash: str) -> Optional[EnrichmentResult]:
    return _lookup_virustotal(file_hash, "hash")


_SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{}"
_SHODAN_MAX_PORTS_SHOWN = 20
_SHODAN_MAX_VULNS_SHOWN = 10
_SHODAN_MAX_HOSTNAMES_SHOWN = 5
_SHODAN_MAX_TAGS_SHOWN = 5


def _shodan_enabled() -> bool:
    return os.getenv("SENTINELOS_SHODAN_ENABLED", "false").strip().lower() in ("1", "true", "yes")


def lookup_ip_shodan(ip: str) -> Optional[EnrichmentResult]:
    """Exposed open ports, hostnames, and known CVEs for an IP, via
    Shodan's free InternetDB endpoint (https://internetdb.shodan.io) —
    unlike AbuseIPDB/VirusTotal, this needs no API key at all.

    That's exactly why it's gated by SENTINELOS_SHODAN_ENABLED (default
    off) instead of "is a key configured": querying a third party with an
    IP a SOC is actively investigating is a real operational-security
    choice — it tells Shodan (and anyone watching Shodan's query logs)
    which IPs this deployment cares about — and a tool with no API key to
    withhold shouldn't make that call silently on an analyst's behalf.

    "verdict" here means exposed-service *risk*, not attacker reputation:
    "suspicious" = a known CVE is associated with a service Shodan found
    exposed on this IP; "harmless" = exposed services with no known CVE;
    "unknown" = Shodan has no scan data for this IP at all.
    """
    if not _shodan_enabled():
        return None

    cache_key = ("shodan", ip)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    import requests

    try:
        response = requests.get(_SHODAN_INTERNETDB_URL.format(ip), timeout=10)
    except requests.RequestException as exc:
        return EnrichmentResult(
            indicator=ip, indicator_type="ip", source="shodan",
            verdict="error", detail=f"Request failed: {exc}",
        )

    if response.status_code == 404:
        result = EnrichmentResult(
            indicator=ip, indicator_type="ip", source="shodan",
            verdict="unknown", detail="No Shodan scan data available for this IP.",
        )
        _cache_set(cache_key, result)
        return result

    if response.status_code != 200:
        return EnrichmentResult(
            indicator=ip, indicator_type="ip", source="shodan",
            verdict="error", detail=f"HTTP {response.status_code}: {response.text[:300]}",
        )

    data = response.json() or {}
    ports = sorted(data.get("ports") or [])
    vulns = data.get("vulns") or []
    hostnames = data.get("hostnames") or []
    tags = data.get("tags") or []

    verdict = "suspicious" if vulns else "harmless"

    detail_parts = [
        f"{len(ports)} open port(s): {', '.join(str(p) for p in ports[:_SHODAN_MAX_PORTS_SHOWN])}"
        if ports
        else "No open ports on record."
    ]
    if vulns:
        detail_parts.append(
            f"{len(vulns)} known vulnerability association(s): "
            f"{', '.join(vulns[:_SHODAN_MAX_VULNS_SHOWN])}"
        )
    if hostnames:
        detail_parts.append(f"Hostnames: {', '.join(hostnames[:_SHODAN_MAX_HOSTNAMES_SHOWN])}")
    if tags:
        detail_parts.append(f"Tags: {', '.join(tags[:_SHODAN_MAX_TAGS_SHOWN])}")

    result = EnrichmentResult(
        indicator=ip,
        indicator_type="ip",
        source="shodan",
        verdict=verdict,
        # Manually capped rather than relying on Pydantic's max_length to
        # catch it — Field(max_length=...) *rejects* an over-long string
        # with a ValidationError rather than truncating it, and a host
        # with an unusually large port/vuln list is exactly the kind of
        # externally-controlled input this project treats defensively.
        detail=" ".join(detail_parts)[:1000],
        link=f"https://www.shodan.io/host/{ip}",
    )
    _cache_set(cache_key, result)
    return result


def reset_cache_for_tests() -> None:
    with _cache_lock:
        _cache.clear()
