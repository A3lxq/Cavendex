"""Real threat-intel provider lookups — AbuseIPDB, VirusTotal, Shodan,
AlienVault OTX, GreyNoise, MalwareBazaar, ThreatFox, URLhaus (abuse.ch),
IBM X-Force Exchange, Metadefender Cloud (OPSWAT), and Censys. Every
function here follows the same contract as the rest of this project's
external-dependency code (utils/llm.py's provider fallback, ingestion's
normalizers): never raise into the caller, return None when a lookup
can't be answered (disabled, no API key configured, the provider
errored, the network is unreachable), so a missing/broken threat-intel
key degrades an incident's context instead of crashing the pipeline.

Results are cached in-process for CACHE_TTL_SECONDS — free-tier quotas are
tight (VirusTotal: 4 requests/minute) and the same IOC is looked up again
every time an incident revisits it (e.g. Investigator re-checking what
Triage already checked).

Honesty note on the 8 newer providers (added after PhD-level research
into their real APIs, ToS, and free tiers — see README's "Adding a
Threat-Intel Provider" section for the full per-platform writeup):
AlienVault OTX, GreyNoise, and the three abuse.ch platforms
(MalwareBazaar/ThreatFox/URLhaus) were verified against real, current
public API docs with stable, well-documented response shapes. IBM
X-Force, Metadefender Cloud, and Censys carry real, flagged uncertainty
at the time this was written — an unresolved 2026 end-of-life question
for IBM X-Force tied to the Palo Alto Networks/QRadar transition, only
2018-era free-tier numbers found for Metadefender, and a genuinely
unstable free tier for Censys — so their response parsing below is
written defensively (never assumes one gold-standard shape) rather than
pinned to a verified-live success response, the same honesty pattern
this project already uses for Wazuh/Splunk/CrowdStrike ("verified
against the documented shape, not a live vendor tenant"). All three are
inert without a key either way, same as everything else here.
"""

import logging
import os
import threading
import time
import urllib.parse
from typing import List, Optional

from enrichment.schemas import EnrichmentResult

logger = logging.getLogger(__name__)

# Security note (applies to every provider function below, not just the
# new ones): an IOC's value ultimately traces back to ingested alert
# data or an LLM's reading of an incident description — both untrusted,
# potentially attacker-influenced input, the same threat model this
# project already treats carefully for prompt injection (see
# tests/test_prompt_injection_regression.py). Two invariants keep that
# untrusted content from becoming an attack surface here:
#   1. No provider function ever fetches an IOC value AS a request
#      target (no `requests.get(indicator)`/`requests.post(indicator)`
#      anywhere) — every call always targets one of this module's own
#      hardcoded provider hostnames; the indicator only ever travels as
#      DATA (a query param, JSON body field, or a URL-encoded path
#      segment appended after the hostname is already fixed in the
#      source). This rules out SSRF: a malicious "IOC" string can never
#      redirect an outbound request to an attacker-chosen host.
#   2. Every indicator interpolated into a URL PATH (as opposed to
#      `requests`' own `params=`/`json=`, which already encode safely)
#      is explicitly run through `urllib.parse.quote(..., safe="")`
#      first, so it can't be mistaken for extra path segments or a query
#      string by the (legitimate, hardcoded) provider's own server.
# On top of that, `enrichment/pipeline.py`'s per-incident lookup cap
# bounds actual outbound *attempts*, not just successful results, so a
# maliciously alert with many fabricated-looking IOCs can't turn a wider
# provider fan-out into an unbounded number of real third-party requests.

_CACHE_TTL_SECONDS = 3600.0
# Bounds the cache's total memory growth over the process's lifetime —
# without this, an indicator looked up exactly once (never again, so its
# own lazy per-key expiry in _cache_get never fires) stayed cached
# forever. A sustained stream of distinct classifiable indicators (via
# POST /enrichment/lookup, or ordinary incident volume) could otherwise
# grow this dict without bound. 5000 entries is generous for realistic
# usage (a real SOC revisits the same handful of hot indicators far more
# than it sees fresh ones within any given hour) while still capping
# worst-case memory at a small, fixed size.
_CACHE_MAX_ENTRIES = 5000
_cache_lock = threading.Lock()
_cache: dict = {}


def _cache_get(key) -> Optional[object]:
    """Generic TTL cache read — not just EnrichmentResult; also backs
    lookup_domain_resolutions_virustotal's plain list-of-IPs result.
    """
    with _cache_lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        result, cached_at = entry
        if time.monotonic() - cached_at > _CACHE_TTL_SECONDS:
            del _cache[key]
            return None
        return result


def _cache_set(key, result: object) -> None:
    with _cache_lock:
        _cache[key] = (result, time.monotonic())
        if len(_cache) <= _CACHE_MAX_ENTRIES:
            return
        now = time.monotonic()
        expired = [k for k, (_, cached_at) in _cache.items() if now - cached_at > _CACHE_TTL_SECONDS]
        for k in expired:
            del _cache[k]
        if len(_cache) > _CACHE_MAX_ENTRIES:
            # Still over budget after sweeping expired entries -- evict
            # the oldest-cached ones first (a simple, adequate policy
            # for a cache this size; not a true LRU, since a cache hit
            # doesn't refresh an entry's position).
            oldest_first = sorted(_cache.items(), key=lambda kv: kv[1][1])
            for k, _ in oldest_first[: len(_cache) - _CACHE_MAX_ENTRIES]:
                del _cache[k]


def _error_detail(response) -> str:
    """A non-200 response's detail, safe to put in a durable
    EnrichmentResult (the vault report, the dashboard, an API response)
    — never echoes the raw third-party response body, which can contain
    anything (an HTML error/maintenance page, a WAF/CDN challenge page,
    occasionally reflected request data) with no guarantee it's safe to
    display verbatim. The full body is still logged server-side (an
    already-trusted vantage point, same tier as `.env`) for whoever
    needs to actually debug a broken integration.
    """
    logger.warning("Provider returned HTTP %s: %s", response.status_code, response.text[:2000])
    return f"HTTP {response.status_code} (see server logs for the response body)."


def _parse_json(response):
    """response.json(), or None if the body isn't valid JSON. A 200
    response with a non-JSON body (a captive portal, a WAF/proxy
    injecting an error page, a provider outage serving HTML with a 200
    status) must never raise past this point — every call site checks
    for None explicitly and returns an "error" EnrichmentResult, rather
    than letting response.json() raise straight out of this module and
    violate its own "never raise into the caller" contract.
    """
    try:
        return response.json()
    except ValueError:
        logger.warning("Provider returned a non-JSON body on HTTP %s", response.status_code)
        return None


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
            detail=_error_detail(response),
        )

    raw = _parse_json(response)
    if raw is None:
        return EnrichmentResult(
            indicator=ip, indicator_type="ip", source="abuseipdb",
            verdict="error", detail="AbuseIPDB returned a non-JSON response body.",
        )
    data = raw.get("data") or {}
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
        )[:1000],
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
            verdict="error", detail=_error_detail(response),
        )

    raw = _parse_json(response)
    if raw is None:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="virustotal",
            verdict="error", detail="VirusTotal returned a non-JSON response body.",
        )
    attributes = (raw.get("data") or {}).get("attributes") or {}
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


def lookup_domain_resolutions_virustotal(domain: str, limit: int = 10) -> Optional[List[str]]:
    """Passive DNS: historical IP addresses `domain` has resolved to, via
    VirusTotal's /domains/{domain}/resolutions endpoint — the same kind
    of evidence a real threat-intel analyst pulls to link two
    lexically-unrelated domains as the same infrastructure (see
    ingestion/identity_correlation.py, which is the only caller of this).
    Requires VIRUSTOTAL_API_KEY, same as every other VirusTotal lookup
    here. Returns None if unconfigured or the request fails outright; an
    empty list is a real, meaningful "no recorded resolutions" answer,
    not a failure — the caller treats both "unconfigured" and "nothing on
    file" the same way (no match), but the distinction matters for anyone
    debugging why a match wasn't found.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None

    cache_key = ("virustotal_resolutions", domain)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    import requests

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions",
            headers={"x-apikey": api_key},
            params={"limit": limit},
            timeout=10,
        )
    except requests.RequestException:
        return None

    if response.status_code != 200:
        return None

    raw = _parse_json(response)
    if raw is None:
        return None
    entries = raw.get("data") or []
    ips = [
        entry["attributes"]["ip_address"]
        for entry in entries
        if isinstance(entry, dict) and (entry.get("attributes") or {}).get("ip_address")
    ]
    _cache_set(cache_key, ips)
    return ips


_SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{}"
_SHODAN_MAX_PORTS_SHOWN = 20
_SHODAN_MAX_VULNS_SHOWN = 10
_SHODAN_MAX_HOSTNAMES_SHOWN = 5
_SHODAN_MAX_TAGS_SHOWN = 5


def _shodan_enabled() -> bool:
    return os.getenv("CAVENDEX_SHODAN_ENABLED", "false").strip().lower() in ("1", "true", "yes")


def lookup_ip_shodan(ip: str) -> Optional[EnrichmentResult]:
    """Exposed open ports, hostnames, and known CVEs for an IP, via
    Shodan's free InternetDB endpoint (https://internetdb.shodan.io) —
    unlike AbuseIPDB/VirusTotal, this needs no API key at all.

    That's exactly why it's gated by CAVENDEX_SHODAN_ENABLED (default
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
            verdict="error", detail=_error_detail(response),
        )

    raw = _parse_json(response)
    if raw is None:
        return EnrichmentResult(
            indicator=ip, indicator_type="ip", source="shodan",
            verdict="error", detail="Shodan returned a non-JSON response body.",
        )
    data = raw
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


_OTX_SECTION_TYPE = {"ip": "IPv4", "domain": "domain", "hash": "file"}


def _lookup_otx(indicator: str, indicator_type: str) -> Optional[EnrichmentResult]:
    """AlienVault OTX — how many community-curated "Pulses" (campaign
    writeups) reference this indicator, and which ones, rather than a
    bare reputation score. Requires ALIENVAULT_OTX_API_KEY.
    """
    api_key = os.getenv("ALIENVAULT_OTX_API_KEY")
    if not api_key:
        return None

    cache_key = ("otx", indicator)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    import requests

    otx_type = _OTX_SECTION_TYPE[indicator_type]
    url = (
        f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/"
        f"{urllib.parse.quote(indicator, safe='')}/general"
    )
    try:
        response = requests.get(url, headers={"X-OTX-API-KEY": api_key}, timeout=10)
    except requests.RequestException as exc:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="alienvault_otx",
            verdict="error", detail=f"Request failed: {exc}"[:1000],
        )

    if response.status_code == 404:
        result = EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="alienvault_otx",
            verdict="unknown", detail="Not found in AlienVault OTX.",
        )
        _cache_set(cache_key, result)
        return result

    if response.status_code != 200:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="alienvault_otx",
            verdict="error", detail=_error_detail(response),
        )

    raw = _parse_json(response)
    if raw is None:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="alienvault_otx",
            verdict="error", detail="AlienVault OTX returned a non-JSON response body.",
        )
    data = raw
    pulse_info = data.get("pulse_info") or {}
    count = pulse_info.get("count", 0)
    pulses = pulse_info.get("pulses") or []
    names = [p.get("name", "unnamed") for p in pulses[:5] if isinstance(p, dict)]

    if count > 0:
        verdict = "malicious"
        detail = f"Referenced in {count} community Pulse(s)" + (f": {', '.join(names)}" if names else "") + "."
    else:
        verdict = "unknown"
        detail = "Not referenced in any community Pulse."

    result = EnrichmentResult(
        indicator=indicator,
        indicator_type=indicator_type,
        source="alienvault_otx",
        verdict=verdict,
        detail=detail[:1000],
        link=f"https://otx.alienvault.com/indicator/{otx_type}/{urllib.parse.quote(indicator, safe='')}",
    )
    _cache_set(cache_key, result)
    return result


def lookup_ip_otx(ip: str) -> Optional[EnrichmentResult]:
    return _lookup_otx(ip, "ip")


def lookup_domain_otx(domain: str) -> Optional[EnrichmentResult]:
    return _lookup_otx(domain, "domain")


def lookup_hash_otx(file_hash: str) -> Optional[EnrichmentResult]:
    return _lookup_otx(file_hash, "hash")


def lookup_ip_greynoise(ip: str) -> Optional[EnrichmentResult]:
    """GreyNoise Community API — whether an IP is internet-wide
    background-scan noise (or a known-good business crawler) rather than
    a targeted attacker, a different signal axis than a reputation
    score. Requires GREYNOISE_API_KEY (free Community registration,
    business email required).
    """
    api_key = os.getenv("GREYNOISE_API_KEY")
    if not api_key:
        return None

    cache_key = ("greynoise", ip)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    import requests

    try:
        response = requests.get(
            f"https://api.greynoise.io/v3/community/{urllib.parse.quote(ip, safe='')}",
            headers={"key": api_key, "Accept": "application/json"},
            timeout=10,
        )
    except requests.RequestException as exc:
        return EnrichmentResult(
            indicator=ip, indicator_type="ip", source="greynoise",
            verdict="error", detail=f"Request failed: {exc}"[:1000],
        )

    if response.status_code == 404:
        result = EnrichmentResult(
            indicator=ip, indicator_type="ip", source="greynoise",
            verdict="unknown", detail="No GreyNoise data available for this IP.",
        )
        _cache_set(cache_key, result)
        return result

    if response.status_code != 200:
        return EnrichmentResult(
            indicator=ip, indicator_type="ip", source="greynoise",
            verdict="error", detail=_error_detail(response),
        )

    raw = _parse_json(response)
    if raw is None:
        return EnrichmentResult(
            indicator=ip, indicator_type="ip", source="greynoise",
            verdict="error", detail="GreyNoise returned a non-JSON response body.",
        )
    data = raw
    classification = data.get("classification", "unknown")
    noise = bool(data.get("noise", False))
    riot = bool(data.get("riot", False))
    name = data.get("name")

    if classification == "malicious":
        verdict = "malicious"
    elif classification == "benign":
        verdict = "harmless"
    else:
        verdict = "unknown"

    detail_parts = [f"Classification: {classification}."]
    if noise:
        detail_parts.append("Flagged as internet-wide background scanning noise.")
    if riot:
        detail_parts.append(f"Known benign business service{f' ({name})' if name else ''}.")

    result = EnrichmentResult(
        indicator=ip,
        indicator_type="ip",
        source="greynoise",
        verdict=verdict,
        detail=" ".join(detail_parts)[:1000],
        link=f"https://viz.greynoise.io/ip/{urllib.parse.quote(ip, safe='')}",
    )
    _cache_set(cache_key, result)
    return result


def _abusech_key() -> Optional[str]:
    """One registration at auth.abuse.ch issues a single Auth-Key that
    covers MalwareBazaar, ThreatFox, and URLhaus alike — one shared env
    var rather than three separate ones.
    """
    return os.getenv("ABUSECH_API_KEY")


def lookup_hash_malwarebazaar(file_hash: str) -> Optional[EnrichmentResult]:
    """MalwareBazaar (abuse.ch) — the named malware family/signature for
    a hash, not just a bare "malicious" verdict. Requires
    ABUSECH_API_KEY.
    """
    api_key = _abusech_key()
    if not api_key:
        return None

    cache_key = ("malwarebazaar", file_hash)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    import requests

    try:
        response = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": file_hash},
            headers={"Auth-Key": api_key},
            timeout=10,
        )
    except requests.RequestException as exc:
        return EnrichmentResult(
            indicator=file_hash, indicator_type="hash", source="malwarebazaar",
            verdict="error", detail=f"Request failed: {exc}"[:1000],
        )

    if response.status_code != 200:
        return EnrichmentResult(
            indicator=file_hash, indicator_type="hash", source="malwarebazaar",
            verdict="error", detail=_error_detail(response),
        )

    raw = _parse_json(response)
    if raw is None:
        return EnrichmentResult(
            indicator=file_hash, indicator_type="hash", source="malwarebazaar",
            verdict="error", detail="MalwareBazaar returned a non-JSON response body.",
        )
    body = raw
    status = body.get("query_status")

    if status != "ok":
        result = EnrichmentResult(
            indicator=file_hash, indicator_type="hash", source="malwarebazaar",
            verdict="unknown", detail=f"Not found in MalwareBazaar (status: {status})."[:1000],
        )
        _cache_set(cache_key, result)
        return result

    entries = body.get("data") or []
    entry = entries[0] if entries and isinstance(entries[0], dict) else {}
    signature = entry.get("signature") or "unclassified"
    tags = [t for t in (entry.get("tags") or []) if isinstance(t, str)][:10]

    detail = f"Known malware sample, signature: {signature}."
    if tags:
        detail += f" Tags: {', '.join(tags)}."

    result = EnrichmentResult(
        indicator=file_hash,
        indicator_type="hash",
        source="malwarebazaar",
        verdict="malicious",
        detail=detail[:1000],
        link=f"https://bazaar.abuse.ch/sample/{urllib.parse.quote(file_hash, safe='')}/",
    )
    _cache_set(cache_key, result)
    return result


def _lookup_threatfox(indicator: str, indicator_type: str) -> Optional[EnrichmentResult]:
    """ThreatFox (abuse.ch) — names the actual malware family plus a
    researcher-asserted confidence score, instead of a bare verdict.
    Requires ABUSECH_API_KEY (shared with MalwareBazaar/URLhaus).
    """
    api_key = _abusech_key()
    if not api_key:
        return None

    cache_key = ("threatfox", indicator)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    import requests

    try:
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": indicator},
            headers={"Auth-Key": api_key},
            timeout=10,
        )
    except requests.RequestException as exc:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="threatfox",
            verdict="error", detail=f"Request failed: {exc}"[:1000],
        )

    if response.status_code != 200:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="threatfox",
            verdict="error", detail=_error_detail(response),
        )

    raw = _parse_json(response)
    if raw is None:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="threatfox",
            verdict="error", detail="ThreatFox returned a non-JSON response body.",
        )
    body = raw
    status = body.get("query_status")

    if status != "ok":
        result = EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="threatfox",
            verdict="unknown", detail=f"Not found in ThreatFox (status: {status})."[:1000],
        )
        _cache_set(cache_key, result)
        return result

    entries = body.get("data") or []
    entry = entries[0] if entries and isinstance(entries[0], dict) else {}
    malware = entry.get("malware_printable") or entry.get("malware") or "unclassified malware"
    confidence = entry.get("confidence_level", "unknown")
    threat_type = entry.get("threat_type", "unknown")

    result = EnrichmentResult(
        indicator=indicator,
        indicator_type=indicator_type,
        source="threatfox",
        verdict="malicious",
        detail=f"Tagged {malware} ({threat_type}), confidence {confidence}."[:1000],
        link=f"https://threatfox.abuse.ch/browse.php?search={urllib.parse.quote(indicator, safe='')}",
    )
    _cache_set(cache_key, result)
    return result


def lookup_ip_threatfox(ip: str) -> Optional[EnrichmentResult]:
    return _lookup_threatfox(ip, "ip")


def lookup_domain_threatfox(domain: str) -> Optional[EnrichmentResult]:
    return _lookup_threatfox(domain, "domain")


def lookup_hash_threatfox(file_hash: str) -> Optional[EnrichmentResult]:
    return _lookup_threatfox(file_hash, "hash")


def lookup_url_threatfox(url: str) -> Optional[EnrichmentResult]:
    return _lookup_threatfox(url, "url")


def lookup_url_urlhaus(url: str) -> Optional[EnrichmentResult]:
    """URLhaus (abuse.ch) — flags a URL as a known malware-distribution
    point and what payload it served, rather than a generic "malicious
    URL" verdict. Requires ABUSECH_API_KEY (shared with
    MalwareBazaar/ThreatFox). The URL itself is only ever sent as POST
    body data to URLhaus's own API — Cavendex never fetches it.
    """
    api_key = _abusech_key()
    if not api_key:
        return None

    cache_key = ("urlhaus", url)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    import requests

    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Auth-Key": api_key},
            timeout=10,
        )
    except requests.RequestException as exc:
        return EnrichmentResult(
            indicator=url, indicator_type="url", source="urlhaus",
            verdict="error", detail=f"Request failed: {exc}"[:1000],
        )

    if response.status_code != 200:
        return EnrichmentResult(
            indicator=url, indicator_type="url", source="urlhaus",
            verdict="error", detail=_error_detail(response),
        )

    raw = _parse_json(response)
    if raw is None:
        return EnrichmentResult(
            indicator=url, indicator_type="url", source="urlhaus",
            verdict="error", detail="URLhaus returned a non-JSON response body.",
        )
    body = raw
    status = body.get("query_status")

    if status != "ok":
        result = EnrichmentResult(
            indicator=url, indicator_type="url", source="urlhaus",
            verdict="unknown", detail=f"Not found in URLhaus (status: {status})."[:1000],
        )
        _cache_set(cache_key, result)
        return result

    url_status = body.get("url_status", "unknown")
    threat = body.get("threat", "unknown")
    payloads = [p for p in (body.get("payloads") or []) if isinstance(p, dict)][:5]
    payload_types = [p.get("file_type", "unknown") for p in payloads]

    detail = f"Known malware-distribution URL ({url_status}), threat: {threat}."
    if payload_types:
        detail += f" Payload type(s): {', '.join(payload_types)}."

    reference = body.get("urlhaus_reference")
    link = reference if isinstance(reference, str) and reference.startswith("https://urlhaus.abuse.ch/") else None

    result = EnrichmentResult(
        indicator=url,
        indicator_type="url",
        source="urlhaus",
        verdict="malicious",
        detail=detail[:1000],
        link=link,
    )
    _cache_set(cache_key, result)
    return result


_XFORCE_ENDPOINT = {
    "ip": "https://api.xforce.ibmcloud.com/api/ipr/{}",
    "hash": "https://api.xforce.ibmcloud.com/api/malware/{}",
    "url": "https://api.xforce.ibmcloud.com/api/url/{}",
}


def _lookup_xforce(
    indicator: str, indicator_type: str, path_value: Optional[str] = None
) -> Optional[EnrichmentResult]:
    """IBM X-Force Exchange — CVE-linked risk scoring and named
    threat-actor Collections, per public API docs. Requires BOTH
    IBM_XFORCE_API_KEY and IBM_XFORCE_API_PASSWORD (HTTP Basic Auth) —
    see this module's docstring for the honest availability caveat.
    """
    api_key = os.getenv("IBM_XFORCE_API_KEY")
    api_password = os.getenv("IBM_XFORCE_API_PASSWORD")
    if not api_key or not api_password:
        return None

    cache_key = ("xforce", indicator)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    import requests

    url = _XFORCE_ENDPOINT[indicator_type].format(urllib.parse.quote(path_value or indicator, safe=""))
    try:
        response = requests.get(url, auth=(api_key, api_password), timeout=10)
    except requests.RequestException as exc:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="ibm_xforce",
            verdict="error", detail=f"Request failed: {exc}"[:1000],
        )

    if response.status_code == 404:
        result = EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="ibm_xforce",
            verdict="unknown", detail="Not found in IBM X-Force Exchange.",
        )
        _cache_set(cache_key, result)
        return result

    if response.status_code != 200:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="ibm_xforce",
            verdict="error", detail=_error_detail(response),
        )

    raw = _parse_json(response)
    if raw is None:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="ibm_xforce",
            verdict="error", detail="IBM X-Force Exchange returned a non-JSON response body.",
        )
    data = raw
    # Response shape genuinely varies by indicator type in X-Force's real
    # API, and this project could not verify a real successful response
    # (see module docstring) — parsed defensively rather than assuming
    # one exact schema across all three endpoints.
    raw_score = data.get("score")
    if raw_score is None:
        raw_score = (data.get("malware") or {}).get("risk") if isinstance(data.get("malware"), dict) else None
    try:
        score = float(raw_score) if raw_score is not None else None
    except (TypeError, ValueError):
        score = None

    if score is None:
        verdict = "unknown"
        detail = "IBM X-Force returned data in an unrecognized shape; no risk score could be parsed."
    elif score >= 7:
        verdict = "malicious"
        detail = f"IBM X-Force risk score: {score}."
    elif score >= 3:
        verdict = "suspicious"
        detail = f"IBM X-Force risk score: {score}."
    else:
        verdict = "harmless"
        detail = f"IBM X-Force risk score: {score}."

    result = EnrichmentResult(
        indicator=indicator,
        indicator_type=indicator_type,
        source="ibm_xforce",
        verdict=verdict,
        detail=detail[:1000],
        link=f"https://exchange.xforce.ibmcloud.com/search/{urllib.parse.quote(indicator, safe='')}",
    )
    _cache_set(cache_key, result)
    return result


def lookup_ip_xforce(ip: str) -> Optional[EnrichmentResult]:
    return _lookup_xforce(ip, "ip")


def lookup_hash_xforce(file_hash: str) -> Optional[EnrichmentResult]:
    return _lookup_xforce(file_hash, "hash")


def lookup_url_xforce(url: str) -> Optional[EnrichmentResult]:
    return _lookup_xforce(url, "url", path_value=url)


_METADEFENDER_ENDPOINT = {
    "ip": "https://api.metadefender.com/v4/ip",
    "domain": "https://api.metadefender.com/v4/domain",
    "hash": "https://api.metadefender.com/v4/hash",
    "url": "https://api.metadefender.com/v4/url",
}


def _lookup_metadefender(indicator: str, indicator_type: str) -> Optional[EnrichmentResult]:
    """Metadefender Cloud (OPSWAT) reputation lookup, via the
    bulk-capable reputation endpoints (a single-item list body; the
    response is a list, first item taken). Requires
    METADEFENDER_API_KEY — see this module's docstring for the honest
    availability/shape caveat.
    """
    api_key = os.getenv("METADEFENDER_API_KEY")
    if not api_key:
        return None

    cache_key = ("metadefender", indicator)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    import requests

    try:
        response = requests.post(
            _METADEFENDER_ENDPOINT[indicator_type],
            json=[indicator],
            headers={"apikey": api_key, "Content-Type": "application/json"},
            timeout=10,
        )
    except requests.RequestException as exc:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="metadefender",
            verdict="error", detail=f"Request failed: {exc}"[:1000],
        )

    if response.status_code != 200:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="metadefender",
            verdict="error", detail=_error_detail(response),
        )

    raw = _parse_json(response)
    if raw is None:
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="metadefender",
            verdict="error", detail="Metadefender Cloud returned a non-JSON response body.",
        )
    body = raw
    entry = body[0] if isinstance(body, list) and body and isinstance(body[0], dict) else None

    if entry is None:
        result = EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, source="metadefender",
            verdict="unknown", detail="No Metadefender Cloud data returned for this indicator.",
        )
        _cache_set(cache_key, result)
        return result

    lookup_result = entry.get("lookup_result") if isinstance(entry.get("lookup_result"), dict) else {}
    detected_by = lookup_result.get("detected_by") or 0
    total_engines = lookup_result.get("total_detected_avs") or lookup_result.get("total_avs") or 0

    try:
        detected_by = int(detected_by)
    except (TypeError, ValueError):
        detected_by = 0

    verdict = "malicious" if detected_by > 0 else "harmless"
    detail = f"Detected by {detected_by}/{total_engines or '?'} engine(s)." if (detected_by or total_engines) else "No detections reported."

    result = EnrichmentResult(
        indicator=indicator,
        indicator_type=indicator_type,
        source="metadefender",
        verdict=verdict,
        detail=detail[:1000],
        link=None,
    )
    _cache_set(cache_key, result)
    return result


def lookup_ip_metadefender(ip: str) -> Optional[EnrichmentResult]:
    return _lookup_metadefender(ip, "ip")


def lookup_domain_metadefender(domain: str) -> Optional[EnrichmentResult]:
    return _lookup_metadefender(domain, "domain")


def lookup_hash_metadefender(file_hash: str) -> Optional[EnrichmentResult]:
    return _lookup_metadefender(file_hash, "hash")


def lookup_url_metadefender(url: str) -> Optional[EnrichmentResult]:
    return _lookup_metadefender(url, "url")


def lookup_ip_censys(ip: str) -> Optional[EnrichmentResult]:
    """Censys Platform API — internet-exposed host/service data via a
    host asset lookup; certificate-transparency pivoting is its real
    differentiator from Shodan (not exposed through this simple lookup,
    which mirrors Shodan's shape for consistency). Requires
    CENSYS_API_KEY (a Platform API Personal Access Token, Bearer auth —
    see this module's docstring for the honest free-tier caveat).
    """
    api_key = os.getenv("CENSYS_API_KEY")
    if not api_key:
        return None

    cache_key = ("censys", ip)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    import requests

    try:
        response = requests.get(
            f"https://api.platform.censys.io/v3/global/asset/host/{urllib.parse.quote(ip, safe='')}",
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=10,
        )
    except requests.RequestException as exc:
        return EnrichmentResult(
            indicator=ip, indicator_type="ip", source="censys",
            verdict="error", detail=f"Request failed: {exc}"[:1000],
        )

    if response.status_code == 404:
        result = EnrichmentResult(
            indicator=ip, indicator_type="ip", source="censys",
            verdict="unknown", detail="No Censys scan data available for this IP.",
        )
        _cache_set(cache_key, result)
        return result

    if response.status_code != 200:
        return EnrichmentResult(
            indicator=ip, indicator_type="ip", source="censys",
            verdict="error", detail=_error_detail(response),
        )

    raw = _parse_json(response)
    if raw is None:
        return EnrichmentResult(
            indicator=ip, indicator_type="ip", source="censys",
            verdict="error", detail="Censys returned a non-JSON response body.",
        )
    data = raw
    result_data = data.get("result") if isinstance(data.get("result"), dict) else data
    services = [s for s in (result_data.get("services") or []) if isinstance(s, dict)]
    ports = sorted({s["port"] for s in services if isinstance(s.get("port"), int)})

    verdict = "unknown" if not services else "harmless"
    if services:
        detail = f"{len(services)} exposed service(s) on port(s): {', '.join(str(p) for p in ports[:20])}."
    else:
        detail = "No exposed services on record."

    result = EnrichmentResult(
        indicator=ip,
        indicator_type="ip",
        source="censys",
        verdict=verdict,
        detail=detail[:1000],
        link=f"https://platform.censys.io/hosts/{urllib.parse.quote(ip, safe='')}",
    )
    _cache_set(cache_key, result)
    return result


def reset_cache_for_tests() -> None:
    with _cache_lock:
        _cache.clear()
