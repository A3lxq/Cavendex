"""Source-specific alert normalizers.

Each function takes a raw payload in whatever shape its source emits and
either returns a NormalizedAlert or None (meaning "not an alert worth
raising — e.g. a non-alert event type"). Add a new source by writing one
function here and registering it in NORMALIZERS — nothing else in the
ingestion pipeline, the graph, or the vault needs to know it exists.

Nine formats are covered as concrete, genuinely different examples of
"pluggable" rather than committing to one vendor:
  - generic: an already-roughly-shaped alert (custom scripts, simple
    webhooks, anything that can be bothered to match our own field names)
  - suricata: Suricata/Zeek-style eve.json alert records (JSON, nested)
  - syslog_cef: raw CEF-formatted syslog lines (flat key=value extension),
    the format many firewalls/network appliances emit
  - wazuh: Wazuh manager alert records (JSON, nested) — the format
    written to /var/ossec/logs/alerts/alerts.json and what a Wazuh
    "integration" script typically forwards as-is
  - splunk: Splunk Enterprise Security notable-event records (JSON,
    flat) — pulled via ingestion/polling.py's generic connector (see
    examples/splunk_poller_config.example.json) or pushed via Splunk's
    own "Webhook" alert action to POST /ingest/splunk
  - crowdstrike: CrowdStrike Falcon Detects API detection summaries
    (JSON, nested) — pulled via the dedicated
    ingestion/crowdstrike_polling.py connector (OAuth2 + a two-step
    query/summarize API the generic connector can't express)
  - elastic: Elastic Security detection-alert documents (JSON, nested
    ECS fields, including real process/command-line/parent-process
    context) — pulled via ingestion/polling.py's generic connector (see
    examples/elastic_poller_config.example.json), an API-key header and
    Elasticsearch's own URI Search endpoint
  - qradar: IBM QRadar Offense records (JSON, flat-ish, a 0-10
    magnitude score instead of a name) — pulled via
    ingestion/polling.py's generic connector (see
    examples/qradar_poller_config.example.json), a static `SEC` header
    token and QRadar's own /api/siem/offenses endpoint
  - sentinel: Microsoft Sentinel SecurityAlert records (JSON, dynamic
    Entities/ExtendedProperties columns from a Log Analytics KQL query)
    — pulled via the dedicated ingestion/sentinel_polling.py connector
    (Azure AD OAuth2 plus a KQL query call the generic connector can't
    express)
"""

import hashlib
import json
import re
from typing import Optional

from ingestion.schemas import NormalizedAlert

_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def normalize_generic(payload: dict) -> Optional[NormalizedAlert]:
    """Accepts a payload already close to our own shape — the path for a
    custom script or a webhook you control the format of."""
    description = str(payload.get("description") or payload.get("message") or "Untitled alert")
    severity = payload.get("severity")
    severity = severity if severity in _VALID_SEVERITIES else "medium"
    source = str(payload.get("source") or "generic")
    affected_assets = [str(a) for a in (payload.get("affected_assets") or [])][:50]
    iocs = [str(i) for i in (payload.get("iocs") or [])][:50]
    dedup_key = str(
        payload.get("dedup_key")
        or hashlib.sha256(f"{source}:{description}".encode()).hexdigest()[:32]
    )

    return NormalizedAlert(
        description=description,
        severity=severity,
        source=source,
        affected_assets=affected_assets,
        iocs=iocs,
        dedup_key=dedup_key,
        raw_excerpt=json.dumps(payload)[:2000],
    )


# Suricata convention: lower number = higher priority. Only a starting
# point — the Triage Agent re-assesses actual severity from context, this
# just avoids handing it a blank slate.
_SURICATA_SEVERITY_MAP = {1: "high", 2: "medium", 3: "low"}


def normalize_suricata_eve(payload: dict) -> Optional[NormalizedAlert]:
    """Suricata/Zeek-style eve.json record. Only `event_type: "alert"`
    records become incidents — flow/dns/http/etc. records are noise for
    this purpose and return None.
    """
    if payload.get("event_type") != "alert":
        return None

    alert = payload.get("alert") or {}
    signature = alert.get("signature", "Unknown Suricata signature")
    category = alert.get("category", "")
    sig_id = alert.get("signature_id", "0")
    src_ip = payload.get("src_ip", "unknown")
    src_port = payload.get("src_port", "")
    dest_ip = payload.get("dest_ip", "unknown")
    dest_port = payload.get("dest_port", "")
    proto = payload.get("proto", "")
    severity = _SURICATA_SEVERITY_MAP.get(alert.get("severity"), "medium")

    description = (
        f"Suricata alert: {signature}"
        + (f" ({category})" if category else "")
        + f" — {src_ip}:{src_port} -> {dest_ip}:{dest_port}/{proto}"
    )
    iocs = [ip for ip in (src_ip, dest_ip) if ip and ip != "unknown"]
    assets = [dest_ip] if dest_ip and dest_ip != "unknown" else []

    return NormalizedAlert(
        description=description,
        severity=severity,
        source="suricata",
        affected_assets=assets,
        iocs=iocs,
        dedup_key=f"suricata:{sig_id}:{src_ip}:{dest_ip}",
        raw_excerpt=json.dumps(payload)[:2000],
    )


# Not a full RFC-perfect CEF parser (real CEF escaping rules are gnarlier
# than this), but good enough for the common case: `key=value` pairs
# separated by whitespace, with `\=` and `\\` escaped inside a value.
_CEF_EXTENSION_RE = re.compile(r"(\w+)=((?:\\.|[^\\=])*?)(?=\s+\w+=|$)")


def _parse_cef(raw: str) -> Optional[dict]:
    if "CEF:" not in raw:
        return None
    raw = raw[raw.index("CEF:") :]
    parts = raw.split("|")
    if len(parts) < 8:
        return None

    _, vendor, product, device_version, sig_id, name, severity, extension = parts[:8]
    fields = {
        "vendor": vendor,
        "product": product,
        "device_version": device_version,
        "signature_id": sig_id,
        "name": name,
        "severity": severity,
    }
    for match in _CEF_EXTENSION_RE.finditer(extension.strip()):
        key = match.group(1)
        value = match.group(2).replace("\\=", "=").replace("\\\\", "\\")
        fields[key] = value
    return fields


def _cef_severity_to_scale(raw_severity) -> str:
    try:
        n = int(raw_severity)
    except (TypeError, ValueError):
        return "medium"
    if n >= 9:
        return "critical"
    if n >= 7:
        return "high"
    if n >= 4:
        return "medium"
    return "low"


def normalize_syslog_cef(payload: dict) -> Optional[NormalizedAlert]:
    """A raw CEF-formatted syslog line, e.g. from a firewall/network
    appliance: `CEF:0|Vendor|Product|1.0|100|Port Scan|7|src=1.2.3.4 dst=10.0.0.5`.
    Expects `payload = {"raw": "<the line>"}`. Returns None if the line
    doesn't parse as CEF at all.
    """
    raw_line = str(payload.get("raw") or payload.get("raw_line") or "")
    fields = _parse_cef(raw_line)
    if fields is None:
        return None

    vendor = fields.get("vendor", "unknown")
    product = fields.get("product", "unknown")
    name = fields.get("name", "Unnamed event")
    src = fields.get("src") or fields.get("shost") or "unknown"
    dst = fields.get("dst") or fields.get("dhost") or "unknown"
    severity = _cef_severity_to_scale(fields.get("severity"))

    description = f"{vendor} {product}: {name} (src={src}, dst={dst})"
    iocs = [ip for ip in (src, dst) if ip and ip != "unknown"]
    assets = [dst] if dst != "unknown" else []

    return NormalizedAlert(
        description=description,
        severity=severity,
        source="syslog_cef",
        affected_assets=assets,
        iocs=iocs,
        dedup_key=f"cef:{fields.get('signature_id', '0')}:{src}:{dst}",
        raw_excerpt=raw_line[:2000],
    )


# Wazuh's rule.level is a 0-15 scale (see Wazuh's own "Rules
# classification" docs): 0-3 informational/low, 4-6 medium, 7-11 high
# (most real security-relevant alerts land here), 12-15 critical (active
# attacks, rootkits). Only a starting point, same as the Suricata/CEF
# scale maps above — Triage re-assesses actual severity from context.
_WAZUH_LEVEL_THRESHOLDS = ((12, "critical"), (7, "high"), (4, "medium"))


def _wazuh_level_to_severity(level) -> str:
    try:
        n = int(level)
    except (TypeError, ValueError):
        return "medium"
    for threshold, severity in _WAZUH_LEVEL_THRESHOLDS:
        if n >= threshold:
            return severity
    return "low"


def normalize_wazuh(payload: dict) -> Optional[NormalizedAlert]:
    """A Wazuh manager alert record — the JSON-lines format written to
    `/var/ossec/logs/alerts/alerts.json`, and also what a Wazuh
    `<integration>` custom-integration script typically forwards
    unmodified (see examples/wazuh_integration.py). A line with no `rule`
    object isn't a real alert record and returns None.

    Field-parsing is built from Wazuh's documented alert JSON schema, not
    verified against a live Wazuh manager — this project has none to
    honestly test against (the same caveat as any other vendor-specific
    integration; see README's Known Gaps). If your Wazuh alerts don't map
    cleanly, the fix is almost certainly here, not in the pipeline.
    """
    rule = payload.get("rule") or {}
    if not rule:
        return None

    agent = payload.get("agent") or {}
    data = payload.get("data") or {}

    rule_id = str(rule.get("id", "0"))
    level = rule.get("level", 0)
    rule_description = rule.get("description", "Unnamed Wazuh rule")
    agent_name = agent.get("name") or "unknown-agent"
    severity = _wazuh_level_to_severity(level)

    src_ip = data.get("srcip")
    dst_ip = data.get("dstip")
    iocs = [str(ip) for ip in (src_ip, dst_ip) if ip]
    for hash_field in ("md5", "sha1", "sha256"):
        value = data.get(hash_field)
        if value:
            iocs.append(str(value))
    url = data.get("url")
    if url:
        iocs.append(str(url))

    mitre_ids = (rule.get("mitre") or {}).get("id") or []
    mitre_suffix = f" [ATT&CK: {', '.join(str(m) for m in mitre_ids)}]" if mitre_ids else ""

    description = (
        f"Wazuh alert (level {level}, rule {rule_id}): {rule_description} on {agent_name}"
        + (f" — src={src_ip}" if src_ip else "")
        + mitre_suffix
    )
    assets = [str(agent_name)] if agent_name != "unknown-agent" else []

    return NormalizedAlert(
        description=description,
        severity=severity,
        source="wazuh",
        affected_assets=assets,
        iocs=iocs[:50],
        dedup_key=f"wazuh:{rule_id}:{agent.get('id', '0')}:{src_ip or 'na'}",
        raw_excerpt=json.dumps(payload)[:2000],
    )


# Splunk Enterprise Security's notable-event urgency scale is five
# values, not our four — "informational" has no exact match, and mapping
# it to "medium" (the fallback every other normalizer here uses for an
# unrecognized value) would overstate it; "low" is the honest mapping.
_SPLUNK_URGENCY_MAP = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def normalize_splunk(payload: dict) -> Optional[NormalizedAlert]:
    """A Splunk Enterprise Security notable-event record — the flat
    per-event dict shape a `search index=notable | fields ...` search
    returns in its own JSON `results` array (see
    examples/splunk_poller_config.example.json), and also what Splunk's
    built-in "Webhook" alert action POSTs (wrapped in a top-level
    `result` key) when used as a push alternative — point that webhook
    at `POST /ingest/splunk` instead of polling. A record with no
    `rule_name`/`search_name` isn't treated as a real notable event and
    returns None.

    Field-parsing is built from Splunk ES's documented notable-event
    field names, not verified against a live Splunk instance — this
    project has none to honestly test against (the same caveat as any
    other vendor-specific integration; see README's Known Gaps). If your
    Splunk alerts don't map cleanly, the fix is almost certainly here,
    not in the pipeline.
    """
    record = payload.get("result") if isinstance(payload.get("result"), dict) else payload

    rule_name = record.get("rule_name") or record.get("search_name")
    if not rule_name:
        return None

    urgency = str(record.get("urgency") or "").lower()
    severity = _SPLUNK_URGENCY_MAP.get(urgency, "medium")

    src = record.get("src")
    dest = record.get("dest")
    dvc = record.get("dvc")
    signature = record.get("signature")
    event_id = record.get("event_id") or record.get("_time") or "0"

    mitre_raw = record.get("mitre_technique_id") or ""
    if isinstance(mitre_raw, list):
        mitre_ids = [str(m) for m in mitre_raw]
    else:
        mitre_ids = [m.strip() for m in str(mitre_raw).split(",") if m.strip()]
    mitre_suffix = f" [ATT&CK: {', '.join(mitre_ids)}]" if mitre_ids else ""

    description = (
        f"Splunk notable event: {rule_name}"
        + (f" — {signature}" if signature else "")
        + (f" (src={src}, dest={dest})" if src or dest else "")
        + mitre_suffix
    )
    iocs = [str(v) for v in (src, dest) if v]
    assets = [str(v) for v in (dest, dvc) if v]

    return NormalizedAlert(
        description=description,
        severity=severity,
        source="splunk",
        affected_assets=assets[:50],
        iocs=iocs[:50],
        dedup_key=f"splunk:{event_id}:{src or 'na'}:{dest or 'na'}",
        raw_excerpt=json.dumps(payload, default=str)[:2000],
    )


_ELASTIC_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _dig(data, dotted_path: str):
    """Walk a dotted path into nested dicts — Elastic Security's real ECS
    alert documents nest fields (`{"kibana": {"alert": {"rule": {"name":
    ...}}}}`), not flat dotted-string keys, so a plain `.get("a.b.c")`
    would never find anything. Returns None anywhere the path doesn't
    resolve rather than raising — this is untrusted, externally-served
    data, and a missing/reshaped field should degrade a record, not
    crash the connector.
    """
    node = data
    for part in dotted_path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def normalize_elastic(payload: dict) -> Optional[NormalizedAlert]:
    """One Elastic Security detection-alert document — either a full
    Elasticsearch search hit (`{"_id": ..., "_source": {...ECS fields...}}`,
    what querying `.alerts-security.alerts-<space>/_search` returns) or a
    bare `_source` dict, so this also works if something in front of the
    poller already unwraps hits itself. A record with no
    `kibana.alert.rule.name` isn't treated as a real alert and returns
    None.

    Fetched via Elasticsearch's own URI Search API (a plain GET with a
    Lucene `q=` query string and an `Authorization: ApiKey <...>` header)
    — see examples/elastic_poller_config.example.json — which fits
    ingestion/polling.py's generic PollerConfig directly with no new
    connector module needed, the same tier as Splunk. This function
    exists (rather than a flat field_map) for two things flat mapping
    can't express: combining `source.ip`/`destination.ip` into one iocs
    list (the same reason Splunk's own normalizer above isn't a flat
    field_map either), and routing real EDR-native process context
    (`process.name`/`process.command_line`/`process.parent.name`) into
    NormalizedAlert's dedicated process_name/command_line/
    parent_process_name fields (see ingestion/schemas.py and README's
    "Process indicator" glossary entry) — a natural pairing, since
    Elastic Security alerts are exactly the kind of source that actually
    carries this context.

    Elastic's own severity scale (`low`/`medium`/`high`/`critical`)
    already matches Cavendex's four-value scale exactly — no remapping
    needed, unlike Splunk's five-value urgency scale or CrowdStrike's
    numeric one.

    Field-parsing is built from Elastic's documented ECS/Detection Engine
    alert schema, not verified against a live Elastic deployment — this
    project has none to honestly test against (the same caveat as every
    other vendor-specific integration; see README's Known Gaps).
    """
    source = payload.get("_source") if isinstance(payload.get("_source"), dict) else payload
    if not isinstance(source, dict):
        return None

    rule_name = _dig(source, "kibana.alert.rule.name")
    if not rule_name:
        return None

    severity_raw = str(_dig(source, "kibana.alert.severity") or "").lower()
    severity = severity_raw if severity_raw in _ELASTIC_VALID_SEVERITIES else "medium"

    src_ip = _dig(source, "source.ip")
    dst_ip = _dig(source, "destination.ip")
    host_name = _dig(source, "host.name")
    process_name = _dig(source, "process.name")
    command_line = _dig(source, "process.command_line")
    parent_name = _dig(source, "process.parent.name")

    technique_ids = _dig(source, "threat.technique.id") or []
    if isinstance(technique_ids, str):
        technique_ids = [technique_ids]
    mitre_suffix = f" [ATT&CK: {', '.join(str(t) for t in technique_ids)}]" if technique_ids else ""

    doc_id = payload.get("_id") or _dig(source, "kibana.alert.uuid") or "0"

    description = (
        f"Elastic Security alert: {rule_name}"
        + (f" (src={src_ip}, dest={dst_ip})" if src_ip or dst_ip else "")
        + mitre_suffix
    )

    return NormalizedAlert(
        description=description[:4000],
        severity=severity,
        source="elastic",
        affected_assets=[str(host_name)] if host_name else [],
        iocs=[str(v) for v in (src_ip, dst_ip) if v][:50],
        process_name=str(process_name) if process_name else None,
        command_line=str(command_line) if command_line else None,
        parent_process_name=str(parent_name) if parent_name else None,
        dedup_key=f"elastic:{doc_id}",
        raw_excerpt=json.dumps(payload, default=str)[:2000],
    )


# CrowdStrike's Detects API reports severity as both a 0-100 numeric
# score and this five-value display name — the display name maps
# directly onto our own scale except "informational," the same
# below-our-floor case Splunk's urgency scale has.
_CROWDSTRIKE_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "low",
}


def normalize_crowdstrike(payload: dict) -> Optional[NormalizedAlert]:
    """A CrowdStrike Falcon Detects API detection-summary record — the
    JSON shape `POST /detects/entities/summaries/GET/v1` returns per
    detection (see ingestion/crowdstrike_polling.py, the dedicated
    connector that fetches these; registered here too so the same shape
    can also be pushed to `POST /ingest/crowdstrike` if you'd rather
    forward detections via your own script than run the poller). A
    record with no `detection_id` isn't a real detection and returns
    None.

    Field-parsing is built from CrowdStrike's documented Detects API
    schema, not verified against a live Falcon tenant — this project has
    none to honestly test against (the same caveat as any other
    vendor-specific integration; see README's Known Gaps).
    """
    detection_id = payload.get("detection_id")
    if not detection_id:
        return None

    severity_name = str(payload.get("max_severity_displayname") or "").lower()
    severity = _CROWDSTRIKE_SEVERITY_MAP.get(severity_name, "medium")

    device = payload.get("device") or {}
    hostname = device.get("hostname")

    behaviors = payload.get("behaviors") or []
    technique_ids = []
    technique_names = []
    iocs = []
    for behavior in behaviors:
        if not isinstance(behavior, dict):
            continue
        technique_id = behavior.get("technique_id")
        if technique_id:
            technique_ids.append(str(technique_id))
        technique_name = behavior.get("technique") or technique_id
        if technique_name:
            technique_names.append(str(technique_name))
        ioc_value = behavior.get("ioc_value")
        if ioc_value:
            iocs.append(str(ioc_value))

    mitre_suffix = f" [ATT&CK: {', '.join(dict.fromkeys(technique_ids))}]" if technique_ids else ""
    behavior_suffix = f" — {', '.join(list(dict.fromkeys(technique_names))[:3])}" if technique_names else ""

    description = f"CrowdStrike detection on {hostname or 'unknown host'}{behavior_suffix}{mitre_suffix}"
    assets = [str(hostname)] if hostname else []

    return NormalizedAlert(
        description=description,
        severity=severity,
        source="crowdstrike",
        affected_assets=assets,
        iocs=[str(i) for i in dict.fromkeys(iocs)][:50],
        dedup_key=f"crowdstrike:{detection_id}",
        raw_excerpt=json.dumps(payload, default=str)[:2000],
    )


# QRadar's magnitude is a documented 0-10 composite score (combining
# severity/credibility/relevance) that IBM recommends using for triage
# prioritization over the raw severity field alone -- the same "a
# numeric scale needs its own threshold mapping" case as Suricata's and
# CEF's own severity numbers above.
_QRADAR_MAGNITUDE_THRESHOLDS = ((9, "critical"), (7, "high"), (4, "medium"))


def _qradar_magnitude_to_severity(magnitude) -> str:
    try:
        n = int(magnitude)
    except (TypeError, ValueError):
        return "medium"
    for threshold, severity in _QRADAR_MAGNITUDE_THRESHOLDS:
        if n >= threshold:
            return severity
    return "low"


_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def normalize_qradar(payload: dict) -> Optional[NormalizedAlert]:
    """One IBM QRadar Offense record — the JSON shape `GET
    /api/siem/offenses` returns per offense (see
    examples/qradar_poller_config.example.json, which fits
    ingestion/polling.py's generic PollerConfig directly — a plain GET
    with a static `SEC` header token, no OAuth2 or multi-step
    choreography needed, the same tier as Splunk/Elastic). A record with
    no `id` isn't a real offense and returns None.

    Uses `magnitude` (a documented 0-10 composite of
    severity/credibility/relevance IBM recommends for triage
    prioritization) for severity, not the narrower raw `severity` field
    alone — neither is expressible via the generic connector's
    string-keyed severity_map, which is why this needs a real normalizer
    rather than a flat field_map, the same reason Suricata/CEF's own
    numeric scales above do.

    `offense_source` is QRadar's own catch-all "source of the offense"
    field — depending on `offense_type` it can be a source IP, a
    username, a MAC address, or a hostname, and the offense JSON gives no
    separate type tag to tell those apart. It's only treated as an IOC
    when it actually looks like a dotted-quad IP; otherwise it's folded
    into the description as context instead of risked as a
    mis-typed indicator — the same "don't infer past what the shape
    actually tells you" reasoning as this file's own `Process indicator`
    handling.

    QRadar has no MITRE ATT&CK mapping at this endpoint — `categories`
    are QRadar's own rule-category names, not ATT&CK technique IDs, so
    they're surfaced as plain context rather than misrepresented as a
    `[ATT&CK: ...]` suffix the way Wazuh/Splunk/CrowdStrike's real
    technique IDs are.

    Field-parsing is built from IBM's documented QRadar REST API Offense
    schema, not verified against a live QRadar deployment — this project
    has none to honestly test against (the same caveat as any other
    vendor-specific integration; see README's Known Gaps).
    """
    offense_id = payload.get("id")
    if offense_id is None:
        return None

    magnitude = payload.get("magnitude", payload.get("severity", 0))
    severity = _qradar_magnitude_to_severity(magnitude)

    offense_description = payload.get("description") or "Unnamed QRadar offense"
    offense_source = payload.get("offense_source")
    categories = [str(c) for c in (payload.get("categories") or []) if c][:5]
    category_suffix = f" [{', '.join(categories)}]" if categories else ""

    destination_networks = [str(n) for n in (payload.get("destination_networks") or []) if n][:50]

    iocs = [str(offense_source)] if offense_source and _IP_RE.match(str(offense_source)) else []

    description = (
        f"QRadar offense (magnitude {magnitude}): {offense_description}"
        + (f" — source={offense_source}" if offense_source else "")
        + category_suffix
    )

    return NormalizedAlert(
        description=description[:4000],
        severity=severity,
        source="qradar",
        affected_assets=destination_networks,
        iocs=iocs,
        dedup_key=f"qradar:{offense_id}",
        raw_excerpt=json.dumps(payload, default=str)[:2000],
    )


# Sentinel's SecurityAlert.AlertSeverity is a documented four-value
# scale, matching CrowdStrike's naming exactly (including the
# below-our-floor "informational" case).
_SENTINEL_SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "low",
}


def _sentinel_dynamic(value):
    """Sentinel's Log Analytics `dynamic` columns (Entities,
    ExtendedProperties) come back from the query API as JSON already
    parsed into Python (list/dict) when the client parses the response
    body as JSON — but a caller that's serialized/deserialized a record
    in between (e.g. round-tripped through this project's own dedup/
    audit-log JSON encoding) may see it as a JSON *string* instead.
    Handles both rather than assuming one, the same defensive parsing
    every other normalizer here does for untrusted, externally-served
    data.
    """
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    return value


def normalize_sentinel(payload: dict) -> Optional[NormalizedAlert]:
    """One Microsoft Sentinel `SecurityAlert` record — one row of the
    Log Analytics KQL query `SecurityAlert | order by TimeGenerated asc`
    (see ingestion/sentinel_polling.py, the dedicated connector that
    fetches these — Azure AD OAuth2 plus a KQL query call, which
    ingestion/polling.py's generic PollerConfig can't express, the same
    "materially different scheme" tier as CrowdStrike). A record with no
    `AlertName` isn't a real alert and returns None.

    `SecurityAlert` (individual detections) is used here rather than the
    higher-level `SecurityIncident` table (Sentinel's own grouped case
    object) specifically because `SecurityIncident` doesn't carry raw
    IOC entities at all — every other connector in this project
    normalizes discrete alerts/detections, not pre-aggregated cases, and
    `SecurityAlert.Entities` is the one Sentinel table that actually has
    IP/file-hash/URL/domain indicators to extract.

    `Entities` is Sentinel's own dynamic JSON array of typed indicators
    (`{"Type": "ip", "Address": "..."}`, `{"Type": "file", "FileHash":
    [...]}`, `{"Type": "url", "Url": "..."}`, `{"Type": "dns",
    "DomainName": "..."}`, `{"Type": "host", "HostName": "..."}` —
    Microsoft's documented entity schema); `ExtendedProperties` may carry
    a `Techniques` list of MITRE ATT&CK technique IDs when the
    originating analytics rule tagged one.

    Field-parsing is built from Microsoft's documented Log Analytics
    `SecurityAlert` table schema, not verified against a live Sentinel
    workspace — this project has none to honestly test against (the same
    caveat as every other vendor-specific integration; see README's
    Known Gaps).
    """
    alert_name = payload.get("AlertName")
    if not alert_name:
        return None

    severity_raw = str(payload.get("AlertSeverity") or "").lower()
    severity = _SENTINEL_SEVERITY_MAP.get(severity_raw, "medium")

    entities = _sentinel_dynamic(payload.get("Entities")) or []
    if not isinstance(entities, list):
        entities = []

    iocs: list = []
    assets: list = []
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        entity_type = str(entity.get("Type") or "").lower()
        if entity_type == "ip" and entity.get("Address"):
            iocs.append(str(entity["Address"]))
        elif entity_type == "url" and entity.get("Url"):
            iocs.append(str(entity["Url"]))
        elif entity_type in ("dns", "domain") and entity.get("DomainName"):
            iocs.append(str(entity["DomainName"]))
        elif entity_type == "file":
            for file_hash in entity.get("FileHash") or []:
                value = file_hash.get("Value") if isinstance(file_hash, dict) else file_hash
                if value:
                    iocs.append(str(value))
        elif entity_type == "host" and entity.get("HostName"):
            assets.append(str(entity["HostName"]))

    compromised_entity = payload.get("CompromisedEntity")
    if compromised_entity:
        assets.append(str(compromised_entity))

    extended_properties = _sentinel_dynamic(payload.get("ExtendedProperties")) or {}
    technique_ids = extended_properties.get("Techniques") if isinstance(extended_properties, dict) else None
    if isinstance(technique_ids, str):
        technique_ids = [t.strip() for t in technique_ids.split(",") if t.strip()]
    mitre_suffix = (
        f" [ATT&CK: {', '.join(str(t) for t in technique_ids)}]" if isinstance(technique_ids, list) and technique_ids else ""
    )

    alert_description = payload.get("Description")
    description = (
        f"Sentinel alert: {alert_name}"
        + (f" — {alert_description}" if alert_description else "")
        + (f" (host={compromised_entity})" if compromised_entity else "")
        + mitre_suffix
    )

    system_alert_id = payload.get("SystemAlertId") or payload.get("TimeGenerated") or "0"

    return NormalizedAlert(
        description=description[:4000],
        severity=severity,
        source="sentinel",
        affected_assets=[str(a) for a in dict.fromkeys(assets)][:50],
        iocs=[str(i) for i in dict.fromkeys(iocs)][:50],
        dedup_key=f"sentinel:{system_alert_id}",
        raw_excerpt=json.dumps(payload, default=str)[:2000],
    )


NORMALIZERS = {
    "generic": normalize_generic,
    "suricata": normalize_suricata_eve,
    "syslog_cef": normalize_syslog_cef,
    "wazuh": normalize_wazuh,
    "splunk": normalize_splunk,
    "crowdstrike": normalize_crowdstrike,
    "elastic": normalize_elastic,
    "qradar": normalize_qradar,
    "sentinel": normalize_sentinel,
}
