"""A generic, configurable connector for pulling alerts from a SIEM/EDR's
own REST API — the pull-based counterpart to /ingest/{source} (push) and
syslog_listener.py (network-received).

Deliberately not hardcoded to any specific vendor's URL/auth/JSON shape
by default: PollerConfig describes how to talk to *any* JSON-returning
HTTP endpoint — base URL, auth (a header name plus an env var to read
the token from, never the token itself), where in the response body the
list of alerts lives, and how to map each alert record's own field names
onto NormalizedAlert's fields. Point it at your actual SIEM/EDR's
alert-listing endpoint and describe its shape in a config file; no code
changes needed, the same "pluggable, not vendor-locked" principle as
ingestion/normalizers.py.

A vendor whose alert schema is flat and whose auth is a single static
token (most REST-API SIEMs) fits the field_map approach directly — see
examples/poller_config.example.json. A vendor with a genuinely different
scheme (nested fields needing real extraction logic, non-standard
severity naming, or auth that isn't a static bearer token) needs more
than field-mapping can express; `normalizer` (below) is the escape
hatch for the first two cases — set it to a name registered in
ingestion/normalizers.py's NORMALIZERS and every record is handed to
that function directly instead of the generic field_map (see
examples/splunk_poller_config.example.json, which uses this for
Splunk's five-value urgency scale and nested MITRE ATT&CK annotations).
Auth that isn't a static token at all — CrowdStrike's OAuth2
client-credentials exchange, for instance — is genuinely outside what
this module can express; ingestion/crowdstrike_polling.py is a fully
separate, dedicated connector for that case, the same reason Wazuh has
its own normalizer and integration script instead of going through this
generic path.
"""

import hashlib
import json
import os
from typing import List, Literal, Optional, Tuple

from pydantic import BaseModel, Field

from graph import tenant_data_dir
from ingestion.schemas import NormalizedAlert
from utils.tenancy import DEFAULT_TENANT, sanitize_tenant_id

_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class PollerConfig(BaseModel):
    name: str = Field(max_length=100)
    base_url: str
    method: Literal["GET", "POST"] = "GET"
    # Auth: the header to set (e.g. "Authorization") and the *name* of an
    # environment variable holding the actual secret — the config file
    # itself never contains a token, so it's safe to keep alongside code.
    auth_header: Optional[str] = None
    auth_token_env: Optional[str] = None
    auth_scheme: Optional[str] = None  # e.g. "Bearer" -> "Bearer <token>"; None -> just "<token>"
    # Dotted path into the JSON response body to the list of alert
    # records, e.g. "results" or "data.alerts". Empty/None means the
    # response body itself is that list.
    records_path: Optional[str] = None
    # Incremental polling: after each fetch, the last record's
    # `cursor_field` (dotted path within one record) is remembered and
    # sent back as `cursor_query_param` on the next request. Leave either
    # unset to always fetch fresh with no narrowing.
    cursor_query_param: Optional[str] = None
    cursor_field: Optional[str] = None
    # Maps NormalizedAlert field names -> a dotted path within one record
    # in *this* API's own shape, e.g. {"description": "title",
    # "severity": "priority", "iocs": "indicators"}. Ignored if
    # `normalizer` is set.
    field_map: dict = Field(default_factory=dict)
    # Remaps this API's own severity string (lowercased) onto our four-
    # value scale before the field_map path's usual "unrecognized ->
    # medium" fallback -- e.g. {"informational": "low"} for a vendor
    # whose scale doesn't line up with ours 1:1. Ignored if `normalizer`
    # is set (a normalizer function does its own severity mapping).
    severity_map: dict = Field(default_factory=dict)
    # Escape hatch for a vendor whose alert shape needs real extraction
    # logic (nested fields, non-standard severity naming) that flat
    # field_map/severity_map can't express: the name of a function
    # registered in ingestion/normalizers.py's NORMALIZERS, called
    # directly on each raw record instead of normalize_polled_record.
    # See this module's own docstring for when to reach for this.
    normalizer: Optional[str] = None
    static_query_params: dict = Field(default_factory=dict)
    poll_interval_seconds: float = 60.0
    tenant: str = DEFAULT_TENANT
    source_name: str = Field(default="polling", max_length=100)


def _get_nested(data, path: Optional[str]):
    """Walk a dotted path (dict keys and/or list indices) into `data`.
    Returns None anywhere the path doesn't resolve, rather than raising —
    a SIEM's API response is untrusted, externally-controlled input, and
    a misconfigured or absent field should degrade a record, not crash
    the connector.
    """
    if not path:
        return data
    node = data
    for part in path.split("."):
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return node


def normalize_polled_record(
    record: dict, field_map: dict, source_name: str, severity_map: Optional[dict] = None
) -> Optional[NormalizedAlert]:
    """Map one record from a polled API's own JSON shape onto a
    NormalizedAlert, using `field_map` to find each value. Returns None
    only if `record` isn't a dict at all — unlike the fixed-format
    normalizers in ingestion/normalizers.py, there's no format-specific
    "not alert-worthy" concept here; every returned record is treated as
    an alert (filtering what an API returns is the API's own job, or a
    future field_map addition, not this connector's).
    """
    if not isinstance(record, dict):
        return None

    def get(key):
        # An unmapped field must resolve to "no value," not to the whole
        # record — _get_nested(record, None) means "the path is empty,
        # return the root," which is the right behavior for
        # PollerConfig.records_path but the wrong one here.
        path = field_map.get(key)
        if path is None:
            return None
        return _get_nested(record, path)

    description = get("description")
    description = str(description) if description else "Untitled alert"

    severity = get("severity")
    severity = str(severity).lower() if isinstance(severity, str) else None
    if severity_map and severity in severity_map:
        severity = severity_map[severity]
    severity = severity if severity in _VALID_SEVERITIES else "medium"

    source = get("source")
    source = str(source) if source else source_name

    def _as_list(value) -> List[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            value = [value]
        return [str(v) for v in value][:50]

    affected_assets = _as_list(get("affected_assets"))
    iocs = _as_list(get("iocs"))

    dedup_key = get("dedup_key")
    if not dedup_key:
        dedup_key = hashlib.sha256(
            json.dumps(record, sort_keys=True, default=str).encode()
        ).hexdigest()[:32]

    return NormalizedAlert(
        description=description[:4000],
        severity=severity,
        source=source[:300],
        affected_assets=affected_assets,
        iocs=iocs,
        dedup_key=str(dedup_key)[:300],
        raw_excerpt=json.dumps(record, default=str)[:2000],
    )


def _build_headers(config: PollerConfig) -> dict:
    if not (config.auth_header and config.auth_token_env):
        return {}
    token = os.getenv(config.auth_token_env)
    if not token:
        return {}
    value = f"{config.auth_scheme} {token}" if config.auth_scheme else token
    return {config.auth_header: value}


def fetch_records(config: PollerConfig, cursor: Optional[str]) -> Tuple[List[dict], Optional[str]]:
    """One real HTTP call to `config.base_url`. Returns (records,
    new_cursor) — new_cursor is unchanged from the input if cursor_field
    isn't configured or no records came back.
    """
    import requests

    params = dict(config.static_query_params)
    if config.cursor_query_param and cursor:
        params[config.cursor_query_param] = cursor

    response = requests.request(
        config.method, config.base_url, headers=_build_headers(config), params=params, timeout=30
    )
    response.raise_for_status()

    body = response.json()
    records = _get_nested(body, config.records_path)
    if records is None:
        records = []
    if not isinstance(records, list):
        records = [records]

    new_cursor = cursor
    if config.cursor_field and records:
        last_value = _get_nested(records[-1], config.cursor_field)
        if last_value is not None:
            new_cursor = str(last_value)

    return records, new_cursor


def _state_path(config: PollerConfig) -> str:
    tenant_id = sanitize_tenant_id(config.tenant)
    directory = os.path.join(tenant_data_dir(tenant_id), "poller_state")
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, f"{config.name}.json")


def load_cursor(config: PollerConfig) -> Optional[str]:
    path = _state_path(config)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f).get("cursor")
    except (json.JSONDecodeError, OSError):
        return None


def save_cursor(config: PollerConfig, cursor: Optional[str]) -> None:
    with open(_state_path(config), "w", encoding="utf-8") as f:
        json.dump({"cursor": cursor}, f)


def poll_once(config: PollerConfig) -> List[dict]:
    """Fetch, normalize, and ingest one batch of records — the unit of
    work both the long-running loop and a cron-style single-shot
    invocation share. Returns the list of ingest_normalized_alert()
    outcome dicts, one per record that was actually a dict.

    Uses config.normalizer (a NORMALIZERS-registered function, called
    directly on each raw record) when set; otherwise the generic
    field_map/severity_map-driven normalize_polled_record. A
    config.normalizer name that isn't actually registered skips every
    record (never ingests anything) rather than silently falling back to
    the generic path -- a typo'd name should fail loud enough to notice,
    not quietly start guessing at a completely different field_map that
    was never configured for it.
    """
    from ingestion.pipeline import ingest_normalized_alert

    normalizer_requested = bool(config.normalizer)
    normalizer_fn = None
    if normalizer_requested:
        from ingestion.normalizers import NORMALIZERS

        normalizer_fn = NORMALIZERS.get(config.normalizer)

    cursor = load_cursor(config)
    records, new_cursor = fetch_records(config, cursor)

    results = []
    for record in records:
        if normalizer_requested:
            alert = normalizer_fn(record) if normalizer_fn and isinstance(record, dict) else None
        else:
            alert = normalize_polled_record(record, config.field_map, config.source_name, config.severity_map)
        if alert is None:
            continue
        results.append(ingest_normalized_alert(alert, tenant_id=config.tenant))

    if new_cursor != cursor:
        save_cursor(config, new_cursor)

    return results


def load_config(path: str) -> PollerConfig:
    with open(path, encoding="utf-8") as f:
        return PollerConfig.model_validate(json.load(f))
