"""A dedicated Microsoft Sentinel polling connector — pulls new
SecurityAlert records from a Log Analytics workspace via Sentinel's own
KQL query API and feeds them into the ingestion pipeline via
ingestion/normalizers.py:normalize_sentinel().

Not built on ingestion/polling.py's generic PollerConfig, unlike most
other SIEM/EDR integrations: Sentinel's real API needs an Azure AD
OAuth2 client-credentials token exchange before any data call, and the
data call itself isn't a plain field-mapped GET/POST -- it's a KQL query
POSTed to the Log Analytics query API, whose response is a columnar
{"tables": [{"columns": [...], "rows": [...]}]} shape that needs zipping
into per-record dicts before a normalizer can use it. This is exactly
the "materially different scheme" ingestion/polling.py's own docstring
already points to needing real code for, the same reason CrowdStrike
has its own dedicated connector instead of going through the generic
path.

Field-parsing and endpoint shapes are built from Microsoft's documented
Log Analytics/Sentinel REST API and the SecurityAlert table schema, not
verified against a live Sentinel workspace — this project has none to
honestly test against (the same caveat as any other vendor-specific
integration; see README's Known Gaps).
"""

import json
import os
import time
from typing import List, Optional, Tuple

from pydantic import BaseModel, Field

from graph import tenant_data_dir
from utils.tenancy import DEFAULT_TENANT, sanitize_tenant_id


class SentinelConfig(BaseModel):
    name: str = Field(max_length=100)
    # Log Analytics workspace GUID (Sentinel -> Settings -> Workspace
    # settings -> Workspace ID) -- not a secret, safe in this config
    # file like CrowdStrikeConfig.base_url.
    workspace_id: str
    # Names of ENVIRONMENT VARIABLES holding the real Azure AD app
    # registration's directory (tenant) ID and OAuth2 client
    # credentials -- this config file never contains a secret itself,
    # the same pattern CrowdStrikeConfig.client_id_env/client_secret_env
    # uses.
    azure_ad_tenant_id_env: str = "AZURE_SENTINEL_TENANT_ID"
    client_id_env: str = "AZURE_SENTINEL_CLIENT_ID"
    client_secret_env: str = "AZURE_SENTINEL_CLIENT_SECRET"
    # Real, fixed Microsoft hostnames by default -- overridable because
    # Azure's sovereign clouds (Azure Government, Azure China) use
    # genuinely different hostnames for both endpoints
    # (login.microsoftonline.us/api.loganalytics.us,
    # login.chinacloudapi.cn/api.loganalytics.azure.cn), the same reason
    # CrowdStrikeConfig.base_url is configurable rather than hardcoded.
    login_base_url: str = "https://login.microsoftonline.com"
    api_base_url: str = "https://api.loganalytics.io"
    # The Log Analytics table to poll -- SecurityAlert (individual
    # detections) by default, since that's the one table that actually
    # carries raw IOC entities (see normalize_sentinel()'s own docstring
    # for why SecurityIncident, Sentinel's higher-level case object,
    # isn't used instead).
    table: str = "SecurityAlert"
    page_size: int = Field(default=100, ge=1, le=1000)
    poll_interval_seconds: float = 60.0
    tenant: str = DEFAULT_TENANT
    source_name: str = Field(default="sentinel", max_length=100)


# Keyed by (azure_ad_tenant_id, client_id) -> (token,
# expires_at_monotonic) -- a module-level cache, not per-config, the
# same reasoning as crowdstrike_polling.py's _token_cache.
_token_cache: dict = {}


def _get_oauth_token(config: SentinelConfig) -> Optional[str]:
    """A cached Azure AD OAuth2 bearer token, refreshed via a real
    client-credentials exchange when missing or close to expiry. Returns
    None if the credentials aren't configured at all -- distinguished
    from a failed exchange (which raises, the same as any other real
    HTTP error in this project's connectors) so a caller can tell "not
    set up yet" apart from "set up but broken."
    """
    azure_ad_tenant_id = os.getenv(config.azure_ad_tenant_id_env)
    client_id = os.getenv(config.client_id_env)
    client_secret = os.getenv(config.client_secret_env)
    if not (azure_ad_tenant_id and client_id and client_secret):
        return None

    cache_key = (azure_ad_tenant_id, client_id)
    cached = _token_cache.get(cache_key)
    if cached and cached[1] > time.monotonic():
        return cached[0]

    import requests

    response = requests.post(
        f"{config.login_base_url}/{azure_ad_tenant_id}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://api.loganalytics.io/.default",
        },
        headers={"Accept": "application/json"},
        timeout=30,
    )
    response.raise_for_status()
    body = response.json() or {}
    token = body.get("access_token")
    if not token:
        return None

    expires_in = body.get("expires_in", 3599)
    # Refresh a little early so an in-flight request never starts
    # against a token that's about to expire mid-request.
    _token_cache[cache_key] = (token, time.monotonic() + max(expires_in - 60, 30))
    return token


def _build_query(config: SentinelConfig, cursor: Optional[str]) -> str:
    """Sentinel's Log Analytics query API takes one KQL string, not a
    set of filter parameters -- `cursor` (the last-seen record's own
    TimeGenerated, an ISO 8601 timestamp this connector wrote itself on
    a previous poll, never attacker-controlled) is interpolated directly
    into a `datetime(...)` literal rather than parameterized, since KQL
    over this API has no separate bind-parameter mechanism the way a SQL
    driver would.
    """
    base = f"{config.table} | order by TimeGenerated asc | take {config.page_size}"
    if not cursor:
        return base
    return (
        f"{config.table} | where TimeGenerated > datetime({cursor}) "
        f"| order by TimeGenerated asc | take {config.page_size}"
    )


def _rows_to_records(table: dict) -> List[dict]:
    """The Log Analytics query API returns one table as {"columns":
    [{"name": ...}, ...], "rows": [[...], ...]} -- a columnar shape, not
    a list of per-record dicts. Zips each row against the column names
    so downstream code (normalize_sentinel()) can work with ordinary
    dicts like every other normalizer in this project.
    """
    columns = [c.get("name") for c in (table.get("columns") or [])]
    return [dict(zip(columns, row)) for row in (table.get("rows") or [])]


def fetch_new_alerts(config: SentinelConfig, token: str, cursor: Optional[str]) -> Tuple[List[dict], Optional[str]]:
    """One real HTTP call: a KQL query POSTed to the Log Analytics query
    API. Returns (records, new_cursor) -- new_cursor is unchanged if
    nothing came back.
    """
    import requests

    query = _build_query(config, cursor)
    response = requests.post(
        f"{config.api_base_url}/v1/workspaces/{config.workspace_id}/query",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"query": query},
        timeout=30,
    )
    response.raise_for_status()

    body = response.json() or {}
    tables = body.get("tables") or []
    records = _rows_to_records(tables[0]) if tables else []

    new_cursor = cursor
    for record in records:
        ts = record.get("TimeGenerated")
        if ts and (new_cursor is None or str(ts) > str(new_cursor)):
            new_cursor = ts

    return records, new_cursor


def _state_path(config: SentinelConfig) -> str:
    tenant_id = sanitize_tenant_id(config.tenant)
    directory = os.path.join(tenant_data_dir(tenant_id), "poller_state")
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, f"{config.name}.json")


def load_cursor(config: SentinelConfig) -> Optional[str]:
    path = _state_path(config)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f).get("cursor")
    except (json.JSONDecodeError, OSError):
        return None


def save_cursor(config: SentinelConfig, cursor: Optional[str]) -> None:
    with open(_state_path(config), "w", encoding="utf-8") as f:
        json.dump({"cursor": cursor}, f)


def poll_once(config: SentinelConfig) -> List[dict]:
    """Fetch, normalize, and ingest one batch of alerts. Returns the
    list of ingest_normalized_alert() outcome dicts, one per record that
    normalized to a real alert -- or a single {"outcome": "auth_failed"}
    entry (no HTTP call attempted beyond the token exchange) if Azure AD
    credentials aren't configured, so a caller can tell "not set up"
    apart from "set up, no new alerts."
    """
    from ingestion.normalizers import normalize_sentinel
    from ingestion.pipeline import ingest_normalized_alert

    token = _get_oauth_token(config)
    if not token:
        return [{"outcome": "auth_failed"}]

    cursor = load_cursor(config)
    records, new_cursor = fetch_new_alerts(config, token, cursor)

    results = []
    for record in records:
        alert = normalize_sentinel(record)
        if alert is None:
            continue
        results.append(ingest_normalized_alert(alert, tenant_id=config.tenant))

    if new_cursor != cursor:
        save_cursor(config, new_cursor)

    return results


def load_config(path: str) -> SentinelConfig:
    with open(path, encoding="utf-8") as f:
        return SentinelConfig.model_validate(json.load(f))
