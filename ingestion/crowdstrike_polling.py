"""A dedicated CrowdStrike Falcon polling connector — pulls new
detections from the Falcon Detects API and feeds them into the
ingestion pipeline via ingestion/normalizers.py:normalize_crowdstrike().

Not built on ingestion/polling.py's generic PollerConfig, unlike most
other SIEM/EDR integrations: CrowdStrike's real API needs an OAuth2
client-credentials token exchange (with expiry and refresh) before any
data call, and fetching one batch of detections is a real two-step
choreography — query matching detection IDs, then POST those IDs to a
separate endpoint for full summaries — not the single GET/POST per poll
PollerConfig's model assumes. This is exactly the "materially different
scheme" ingestion/polling.py's own docstring already points to needing
real code for, the same reason Wazuh has its own normalizer and
integration script instead of going through the generic path.

Field-parsing and endpoint shapes are built from CrowdStrike's
documented Falcon Detects API, not verified against a live Falcon
tenant — this project has none to honestly test against (the same
caveat as any other vendor-specific integration; see README's Known
Gaps).
"""

import json
import os
import time
from typing import List, Optional, Tuple

from pydantic import BaseModel, Field

from graph import tenant_data_dir
from utils.tenancy import DEFAULT_TENANT, sanitize_tenant_id


class CrowdStrikeConfig(BaseModel):
    name: str = Field(max_length=100)
    # Falcon's API base URL depends on your cloud region -- see
    # examples/crowdstrike_poller_config.example.json for the real
    # per-region hostnames.
    base_url: str = "https://api.crowdstrike.com"
    # Names of ENVIRONMENT VARIABLES holding the real OAuth2 client
    # credentials -- this config file never contains the secret itself,
    # the same pattern PollerConfig.auth_token_env uses.
    client_id_env: str = "CROWDSTRIKE_CLIENT_ID"
    client_secret_env: str = "CROWDSTRIKE_CLIENT_SECRET"
    page_size: int = Field(default=100, ge=1, le=1000)
    poll_interval_seconds: float = 60.0
    tenant: str = DEFAULT_TENANT
    source_name: str = Field(default="crowdstrike", max_length=100)


# Keyed by (base_url, client_id) -> (token, expires_at_monotonic). A
# module-level cache, not per-config: the same credentials shouldn't pay
# for a fresh token exchange every poll_once() call just because a
# caller reloaded its config in between.
_token_cache: dict = {}


def _get_oauth_token(config: CrowdStrikeConfig) -> Optional[str]:
    """A cached OAuth2 bearer token, refreshed via a real client-
    credentials exchange when missing or close to expiry. Returns None
    if the credentials aren't configured at all -- distinguished from a
    failed exchange (which raises, the same as any other real HTTP
    error in this project's connectors) so a caller can tell "not set
    up yet" apart from "set up but broken."
    """
    client_id = os.getenv(config.client_id_env)
    client_secret = os.getenv(config.client_secret_env)
    if not client_id or not client_secret:
        return None

    cache_key = (config.base_url, client_id)
    cached = _token_cache.get(cache_key)
    if cached and cached[1] > time.monotonic():
        return cached[0]

    import requests

    response = requests.post(
        f"{config.base_url}/oauth2/token",
        data={"client_id": client_id, "client_secret": client_secret},
        headers={"Accept": "application/json"},
        timeout=30,
    )
    response.raise_for_status()
    body = response.json() or {}
    token = body.get("access_token")
    if not token:
        return None

    expires_in = body.get("expires_in", 1799)
    # Refresh a little early so an in-flight request never starts
    # against a token that's about to expire mid-request.
    _token_cache[cache_key] = (token, time.monotonic() + max(expires_in - 60, 30))
    return token


def _state_path(config: CrowdStrikeConfig) -> str:
    tenant_id = sanitize_tenant_id(config.tenant)
    directory = os.path.join(tenant_data_dir(tenant_id), "poller_state")
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, f"{config.name}.json")


def load_cursor(config: CrowdStrikeConfig) -> Optional[str]:
    path = _state_path(config)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f).get("cursor")
    except (json.JSONDecodeError, OSError):
        return None


def save_cursor(config: CrowdStrikeConfig, cursor: Optional[str]) -> None:
    with open(_state_path(config), "w", encoding="utf-8") as f:
        json.dump({"cursor": cursor}, f)


def fetch_new_detections(
    config: CrowdStrikeConfig, token: str, cursor: Optional[str]
) -> Tuple[List[dict], Optional[str]]:
    """Two real HTTP calls, the real Falcon Detects API choreography:
    query matching detection IDs created after `cursor` (oldest-first,
    so the cursor always advances forward through a large backlog rather
    than jumping straight to the newest page), then fetch full summaries
    for those IDs. Returns (summaries, new_cursor) -- new_cursor is
    unchanged if nothing came back.
    """
    import requests

    headers = {"Authorization": f"Bearer {token}"}

    params = {"sort": "created_timestamp.asc", "limit": config.page_size}
    if cursor:
        params["filter"] = f"created_timestamp:>'{cursor}'"

    query_response = requests.get(
        f"{config.base_url}/detects/queries/detects/v1", headers=headers, params=params, timeout=30
    )
    query_response.raise_for_status()
    ids = (query_response.json() or {}).get("resources") or []
    if not ids:
        return [], cursor

    summary_response = requests.post(
        f"{config.base_url}/detects/entities/summaries/GET/v1",
        headers={**headers, "Content-Type": "application/json"},
        json={"ids": ids},
        timeout=30,
    )
    summary_response.raise_for_status()
    summaries = (summary_response.json() or {}).get("resources") or []

    new_cursor = cursor
    for summary in summaries:
        if not isinstance(summary, dict):
            continue
        ts = summary.get("created_timestamp")
        if ts and (new_cursor is None or ts > new_cursor):
            new_cursor = ts

    return summaries, new_cursor


def poll_once(config: CrowdStrikeConfig) -> List[dict]:
    """Fetch, normalize, and ingest one batch of detections. Returns the
    list of ingest_normalized_alert() outcome dicts, one per detection
    summary that normalized to a real alert -- or a single
    {"outcome": "auth_failed"} entry (no HTTP call attempted beyond the
    token exchange) if OAuth2 credentials aren't configured, so a caller
    can tell "not set up" apart from "set up, no new detections."
    """
    from ingestion.normalizers import normalize_crowdstrike
    from ingestion.pipeline import ingest_normalized_alert

    token = _get_oauth_token(config)
    if not token:
        return [{"outcome": "auth_failed"}]

    cursor = load_cursor(config)
    summaries, new_cursor = fetch_new_detections(config, token, cursor)

    results = []
    for summary in summaries:
        if not isinstance(summary, dict):
            continue
        alert = normalize_crowdstrike(summary)
        if alert is None:
            continue
        results.append(ingest_normalized_alert(alert, tenant_id=config.tenant))

    if new_cursor != cursor:
        save_cursor(config, new_cursor)

    return results


def load_config(path: str) -> CrowdStrikeConfig:
    with open(path, encoding="utf-8") as f:
        return CrowdStrikeConfig.model_validate(json.load(f))
