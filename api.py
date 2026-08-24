"""Minimal FastAPI layer over the SentinelOS incident pipeline.

Run with: uvicorn api:api --reload, then open http://localhost:8000/ for
the analyst dashboard.

Every endpoint is tenant-scoped. The unprefixed routes (/incidents, /hunts)
operate on the "default" tenant for convenience/backward-compatibility;
/tenants/{tenant_id}/... routes operate on an explicit tenant, with full
isolation (separate SQLite DB, ChromaDB collection, and Obsidian vault
subfolder per tenant — see graph.get_app, memory.vector_store,
utils.obsidian).

Auth: set SENTINELOS_API_KEY to require `Authorization: Bearer <key>` on
every data route except /health, /, and /static/* (the dashboard's HTML
shell contains no incident data — only its own fetch() calls to the
protected routes need the key, entered client-side in the dashboard).
Unset, the API runs unauthenticated — fine for local/internal use behind
your own gateway, not for public exposure. /docs, /redoc, and
/openapi.json are gated the same way — FastAPI's default versions of
these routes bypass the router-level auth dependency entirely, so this
project defines its own authenticated ones instead of using the default.

Tenant isolation: SENTINELOS_API_KEY alone authorizes a caller for every
tenant — fine for one trusted operator using tenants purely to organize
data, but not a real boundary between organizations that shouldn't see
each other's incidents (storage was already isolated per-tenant; auth
was not). SENTINELOS_TENANT_API_KEYS closes that: a JSON object mapping
a tenant_id to its own key, e.g. {"acme-corp": "...", "globex": "..."}.
A tenant with an entry there only ever accepts *that* key on its
/tenants/{tenant_id}/... routes — the global key no longer works for it.
A tenant with no entry keeps today's behavior and falls back to the
global key, so a single-operator deployment needs no new configuration.
"""

import json
import os
import secrets
from typing import List, Optional

from dotenv import load_dotenv

load_dotenv(override=True)

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ingestion.pipeline import ingest_alert
from state import Severity, ShortStr
from utils.auth_monitor import record_auth_failure
from utils.incident_index import get_incident_stats, list_incidents
from utils.rate_limit import check_rate_limit
from utils.tenancy import DEFAULT_TENANT
from workflows.incident_pipeline import (
    get_incident_state,
    resolve_proposed_actions,
    run_new_incident,
    run_new_incident_stream,
    run_threat_hunt,
)

if not os.getenv("SENTINELOS_API_KEY"):
    print(
        "⚠️  SENTINELOS_API_KEY is not set — the API is running unauthenticated. "
        "Fine for local/internal use; set it before exposing this beyond your own machine."
    )

_bearer_scheme = HTTPBearer(auto_error=False)


def _global_api_key() -> Optional[str]:
    return os.getenv("SENTINELOS_API_KEY")


def _tenant_api_keys() -> dict:
    """Parses SENTINELOS_TENANT_API_KEYS (a JSON object mapping tenant_id
    to its own key) once per call — cheap enough not to cache, and always
    reflects the current environment, the same as every other
    os.getenv(...)-per-call setting in this project. Malformed JSON is
    treated as "no per-tenant keys configured" (with a startup-time-style
    warning) rather than crashing every request — misconfiguring this
    should degrade to today's global-key behavior, never to a 500.
    """
    raw = (os.getenv("SENTINELOS_TENANT_API_KEYS") or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        print(
            "SENTINELOS_TENANT_API_KEYS is not valid JSON — ignoring it. "
            "Every tenant will fall back to the shared SENTINELOS_API_KEY."
        )
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(k): str(v) for k, v in parsed.items()}


def require_api_key(
    request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme)
):
    """Bearer-token auth for the unprefixed, default-tenant routes. Uses a
    constant-time comparison so a valid key can't be brute-forced via
    response-time differences on a partial match.
    """
    expected_key = _global_api_key()
    if not expected_key:
        return
    if credentials is None or not secrets.compare_digest(credentials.credentials, expected_key):
        client_ip = request.client.host if request.client else "unknown"
        record_auth_failure(client_ip, request.url.path)
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def require_tenant_api_key(
    tenant_id: str,
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
):
    """Bearer-token auth for /tenants/{tenant_id}/... routes, scoped to
    the tenant actually named in the URL.

    Previously every tenant route accepted the single global
    SENTINELOS_API_KEY — tenancy isolated storage but not who could read
    or act on it, so one key holder could reach every tenant just by
    changing the URL. If SENTINELOS_TENANT_API_KEYS configures a key for
    THIS tenant, the caller must present exactly that key; the global key
    no longer authorizes it. A tenant with no entry in that mapping falls
    back to the global key, preserving today's behavior for anyone who
    hasn't configured per-tenant keys.
    """
    expected_key = _tenant_api_keys().get(tenant_id) or _global_api_key()
    if not expected_key:
        return
    if credentials is None or not secrets.compare_digest(credentials.credentials, expected_key):
        client_ip = request.client.host if request.client else "unknown"
        record_auth_failure(client_ip, request.url.path, tenant_id=tenant_id)
        raise HTTPException(status_code=401, detail=f"Invalid or missing API key for tenant '{tenant_id}'")


def _enforce_rate_limit(key: str) -> None:
    retry_after = check_rate_limit(key)
    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Rate limit exceeded ({os.getenv('SENTINELOS_RATE_LIMIT_PER_MINUTE', '10')} "
                "requests/minute) — this endpoint runs a full LLM pipeline per call."
            ),
            headers={"Retry-After": str(int(retry_after))},
        )


def rate_limit_default(request: Request) -> None:
    """Applied to the LLM-triggering default-tenant routes only — reads
    (show/get) and human approve/deny decisions never call an LLM, so
    they're not rate-limited.
    """
    client_ip = request.client.host if request.client else "unknown"
    _enforce_rate_limit(f"{DEFAULT_TENANT}:{client_ip}")


def rate_limit_for_tenant(tenant_id: str, request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    _enforce_rate_limit(f"{tenant_id}:{client_ip}")


_MAX_INGEST_BODY_BYTES = 65536


def enforce_max_body_size(request: Request) -> None:
    """A raw alert payload (unlike our own request models) has no schema
    to bound its size — this is a best-effort guard (Content-Length can be
    absent or spoofed by a malicious client) against an oversized ingest
    payload, on top of the normalizers already capping every field they
    extract.
    """
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > _MAX_INGEST_BODY_BYTES:
        raise HTTPException(
            status_code=413, detail=f"Payload too large (max {_MAX_INGEST_BODY_BYTES} bytes)"
        )


# docs_url/redoc_url/openapi_url are disabled here and re-added below as
# authenticated routes on `router` instead — FastAPI's default /docs,
# /redoc, and /openapi.json are otherwise reachable with NO credentials
# even when SENTINELOS_API_KEY is set (they're framework routes on the
# app object, not the auth-gated router), disclosing the entire API
# schema for free. Live-verified before this fix: all three returned 200
# with zero Authorization header sent.
api = FastAPI(
    title="SentinelOS",
    description="Cybersecurity agentic AI operating system",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@api.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Baseline response headers on every route. HSTS is deliberately NOT
    set here — it belongs at the TLS-terminating reverse proxy (see
    DEPLOYMENT.md section 5), since this app has no reliable way to know
    at runtime whether it's actually being served over HTTPS, and a
    wrongly-set HSTS header on a plain-HTTP local dev instance would make
    a browser force HTTPS on that host afterward.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    return response


_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
api.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


@api.get("/")
def dashboard():
    """The analyst dashboard's HTML shell — unauthenticated like /health,
    since it contains no incident data. The dashboard's own JS prompts for
    an API key client-side and attaches it to its fetch() calls, which do
    hit the protected routes below.
    """
    return FileResponse(os.path.join(_STATIC_DIR, "index.html"))


@api.get("/health")
def health():
    return {"status": "ok"}


# Every route except /health, /, and /static/* requires auth (when
# SENTINELOS_API_KEY is set) — enforced once here rather than repeated on
# each route, so a new route can't accidentally be added unauthenticated.
# Tenant-scoped routes get their own router below with a dependency that
# also checks SENTINELOS_TENANT_API_KEYS for the specific tenant in the
# URL, not just the global key.
router = APIRouter(dependencies=[Depends(require_api_key)])
tenant_router = APIRouter(dependencies=[Depends(require_tenant_api_key)])


# The API's own schema, gated behind the same auth as everything else it
# describes — see the docs_url=None comment above for why this exists.
@router.get("/openapi.json", include_in_schema=False)
def openapi_schema():
    return JSONResponse(
        get_openapi(title=api.title, version=api.version, description=api.description, routes=api.routes)
    )


@router.get("/docs", include_in_schema=False)
def swagger_docs():
    return get_swagger_ui_html(openapi_url="/openapi.json", title=f"{api.title} — Swagger UI")


@router.get("/redoc", include_in_schema=False)
def redoc_docs():
    return get_redoc_html(openapi_url="/openapi.json", title=f"{api.title} — ReDoc")


# Mirrors state.Incident's constraints so oversized/malformed requests are
# rejected by FastAPI's request validation before they ever reach the
# pipeline, rather than relying solely on Incident's own validation deeper in.
class NewIncidentRequest(BaseModel):
    description: str = Field(max_length=4000)
    severity: Severity = "medium"
    affected_assets: List[ShortStr] = Field(default_factory=list, max_length=50)
    iocs: List[ShortStr] = Field(default_factory=list, max_length=50)
    source: Optional[ShortStr] = None


class HuntRequest(BaseModel):
    query: str = Field(max_length=4000)


class ApprovalRequest(BaseModel):
    # Who's approving/denying — an analyst-supplied label, not an
    # authenticated identity (see README Known Gaps: no per-user
    # accounts). Optional so existing callers that never send a body
    # don't break; omitting it is recorded as "unspecified," visibly,
    # rather than silently attributed to a generic "Human Reviewer."
    approved_by: Optional[ShortStr] = None


class IocLookupRequest(BaseModel):
    iocs: List[ShortStr] = Field(max_length=50)


def _msg_name_content(msg):
    if isinstance(msg, dict):
        return msg.get("name") or msg.get("role", "assistant"), msg.get("content", "")
    return getattr(msg, "name", None) or "Agent", getattr(msg, "content", "")


def _serialize_state(state):
    if not state:
        return None
    incident = state.get("incident")
    messages = [
        {"agent": name, "content": content}
        for name, content in (_msg_name_content(m) for m in (state.get("messages", []) or []))
    ]
    proposed_actions = [
        {
            "action": a.action, "target": a.target, "rationale": a.rationale,
            "approved": a.approved, "approved_by": a.approved_by,
        }
        for a in (state.get("proposed_actions", []) or [])
    ]
    return {
        "incident": incident.model_dump() if incident else None,
        "messages": messages,
        "proposed_actions": proposed_actions,
        "token_usage": state.get("token_usage") or {},
        "threat_intel": state.get("threat_intel") or [],
        "attack_technique": state.get("attack_technique"),
        "audit_log": state.get("audit_log", []),
    }


def _create_incident(payload: NewIncidentRequest, tenant_id: str):
    state = run_new_incident(
        description=payload.description,
        severity=payload.severity,
        affected_assets=payload.affected_assets,
        iocs=payload.iocs,
        source=payload.source,
        tenant_id=tenant_id,
    )
    return _serialize_state(state)


def _read_incident(thread_id: str, tenant_id: str):
    state = get_incident_state(thread_id, tenant_id=tenant_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _serialize_state(state)


def _verify_audit(thread_id: str, tenant_id: str):
    from utils.audit_chain import verify_incident_audit_log

    state = get_incident_state(thread_id, tenant_id=tenant_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return verify_incident_audit_log(tenant_id, thread_id, state.get("audit_log", []))


def _resolve_incident(thread_id: str, approve: bool, tenant_id: str, approved_by: Optional[str] = None):
    try:
        state = resolve_proposed_actions(thread_id, approve=approve, tenant_id=tenant_id, approved_by=approved_by)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _serialize_state(state)


def _create_hunt(payload: HuntRequest, tenant_id: str):
    state = run_threat_hunt(payload.query, tenant_id=tenant_id)
    return _serialize_state(state)


def _sse_events(event_generator):
    """Format each yielded dict as a Server-Sent Events `data:` line — the
    live-view counterpart to the synchronous endpoints: a client sees each
    agent's finding as it completes instead of only the final result.
    """
    for event in event_generator:
        yield f"data: {json.dumps(event)}\n\n"


def _stream_incident(payload: NewIncidentRequest, tenant_id: str) -> StreamingResponse:
    generator = run_new_incident_stream(
        description=payload.description,
        severity=payload.severity,
        affected_assets=payload.affected_assets,
        iocs=payload.iocs,
        source=payload.source,
        tenant_id=tenant_id,
    )
    return StreamingResponse(_sse_events(generator), media_type="text/event-stream")


# --- Default-tenant routes (backward-compatible / convenience) ---


@router.get("/incidents")
def list_incidents_default(
    limit: int = 100, severity: Optional[str] = None, status: Optional[str] = None, search: Optional[str] = None
):
    return list_incidents(DEFAULT_TENANT, limit=limit, severity=severity, status=status, search=search)


@router.get("/incidents/stats")
def incident_stats_default():
    return get_incident_stats(DEFAULT_TENANT)


@router.post("/incidents", dependencies=[Depends(rate_limit_default)])
def create_incident(payload: NewIncidentRequest):
    return _create_incident(payload, DEFAULT_TENANT)


@router.post("/incidents/stream", dependencies=[Depends(rate_limit_default)])
def create_incident_stream(payload: NewIncidentRequest):
    return _stream_incident(payload, DEFAULT_TENANT)


@router.get("/incidents/{thread_id}")
def read_incident(thread_id: str):
    return _read_incident(thread_id, DEFAULT_TENANT)


@router.get("/incidents/{thread_id}/verify-audit")
def verify_incident_audit(thread_id: str):
    return _verify_audit(thread_id, DEFAULT_TENANT)


@router.post("/incidents/{thread_id}/approve")
def approve_incident(thread_id: str, payload: Optional[ApprovalRequest] = None):
    return _resolve_incident(thread_id, True, DEFAULT_TENANT, approved_by=payload.approved_by if payload else None)


@router.post("/incidents/{thread_id}/deny")
def deny_incident(thread_id: str, payload: Optional[ApprovalRequest] = None):
    return _resolve_incident(thread_id, False, DEFAULT_TENANT, approved_by=payload.approved_by if payload else None)


@router.post("/hunts", dependencies=[Depends(rate_limit_default)])
def create_hunt(payload: HuntRequest):
    return _create_hunt(payload, DEFAULT_TENANT)


@router.post("/enrichment/lookup", dependencies=[Depends(rate_limit_default)])
def enrichment_lookup(payload: IocLookupRequest):
    """Real threat-intel lookups on demand, with no incident created —
    for an analyst who just wants to check an indicator's reputation.
    Reuses the exact same enrich_iocs() the pipeline calls internally, so
    results (and their caching/rate-limit behavior against the real
    providers) are identical either way. Rate-limited the same as
    incident/hunt creation, even though it never calls an LLM itself —
    it's still spending real, possibly-quota-limited external API calls.
    """
    from enrichment.pipeline import enrich_iocs

    return [r.model_dump() for r in enrich_iocs(payload.iocs)]


@router.post(
    "/ingest/{source}",
    dependencies=[Depends(rate_limit_default), Depends(enforce_max_body_size)],
)
def ingest(source: str, payload: dict):
    """Feed one raw alert from `source` (see ingestion/normalizers.py for
    the registered sources) into the ingestion pipeline — promoted to a
    full incident, deduped, or suppressed depending on severity, never
    silently dropped (see ingestion/pipeline.py and each tenant's
    data/{tenant}/ingestion_log.jsonl).
    """
    return ingest_alert(source, payload, tenant_id=DEFAULT_TENANT)


# --- Explicit tenant routes ---


@tenant_router.get("/tenants/{tenant_id}/incidents")
def list_incidents_for_tenant(
    tenant_id: str,
    limit: int = 100,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
):
    return list_incidents(tenant_id, limit=limit, severity=severity, status=status, search=search)


@tenant_router.get("/tenants/{tenant_id}/incidents/stats")
def incident_stats_for_tenant(tenant_id: str):
    return get_incident_stats(tenant_id)


@tenant_router.post("/tenants/{tenant_id}/incidents", dependencies=[Depends(rate_limit_for_tenant)])
def create_incident_for_tenant(tenant_id: str, payload: NewIncidentRequest):
    return _create_incident(payload, tenant_id)


@tenant_router.post("/tenants/{tenant_id}/incidents/stream", dependencies=[Depends(rate_limit_for_tenant)])
def create_incident_stream_for_tenant(tenant_id: str, payload: NewIncidentRequest):
    return _stream_incident(payload, tenant_id)


@tenant_router.get("/tenants/{tenant_id}/incidents/{thread_id}")
def read_incident_for_tenant(tenant_id: str, thread_id: str):
    return _read_incident(thread_id, tenant_id)


@tenant_router.get("/tenants/{tenant_id}/incidents/{thread_id}/verify-audit")
def verify_incident_audit_for_tenant(tenant_id: str, thread_id: str):
    return _verify_audit(thread_id, tenant_id)


@tenant_router.post("/tenants/{tenant_id}/incidents/{thread_id}/approve")
def approve_incident_for_tenant(tenant_id: str, thread_id: str, payload: Optional[ApprovalRequest] = None):
    return _resolve_incident(thread_id, True, tenant_id, approved_by=payload.approved_by if payload else None)


@tenant_router.post("/tenants/{tenant_id}/incidents/{thread_id}/deny")
def deny_incident_for_tenant(tenant_id: str, thread_id: str, payload: Optional[ApprovalRequest] = None):
    return _resolve_incident(thread_id, False, tenant_id, approved_by=payload.approved_by if payload else None)


@tenant_router.post("/tenants/{tenant_id}/hunts", dependencies=[Depends(rate_limit_for_tenant)])
def create_hunt_for_tenant(tenant_id: str, payload: HuntRequest):
    return _create_hunt(payload, tenant_id)


@tenant_router.post("/tenants/{tenant_id}/enrichment/lookup", dependencies=[Depends(rate_limit_for_tenant)])
def enrichment_lookup_for_tenant(tenant_id: str, payload: IocLookupRequest):
    from enrichment.pipeline import enrich_iocs

    return [r.model_dump() for r in enrich_iocs(payload.iocs)]


@tenant_router.post(
    "/tenants/{tenant_id}/ingest/{source}",
    dependencies=[Depends(rate_limit_for_tenant), Depends(enforce_max_body_size)],
)
def ingest_for_tenant(tenant_id: str, source: str, payload: dict):
    return ingest_alert(source, payload, tenant_id=tenant_id)


api.include_router(router)
api.include_router(tenant_router)
