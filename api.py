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

import asyncio
import json
import os
import queue
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
from utils.incident_events import subscribe as subscribe_incident_events
from utils.incident_events import unsubscribe as unsubscribe_incident_events
from utils.incident_index import get_incident_stats, list_incidents
from utils.rate_limit import check_rate_limit
from utils.tenancy import DEFAULT_TENANT
from utils.user_accounts import (
    change_role,
    create_session,
    create_user,
    delete_user,
    has_any_users,
    invalidate_session,
    list_users,
    validate_session,
    verify_password,
)
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


def _require_login_when_users_exist() -> bool:
    return os.getenv("SENTINELOS_REQUIRE_LOGIN", "false").strip().lower() in ("1", "true", "yes")


def require_api_key(
    request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme)
):
    """Bearer-token auth for the unprefixed, default-tenant routes. Uses a
    constant-time comparison so a valid key can't be brute-forced via
    response-time differences on a partial match.

    Also accepts a real per-user session token (see utils/user_accounts.py)
    as an alternative credential — checked first, since a session token
    and the static API key are visually indistinguishable bearer strings
    and only one lookup will ever match. `request.state.session_user` is
    set to that user's {"username", "role"} for the rest of the request
    (None for plain API-key auth) — route handlers that want to attribute
    an action to a real identity (e.g. auto-filling `approved_by`) read
    it from there.

    Creating a user account never by itself changes whether an
    unauthenticated caller is admitted — that would silently flip a
    tenant's security posture for everyone else the moment one analyst
    sets up a login purely for its accountability benefit (a real
    identity auto-filling `approved_by`), the exact kind of surprise
    every other opt-in feature in this project goes out of its way to
    avoid. `SENTINELOS_REQUIRE_LOGIN=true` opts into treating "this
    tenant has any real user accounts" as its own reason to require a
    credential, for an operator who deliberately wants account creation
    itself to be the access-control switch instead of (or in addition
    to) SENTINELOS_API_KEY.
    """
    request.state.session_user = None
    if credentials is not None:
        session = validate_session(DEFAULT_TENANT, credentials.credentials)
        if session is not None:
            request.state.session_user = session
            return

    expected_key = _global_api_key()
    requires_auth = bool(expected_key) or (
        _require_login_when_users_exist() and has_any_users(DEFAULT_TENANT)
    )
    if not requires_auth:
        return
    if credentials is None or not (expected_key and secrets.compare_digest(credentials.credentials, expected_key)):
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

    Also accepts a real per-user session token scoped to this tenant —
    see require_api_key's docstring for both that and
    SENTINELOS_REQUIRE_LOGIN, the reasoning is identical here.
    """
    request.state.session_user = None
    if credentials is not None:
        session = validate_session(tenant_id, credentials.credentials)
        if session is not None:
            request.state.session_user = session
            return

    expected_key = _tenant_api_keys().get(tenant_id) or _global_api_key()
    requires_auth = bool(expected_key) or (_require_login_when_users_exist() and has_any_users(tenant_id))
    if not requires_auth:
        return
    if credentials is None or not (expected_key and secrets.compare_digest(credentials.credentials, expected_key)):
        client_ip = request.client.host if request.client else "unknown"
        record_auth_failure(client_ip, request.url.path, tenant_id=tenant_id)
        raise HTTPException(status_code=401, detail=f"Invalid or missing API key for tenant '{tenant_id}'")


def require_admin(request: Request) -> None:
    """Gates user-management routes (create/list/delete user, change
    role). A caller authenticated via a real session must hold the
    `admin` role. A caller authenticated via the plain API key (no
    session at all — `request.state.session_user` is None) is allowed
    through: the API key is already a super-credential that authorizes
    every other route in this system, so treating it as implicitly
    admin here is consistent with the existing trust model, and is also
    the only way to bootstrap a tenant's very first user account (there
    is, by definition, no admin session yet at that point).
    """
    session_user = getattr(request.state, "session_user", None)
    if session_user is not None and session_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")


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


class LoginRequest(BaseModel):
    username: ShortStr
    password: ShortStr


class CreateUserRequest(BaseModel):
    username: ShortStr
    password: ShortStr
    role: str = "analyst"


class ChangeRoleRequest(BaseModel):
    role: str


def _login_rate_limit_per_minute() -> int:
    try:
        return int(os.getenv("SENTINELOS_LOGIN_RATE_LIMIT_PER_MINUTE", "5"))
    except ValueError:
        return 5


def _login(tenant_id: str, payload: LoginRequest, request: Request) -> dict:
    """Deliberately unauthenticated — logging in is how a caller obtains
    a credential in the first place, so it can't itself require one.
    Rate-limited far more tightly than the LLM-triggering routes
    (SENTINELOS_LOGIN_RATE_LIMIT_PER_MINUTE, default 5/minute per
    (tenant, client IP)) since this is the one route in the whole API
    whose entire job is checking a password against a stored hash — the
    exact kind of endpoint password-brute-forcing targets.
    """
    client_ip = request.client.host if request.client else "unknown"
    retry_after = check_rate_limit(f"login:{tenant_id}:{client_ip}", limit=_login_rate_limit_per_minute())
    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts — try again shortly.",
            headers={"Retry-After": str(int(retry_after))},
        )

    user = verify_password(tenant_id, payload.username, payload.password)
    if user is None:
        record_auth_failure(client_ip, request.url.path, tenant_id=tenant_id)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    session = create_session(tenant_id, user["username"], user["role"])
    return {
        "token": session["token"],
        "expires_at": session["expires_at"],
        "username": user["username"],
        "role": user["role"],
    }


@api.post("/auth/login")
def login_default(payload: LoginRequest, request: Request):
    return _login(DEFAULT_TENANT, payload, request)


@api.post("/tenants/{tenant_id}/auth/login")
def login_for_tenant(tenant_id: str, payload: LoginRequest, request: Request):
    return _login(tenant_id, payload, request)


# Every route except /health, /, /static/*, and /auth/login requires auth
# (when SENTINELOS_API_KEY is set, or when the tenant has any real user
# accounts — see require_api_key/require_tenant_api_key) — enforced once
# here rather than repeated on each route, so a new route can't
# accidentally be added unauthenticated. Tenant-scoped routes get their
# own router below with a dependency that also checks
# SENTINELOS_TENANT_API_KEYS for the specific tenant in the URL, not just
# the global key.
router = APIRouter(dependencies=[Depends(require_api_key)])
tenant_router = APIRouter(dependencies=[Depends(require_tenant_api_key)])


def _logout(tenant_id: str, credentials: Optional[HTTPAuthorizationCredentials]) -> dict:
    if credentials is not None:
        invalidate_session(tenant_id, credentials.credentials)
    return {"status": "logged_out"}


def _me(request: Request) -> dict:
    session_user = getattr(request.state, "session_user", None)
    if session_user is None:
        return {"authenticated_via": "api_key", "username": None, "role": None}
    return {"authenticated_via": "session", "username": session_user["username"], "role": session_user["role"]}


def _create_user_account(tenant_id: str, payload: CreateUserRequest) -> dict:
    try:
        return create_user(tenant_id, payload.username, payload.password, role=payload.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _delete_user_account(tenant_id: str, username: str) -> dict:
    if not delete_user(tenant_id, username):
        raise HTTPException(status_code=404, detail=f"No such user: {username}")
    return {"status": "deleted", "username": username}


def _change_user_role(tenant_id: str, username: str, payload: ChangeRoleRequest) -> dict:
    try:
        changed = change_role(tenant_id, username, payload.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not changed:
        raise HTTPException(status_code=404, detail=f"No such user: {username}")
    return {"status": "updated", "username": username, "role": payload.role}


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


class NoteRequest(BaseModel):
    text: str = Field(max_length=2000)
    # Same "analyst-typed label, not an authenticated identity" pattern
    # as ApprovalRequest.approved_by.
    author: Optional[ShortStr] = None


class AssignRequest(BaseModel):
    # None/omitted unassigns the incident. Same accountability-label
    # caveat as everywhere else an analyst name is recorded.
    assigned_to: Optional[ShortStr] = None


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
            "action_type": a.action_type, "approved": a.approved, "approved_by": a.approved_by,
            "executed": a.executed, "execution_detail": a.execution_detail,
            "playbook_id": a.playbook_id, "chain_step": a.chain_step,
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


def _list_notes(thread_id: str, tenant_id: str):
    from utils.incident_notes import list_notes

    if get_incident_state(thread_id, tenant_id=tenant_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return list_notes(tenant_id, thread_id)


def _add_note(thread_id: str, tenant_id: str, payload: NoteRequest):
    from utils.incident_notes import add_note

    if get_incident_state(thread_id, tenant_id=tenant_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    try:
        return add_note(tenant_id, thread_id, payload.text, author=payload.author)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _assign_incident(thread_id: str, tenant_id: str, assigned_to: Optional[str]):
    from utils.incident_index import set_assigned_to

    if get_incident_state(thread_id, tenant_id=tenant_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    set_assigned_to(tenant_id, thread_id, assigned_to)
    return {"thread_id": thread_id, "assigned_to": assigned_to}


# The standard MITRE ATT&CK Enterprise kill-chain order — matches every
# tactic name actually used in enrichment/mitre_attack.py's curated
# dataset, so the overview renders tactics left-to-right in the order an
# analyst already expects from the real ATT&CK matrix, not alphabetical.
_TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]


def _attack_overview(tenant_id: str) -> dict:
    """Groups every ATT&CK technique cited (and verified) across this
    tenant's incidents by tactic — a single incident only ever cites one
    technique, so there's no per-incident "matrix" to show; this is the
    aggregate view across everything this tenant has actually seen.
    Tactic membership comes from enrichment/mitre_attack.py's own
    dataset (the same one citations are verified against), not a second
    copy of that mapping.
    """
    from enrichment.mitre_attack import lookup_technique
    from utils.incident_index import get_attack_technique_stats

    by_tactic: dict = {tactic: [] for tactic in _TACTIC_ORDER}
    for entry in get_attack_technique_stats(tenant_id):
        info = lookup_technique(entry["id"])
        tactic = info["tactic"] if info else "Unknown"
        by_tactic.setdefault(tactic, []).append(entry)

    return {
        "tactics": [
            {"tactic": tactic, "techniques": techniques}
            for tactic, techniques in by_tactic.items()
            if techniques
        ]
    }


def _incident_graph(tenant_id: str) -> dict:
    from utils.incident_index import get_incident_graph

    return get_incident_graph(tenant_id)


def _effective_actor(request: Request, explicit: Optional[str]) -> Optional[str]:
    """The name to attribute an approve/deny call to: `explicit` (the
    request body's own approved_by, if given) always wins, but when a
    caller didn't supply one and is logged in via a real session, that
    session's authenticated username is used instead of leaving the
    field empty — a real identity is strictly better attribution than
    "unspecified," so prefer it whenever it's actually available.
    """
    if explicit:
        return explicit
    session_user = getattr(request.state, "session_user", None)
    return session_user["username"] if session_user else None


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


# How long a single blocking queue.get() waits before giving up and
# looping again — bounds how often we re-check for client disconnect and
# how often an idle connection gets a heartbeat comment (keeps proxies/
# load balancers with their own idle-timeout from silently killing the
# connection; see DEPLOYMENT.md's note on long-lived SSE behind a proxy).
# Configurable because it's also the longest a background executor thread
# can be left blocked in queue.get() after a client disconnects (that
# thread only unblocks on its own timeout, not on cancellation) — tests
# turn this down so a closed test connection doesn't leave a slow-to-join
# thread behind.
def _events_heartbeat_seconds() -> float:
    try:
        return max(1.0, float(os.getenv("SENTINELOS_EVENTS_HEARTBEAT_SECONDS", "15")))
    except ValueError:
        return 15.0


async def _incident_events_stream(tenant_id: str):
    """Pushes a small "something changed, go refetch" event to the
    dashboard every time this tenant's incident index is updated (new
    incident, approve/deny, correlated merge, hunt — anything that calls
    workflows/incident_pipeline.py's _persist()). Deliberately just a
    signal, not the incident payload itself — the dashboard already has
    a correct, tested loadIncidents()/loadStats() path; this only tells
    it *when* to call that path again instead of waiting for the next
    poll tick.

    Bridges the sync queue.Queue (utils/incident_events.py) into this
    async route via run_in_executor. Disconnect is *not* detected via
    request.is_disconnected() -- that call races Starlette's own ASGI
    receive loop and, behind this app's @api.middleware("http") (which
    already owns the request's receive channel to relay it through
    call_next), it never resolves, hanging the connection open forever
    with nothing ever flushed to the client. Instead, a dead connection
    is discovered the ordinary way: the next attempt to yield to it
    fails, which closes this generator (running the `finally` below) --
    bounded by the heartbeat interval below, same as any idle connection.
    """
    q = subscribe_incident_events(tenant_id)
    loop = asyncio.get_running_loop()
    try:
        yield "data: {\"type\": \"connected\"}\n\n"
        while True:
            try:
                event = await loop.run_in_executor(None, q.get, True, _events_heartbeat_seconds())
            except queue.Empty:
                yield ": heartbeat\n\n"
                continue
            yield f"data: {json.dumps(event)}\n\n"
    finally:
        unsubscribe_incident_events(tenant_id, q)


def _incident_events(tenant_id: str) -> StreamingResponse:
    return StreamingResponse(_incident_events_stream(tenant_id), media_type="text/event-stream")


# --- Default-tenant routes (backward-compatible / convenience) ---


@router.post("/auth/logout")
def logout_default(credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme)):
    return _logout(DEFAULT_TENANT, credentials)


@router.get("/auth/me")
def me_default(request: Request):
    return _me(request)


@router.post("/auth/users", dependencies=[Depends(require_admin)])
def create_user_default(payload: CreateUserRequest):
    return _create_user_account(DEFAULT_TENANT, payload)


@router.get("/auth/users", dependencies=[Depends(require_admin)])
def list_users_default():
    return list_users(DEFAULT_TENANT)


@router.delete("/auth/users/{username}", dependencies=[Depends(require_admin)])
def delete_user_default(username: str):
    return _delete_user_account(DEFAULT_TENANT, username)


@router.patch("/auth/users/{username}/role", dependencies=[Depends(require_admin)])
def change_user_role_default(username: str, payload: ChangeRoleRequest):
    return _change_user_role(DEFAULT_TENANT, username, payload)


@router.get("/incidents")
def list_incidents_default(
    limit: int = 100, severity: Optional[str] = None, status: Optional[str] = None, search: Optional[str] = None
):
    return list_incidents(DEFAULT_TENANT, limit=limit, severity=severity, status=status, search=search)


@router.get("/incidents/stats")
def incident_stats_default():
    return get_incident_stats(DEFAULT_TENANT)


@router.get("/incidents/attack-overview")
def attack_overview_default():
    return _attack_overview(DEFAULT_TENANT)


@router.get("/incidents/graph")
def incident_graph_default():
    return _incident_graph(DEFAULT_TENANT)


@router.get("/incidents/events")
def incident_events_default():
    return _incident_events(DEFAULT_TENANT)


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


@router.get("/incidents/{thread_id}/notes")
def list_incident_notes(thread_id: str):
    return _list_notes(thread_id, DEFAULT_TENANT)


@router.post("/incidents/{thread_id}/notes")
def add_incident_note(thread_id: str, payload: NoteRequest):
    return _add_note(thread_id, DEFAULT_TENANT, payload)


@router.post("/incidents/{thread_id}/assign")
def assign_incident(thread_id: str, payload: Optional[AssignRequest] = None):
    return _assign_incident(thread_id, DEFAULT_TENANT, payload.assigned_to if payload else None)


@router.post("/incidents/{thread_id}/approve")
def approve_incident(thread_id: str, request: Request, payload: Optional[ApprovalRequest] = None):
    approved_by = _effective_actor(request, payload.approved_by if payload else None)
    return _resolve_incident(thread_id, True, DEFAULT_TENANT, approved_by=approved_by)


@router.post("/incidents/{thread_id}/deny")
def deny_incident(thread_id: str, request: Request, payload: Optional[ApprovalRequest] = None):
    approved_by = _effective_actor(request, payload.approved_by if payload else None)
    return _resolve_incident(thread_id, False, DEFAULT_TENANT, approved_by=approved_by)


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


@tenant_router.post("/tenants/{tenant_id}/auth/logout")
def logout_for_tenant(tenant_id: str, credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme)):
    return _logout(tenant_id, credentials)


@tenant_router.get("/tenants/{tenant_id}/auth/me")
def me_for_tenant(tenant_id: str, request: Request):
    return _me(request)


@tenant_router.post("/tenants/{tenant_id}/auth/users", dependencies=[Depends(require_admin)])
def create_user_for_tenant(tenant_id: str, payload: CreateUserRequest):
    return _create_user_account(tenant_id, payload)


@tenant_router.get("/tenants/{tenant_id}/auth/users", dependencies=[Depends(require_admin)])
def list_users_for_tenant(tenant_id: str):
    return list_users(tenant_id)


@tenant_router.delete("/tenants/{tenant_id}/auth/users/{username}", dependencies=[Depends(require_admin)])
def delete_user_for_tenant(tenant_id: str, username: str):
    return _delete_user_account(tenant_id, username)


@tenant_router.patch("/tenants/{tenant_id}/auth/users/{username}/role", dependencies=[Depends(require_admin)])
def change_user_role_for_tenant(tenant_id: str, username: str, payload: ChangeRoleRequest):
    return _change_user_role(tenant_id, username, payload)


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


@tenant_router.get("/tenants/{tenant_id}/incidents/attack-overview")
def attack_overview_for_tenant(tenant_id: str):
    return _attack_overview(tenant_id)


@tenant_router.get("/tenants/{tenant_id}/incidents/graph")
def incident_graph_for_tenant(tenant_id: str):
    return _incident_graph(tenant_id)


@tenant_router.get("/tenants/{tenant_id}/incidents/events")
def incident_events_for_tenant(tenant_id: str):
    return _incident_events(tenant_id)


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


@tenant_router.get("/tenants/{tenant_id}/incidents/{thread_id}/notes")
def list_incident_notes_for_tenant(tenant_id: str, thread_id: str):
    return _list_notes(thread_id, tenant_id)


@tenant_router.post("/tenants/{tenant_id}/incidents/{thread_id}/notes")
def add_incident_note_for_tenant(tenant_id: str, thread_id: str, payload: NoteRequest):
    return _add_note(thread_id, tenant_id, payload)


@tenant_router.post("/tenants/{tenant_id}/incidents/{thread_id}/assign")
def assign_incident_for_tenant(tenant_id: str, thread_id: str, payload: Optional[AssignRequest] = None):
    return _assign_incident(thread_id, tenant_id, payload.assigned_to if payload else None)


@tenant_router.post("/tenants/{tenant_id}/incidents/{thread_id}/approve")
def approve_incident_for_tenant(
    tenant_id: str, thread_id: str, request: Request, payload: Optional[ApprovalRequest] = None
):
    approved_by = _effective_actor(request, payload.approved_by if payload else None)
    return _resolve_incident(thread_id, True, tenant_id, approved_by=approved_by)


@tenant_router.post("/tenants/{tenant_id}/incidents/{thread_id}/deny")
def deny_incident_for_tenant(
    tenant_id: str, thread_id: str, request: Request, payload: Optional[ApprovalRequest] = None
):
    approved_by = _effective_actor(request, payload.approved_by if payload else None)
    return _resolve_incident(thread_id, False, tenant_id, approved_by=approved_by)


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
