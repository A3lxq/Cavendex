"""Single Sign-On via a generic OIDC Authorization Code + PKCE flow —
an *additional*, opt-in credential type for the dashboard, alongside the
static `CAVENDEX_API_KEY` and `utils/user_accounts.py`'s local username/
password sessions, never a replacement for either. Works against any
standards-compliant OIDC provider (Okta, Azure AD/Entra ID, Google
Workspace, Auth0, Keycloak, ...) — nothing here is provider-specific.

A successful login issues a real Cavendex session via
`utils.user_accounts.create_session()`, the exact same session store the
password-login flow already uses — OIDC is just a new way to
*authenticate into* that system, not a parallel one. `approved_by`
auto-fill, session TTL, and tenant-scoping all keep working unchanged.

No server-side login-flow state store is needed (and so this works the
same whether Cavendex runs as one process or many, unlike some other
opt-in features in this project). The PKCE code_verifier, the tenant this
login is for, and a nonce are packed into the OIDC `state` parameter
itself as a short-lived JWT signed with a value derived deterministically
from `CAVENDEX_OIDC_CLIENT_SECRET` (via HMAC-SHA256, see `_state_secret()`)
— `state` is an opaque string as far as the OIDC spec and the identity
provider are concerned, simply roundtripped back to us verbatim in the
callback.

**This derivation replaced an earlier, genuinely broken design, caught
by a security review, not by this project's own live-verification at the
time.** The first implementation used a fresh random secret generated
once at module-import time. That's fine for one process, but `cavendex
serve --workers N` (N > 1) spawns each worker via
`multiprocessing.get_context("spawn")` — confirmed by reading the
installed uvicorn's own source — which starts a genuinely fresh Python
interpreter per worker, not a fork after import. Each worker therefore
got its own, different random secret, so a login whose `/auth/oidc/login`
and `/auth/oidc/callback` requests landed on different workers (routine
under load-balancing across workers sharing one listening socket) failed
every time with "Invalid or expired OIDC state," directly contradicting
this project's own claim that OIDC "works identically whether Cavendex
runs as one process or many." Deriving the secret from
`CAVENDEX_OIDC_CLIENT_SECRET` instead — already a required, shared
config value once OIDC is configured at all, identical across every
worker since they all read the same `.env` — fixes this without adding
a new environment variable or a `CAVENDEX_REDIS_URL` dependency, and as
a side effect an in-flight login also survives a restart now, which the
old per-process-random design didn't.

Honest limitation: no real IdP tenant (a real Okta/Azure AD/Google
Workspace organization) is available to this project, so this is
verified against a real local OIDC-compliant mock provider implementing
discovery + token + JWKS endpoints — the same "verified against the
real protocol, not a live vendor" tier this project already applies to
Wazuh/Splunk/CrowdStrike (each verified against a real local server
matching that vendor's documented API shape, not a live vendor tenant).
"""

import base64
import hashlib
import hmac
import secrets
import time
import urllib.parse

import jwt

_STATE_TTL_SECONDS = 600
_DISCOVERY_CACHE: dict = {}
_DISCOVERY_TTL_SECONDS = 3600


class OidcError(Exception):
    """Raised for anything that fails OIDC login verification — a caller
    (api.py) turns this into a 401, never a silently-accepted identity.
    """


def _issuer_url() -> str:
    import os

    return os.getenv("CAVENDEX_OIDC_ISSUER_URL", "").rstrip("/")


def _client_id() -> str:
    import os

    return os.getenv("CAVENDEX_OIDC_CLIENT_ID", "")


def _client_secret() -> str:
    import os

    return os.getenv("CAVENDEX_OIDC_CLIENT_SECRET", "")


def _redirect_url() -> str:
    import os

    return os.getenv("CAVENDEX_OIDC_REDIRECT_URL", "")


def is_configured() -> bool:
    return bool(_issuer_url() and _client_id() and _client_secret() and _redirect_url())


def _state_secret() -> str:
    """Deterministic per-deployment secret for signing/verifying the OIDC
    `state` JWT — derived via HMAC-SHA256 from `CAVENDEX_OIDC_CLIENT_SECRET`
    rather than a random value generated once at import time, specifically
    so every `cavendex serve --workers N` worker process computes the
    identical secret (they all read the same `.env`) instead of each
    getting its own, unshared random value. See this module's own
    docstring for the real, live-confirmed bug this fixes.
    """
    return hmac.new(_client_secret().encode("utf-8"), b"cavendex-oidc-state", hashlib.sha256).hexdigest()


def _discovery_document() -> dict:
    """The provider's `.well-known/openid-configuration` document —
    cached for an hour, since this almost never changes and every login
    (and every callback) would otherwise cost a real HTTP round-trip.
    """
    issuer = _issuer_url()
    cached = _DISCOVERY_CACHE.get(issuer)
    if cached and cached[1] > time.monotonic():
        return cached[0]

    import requests

    response = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=10)
    response.raise_for_status()
    doc = response.json()
    _DISCOVERY_CACHE[issuer] = (doc, time.monotonic() + _DISCOVERY_TTL_SECONDS)
    return doc


def _make_pkce_pair() -> tuple:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def build_authorization_url(tenant_id: str) -> str:
    """Starts a real Authorization Code + PKCE flow for `tenant_id`.
    Returns the URL to redirect the browser to.
    """
    doc = _discovery_document()
    verifier, challenge = _make_pkce_pair()
    nonce = secrets.token_urlsafe(16)
    state = jwt.encode(
        {
            "tenant_id": tenant_id,
            "code_verifier": verifier,
            "nonce": nonce,
            "exp": int(time.time()) + _STATE_TTL_SECONDS,
        },
        _state_secret(),
        algorithm="HS256",
    )
    params = {
        "response_type": "code",
        "client_id": _client_id(),
        "redirect_uri": _redirect_url(),
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{doc['authorization_endpoint']}?{urllib.parse.urlencode(params)}"


def _decode_state(state: str) -> dict:
    try:
        return jwt.decode(state, _state_secret(), algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise OidcError(f"Invalid or expired OIDC state: {exc}")


def complete_login(code: str, state: str) -> dict:
    """Exchanges an authorization `code` for tokens, verifies the ID
    token's signature/issuer/audience/nonce against the provider's real
    JWKS, and returns {"tenant_id", "username", "role"} — the caller
    (api.py) issues a real session from this via
    utils.user_accounts.create_session(). Raises OidcError for any
    verification failure; never returns an identity it hasn't verified.

    Every OIDC-authenticated login gets the "analyst" role — mapping an
    IdP group/claim to "admin" would need real per-deployment claim
    configuration this project has no way to guess a sensible default
    for; an operator who wants an SSO user to hold admin can promote them
    with `python cli.py --tenant <id> ...` or the existing
    PATCH /auth/users/{username}/role route (both already work against
    any username, session-issued or not).
    """
    claims = _decode_state(state)
    doc = _discovery_document()

    import requests

    token_response = requests.post(
        doc["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": _redirect_url(),
            "client_id": _client_id(),
            "client_secret": _client_secret(),
            "code_verifier": claims["code_verifier"],
        },
        timeout=15,
    )
    if token_response.status_code >= 400:
        raise OidcError(f"Token exchange failed: HTTP {token_response.status_code}")
    tokens = token_response.json()
    id_token = tokens.get("id_token")
    if not id_token:
        raise OidcError("Token response had no id_token")

    try:
        jwks_client = jwt.PyJWKClient(doc["jwks_uri"])
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        id_claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=_client_id(),
            issuer=doc["issuer"],
        )
    except jwt.PyJWTError as exc:
        raise OidcError(f"ID token verification failed: {exc}")

    if id_claims.get("nonce") != claims["nonce"]:
        raise OidcError("ID token nonce mismatch — possible replay or mixup attack")

    username = id_claims.get("preferred_username") or id_claims.get("email") or id_claims.get("sub")
    if not username:
        raise OidcError("ID token has no usable identity claim (preferred_username/email/sub)")

    return {"tenant_id": claims["tenant_id"], "username": username, "role": "analyst"}
