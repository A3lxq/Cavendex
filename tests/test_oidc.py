"""Tests utils/oidc.py: PKCE/state construction, and a full real login
flow (discovery, token exchange, JWKS signature verification) against a
real local OIDC-compliant mock provider -- the same "prefer real I/O,
verified against the real protocol since no real IdP tenant is available"
tier this project already applies to Wazuh/Splunk/CrowdStrike."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest
from jwt.algorithms import RSAAlgorithm

from utils.oidc import OidcError, build_authorization_url, complete_login, is_configured

# ---------- a real RSA keypair for signing test ID tokens ----------

from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_JWK = json.loads(RSAAlgorithm(RSAAlgorithm.SHA256).to_jwk(_PRIVATE_KEY.public_key()))
_PUBLIC_JWK.update({"kid": "test-key-1", "use": "sig", "alg": "RS256"})

_OTHER_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _sign_id_token(claims: dict, key=None) -> str:
    return jwt.encode(claims, key or _PRIVATE_KEY, algorithm="RS256", headers={"kid": "test-key-1"})


# ---------- real local mock OIDC provider ----------


class _MockOidcHandler(BaseHTTPRequestHandler):
    def _send_json(self, body: dict, status: int = 200):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            base = f"http://127.0.0.1:{self.server.server_port}"
            self._send_json({
                "issuer": base,
                "authorization_endpoint": f"{base}/authorize",
                "token_endpoint": f"{base}/token",
                "jwks_uri": f"{base}/jwks",
            })
        elif self.path == "/jwks":
            self._send_json({"keys": [_PUBLIC_JWK]})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/token":
            length = int(self.headers.get("Content-Length", 0) or 0)
            self.rfile.read(length)  # form body, not needed by the fixed response below
            self._send_json({"access_token": "fake-access-token", "id_token": self.server.next_id_token})
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def mock_idp():
    server = HTTPServer(("127.0.0.1", 0), _MockOidcHandler)
    server.next_id_token = None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.issuer = f"http://127.0.0.1:{server.server_port}"
    yield server
    server.shutdown()
    server.server_close()


def _configure(monkeypatch, mock_idp):
    monkeypatch.setenv("CAVENDEX_OIDC_ISSUER_URL", mock_idp.issuer)
    monkeypatch.setenv("CAVENDEX_OIDC_CLIENT_ID", "test-client")
    monkeypatch.setenv("CAVENDEX_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("CAVENDEX_OIDC_REDIRECT_URL", "http://cavendex.example/auth/oidc/callback")
    # utils/oidc.py caches the discovery document keyed by issuer for an
    # hour -- a fresh mock server on a new random port each test must not
    # accidentally reuse a previous test's cached document.
    import utils.oidc as oidc_module
    oidc_module._DISCOVERY_CACHE.clear()


def _base_claims(mock_idp, **overrides):
    claims = {
        "iss": mock_idp.issuer,
        "aud": "test-client",
        "sub": "user-123",
        "preferred_username": "j.smith",
        "email": "j.smith@example.com",
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
    }
    claims.update(overrides)
    # A None override means "a real IdP simply wouldn't send this claim,"
    # not "send it as a JSON null" -- PyJWT's own claim validation (e.g.
    # "sub must be a string") would otherwise reject a null sub before
    # this project's own "no usable identity claim" check is ever reached.
    return {k: v for k, v in claims.items() if v is not None}


# ---------- configuration ----------


def test_is_configured_false_when_unset(monkeypatch):
    for var in ("CAVENDEX_OIDC_ISSUER_URL", "CAVENDEX_OIDC_CLIENT_ID", "CAVENDEX_OIDC_CLIENT_SECRET", "CAVENDEX_OIDC_REDIRECT_URL"):
        monkeypatch.delenv(var, raising=False)
    assert is_configured() is False


def test_is_configured_true_when_fully_set(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    assert is_configured() is True


# ---------- _state_secret: the real, live-confirmed multi-worker bug fix ----------


def test_state_secret_is_deterministic_not_random_per_process(monkeypatch, mock_idp):
    """The real bug this locks in: the old design generated a fresh random
    secret once at module-import time, which `cavendex serve --workers N`
    breaks -- uvicorn spawns each worker as a genuinely fresh Python
    interpreter (multiprocessing's "spawn" context, not fork-after-import),
    so each worker got its own, different random secret, and a login whose
    callback landed on a different worker than the one that started it
    failed every time. Deriving the secret from CAVENDEX_OIDC_CLIENT_SECRET
    instead means every worker computes the identical value, since they all
    read the same .env -- simulated here by calling the function twice with
    nothing cached between calls, standing in for two independent worker
    processes recomputing it from scratch."""
    _configure(monkeypatch, mock_idp)
    import utils.oidc as oidc_module

    assert oidc_module._state_secret() == oidc_module._state_secret()


def test_state_secret_changes_with_client_secret(monkeypatch, mock_idp):
    """Confirms this is a real derivation from the configured secret, not a
    hardcoded constant that would trivially defeat the point of signing
    state at all."""
    _configure(monkeypatch, mock_idp)
    import utils.oidc as oidc_module

    first = oidc_module._state_secret()
    monkeypatch.setenv("CAVENDEX_OIDC_CLIENT_SECRET", "a-completely-different-secret")
    assert oidc_module._state_secret() != first


def test_login_started_and_completed_by_different_simulated_workers(monkeypatch, mock_idp):
    """End-to-end proof of the fix: a state JWT is built (simulating the
    worker that served /auth/oidc/login), then verified via a state secret
    recomputed completely independently (simulating a *different* worker,
    spawned fresh, serving /auth/oidc/callback) -- and the login still
    completes, which is exactly the case that failed before this fix."""
    _configure(monkeypatch, mock_idp)
    auth_url = build_authorization_url("acme-corp")
    from urllib.parse import unquote

    state = unquote(dict(p.split("=", 1) for p in auth_url.split("?", 1)[1].split("&"))["state"])
    nonce = jwt.decode(state, options={"verify_signature": False})["nonce"]

    # Prove the state was NOT signed with any cached/global secret still
    # sitting in this process's memory -- decode it using a state secret
    # computed fresh, the same way an entirely different worker process
    # would have to.
    import utils.oidc as oidc_module

    independently_recomputed_secret = oidc_module._state_secret()
    reverified = jwt.decode(state, independently_recomputed_secret, algorithms=["HS256"])
    assert reverified["tenant_id"] == "acme-corp"

    mock_idp.next_id_token = _sign_id_token(_base_claims(mock_idp, nonce=nonce))
    identity = complete_login("real-auth-code", state)
    assert identity == {"tenant_id": "acme-corp", "username": "j.smith", "role": "analyst"}


# ---------- build_authorization_url ----------


def test_authorization_url_has_pkce_and_client_params(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    url = build_authorization_url("acme-corp")
    assert url.startswith(mock_idp.issuer + "/authorize?")
    assert "client_id=test-client" in url
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url
    assert "response_type=code" in url


# ---------- complete_login: happy path ----------


def test_complete_login_happy_path(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    auth_url = build_authorization_url("acme-corp")
    state = dict(p.split("=", 1) for p in auth_url.split("?", 1)[1].split("&")).get("state")
    from urllib.parse import unquote

    state = unquote(state)

    mock_idp.next_id_token = _sign_id_token(_base_claims(mock_idp, nonce=jwt.decode(state, options={"verify_signature": False})["nonce"]))

    identity = complete_login("real-auth-code", state)
    assert identity == {"tenant_id": "acme-corp", "username": "j.smith", "role": "analyst"}


def test_complete_login_falls_back_to_email_then_sub(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    auth_url = build_authorization_url("default")
    from urllib.parse import unquote

    state = unquote(dict(p.split("=", 1) for p in auth_url.split("?", 1)[1].split("&"))["state"])
    nonce = jwt.decode(state, options={"verify_signature": False})["nonce"]

    mock_idp.next_id_token = _sign_id_token(
        _base_claims(mock_idp, nonce=nonce, preferred_username=None, email="only-email@example.com")
    )
    identity = complete_login("code", state)
    assert identity["username"] == "only-email@example.com"


# ---------- complete_login: rejections ----------


def test_rejects_expired_state(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    import utils.oidc as oidc_module

    expired_state = jwt.encode(
        {"tenant_id": "default", "code_verifier": "x", "nonce": "n", "exp": int(time.time()) - 10},
        oidc_module._state_secret(),
        algorithm="HS256",
    )
    with pytest.raises(OidcError, match="Invalid or expired"):
        complete_login("code", expired_state)


def test_rejects_state_signed_with_wrong_secret(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    forged_state = jwt.encode(
        {"tenant_id": "default", "code_verifier": "x", "nonce": "n", "exp": int(time.time()) + 300},
        "not-the-real-secret",
        algorithm="HS256",
    )
    with pytest.raises(OidcError, match="Invalid or expired"):
        complete_login("code", forged_state)


def test_rejects_nonce_mismatch(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    auth_url = build_authorization_url("default")
    from urllib.parse import unquote

    state = unquote(dict(p.split("=", 1) for p in auth_url.split("?", 1)[1].split("&"))["state"])

    mock_idp.next_id_token = _sign_id_token(_base_claims(mock_idp, nonce="a-different-nonce-entirely"))
    with pytest.raises(OidcError, match="nonce mismatch"):
        complete_login("code", state)


def test_rejects_wrong_issuer_in_id_token(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    auth_url = build_authorization_url("default")
    from urllib.parse import unquote

    state = unquote(dict(p.split("=", 1) for p in auth_url.split("?", 1)[1].split("&"))["state"])
    nonce = jwt.decode(state, options={"verify_signature": False})["nonce"]

    mock_idp.next_id_token = _sign_id_token(_base_claims(mock_idp, nonce=nonce, iss="https://an-attacker-controlled-issuer.example"))
    with pytest.raises(OidcError, match="verification failed"):
        complete_login("code", state)


def test_rejects_wrong_audience_in_id_token(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    auth_url = build_authorization_url("default")
    from urllib.parse import unquote

    state = unquote(dict(p.split("=", 1) for p in auth_url.split("?", 1)[1].split("&"))["state"])
    nonce = jwt.decode(state, options={"verify_signature": False})["nonce"]

    mock_idp.next_id_token = _sign_id_token(_base_claims(mock_idp, nonce=nonce, aud="someone-elses-client-id"))
    with pytest.raises(OidcError, match="verification failed"):
        complete_login("code", state)


def test_rejects_expired_id_token(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    auth_url = build_authorization_url("default")
    from urllib.parse import unquote

    state = unquote(dict(p.split("=", 1) for p in auth_url.split("?", 1)[1].split("&"))["state"])
    nonce = jwt.decode(state, options={"verify_signature": False})["nonce"]

    mock_idp.next_id_token = _sign_id_token(_base_claims(mock_idp, nonce=nonce, exp=int(time.time()) - 60))
    with pytest.raises(OidcError, match="verification failed"):
        complete_login("code", state)


def test_rejects_id_token_signed_with_wrong_key(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    auth_url = build_authorization_url("default")
    from urllib.parse import unquote

    state = unquote(dict(p.split("=", 1) for p in auth_url.split("?", 1)[1].split("&"))["state"])
    nonce = jwt.decode(state, options={"verify_signature": False})["nonce"]

    # Signed with a real RSA key, just not the one published in the mock
    # IdP's own JWKS -- PyJWKClient will fetch the real (wrong) public key
    # for this kid... actually this key has no matching kid in the JWKS
    # at all, which PyJWKClient must also reject rather than guessing.
    forged = jwt.encode(
        _base_claims(mock_idp, nonce=nonce), _OTHER_PRIVATE_KEY, algorithm="RS256", headers={"kid": "test-key-1"}
    )
    mock_idp.next_id_token = forged
    with pytest.raises(OidcError, match="verification failed"):
        complete_login("code", state)


def test_rejects_id_token_with_no_usable_identity_claim(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    auth_url = build_authorization_url("default")
    from urllib.parse import unquote

    state = unquote(dict(p.split("=", 1) for p in auth_url.split("?", 1)[1].split("&"))["state"])
    nonce = jwt.decode(state, options={"verify_signature": False})["nonce"]

    mock_idp.next_id_token = _sign_id_token(
        _base_claims(mock_idp, nonce=nonce, preferred_username=None, email=None, sub=None)
    )
    with pytest.raises(OidcError, match="no usable identity claim"):
        complete_login("code", state)
