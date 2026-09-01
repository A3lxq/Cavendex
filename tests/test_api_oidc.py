"""Tests the /auth/oidc/* routes' wiring against a real HTTP
request/response cycle via TestClient -- status/404-when-unconfigured,
the redirect to a real local mock IdP, and a full real callback round
trip issuing a real session. JWT/claim-verification edge cases are
covered exhaustively in tests/test_oidc.py; this file is about routing
and session issuance, not re-testing that logic."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from api import api
from utils.user_accounts import validate_session

client = TestClient(api, follow_redirects=False)

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_JWK = json.loads(RSAAlgorithm(RSAAlgorithm.SHA256).to_jwk(_PRIVATE_KEY.public_key()))
_PUBLIC_JWK.update({"kid": "test-key-1", "use": "sig", "alg": "RS256"})


class _MockOidcHandler(BaseHTTPRequestHandler):
    def _send_json(self, body, status=200):
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
            self.rfile.read(length)
            self._send_json({"access_token": "fake", "id_token": self.server.next_id_token})
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


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.delenv("CAVENDEX_API_KEY", raising=False)
    import utils.oidc as oidc_module

    oidc_module._DISCOVERY_CACHE.clear()
    yield


def _configure(monkeypatch, mock_idp):
    monkeypatch.setenv("CAVENDEX_OIDC_ISSUER_URL", mock_idp.issuer)
    monkeypatch.setenv("CAVENDEX_OIDC_CLIENT_ID", "test-client")
    monkeypatch.setenv("CAVENDEX_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("CAVENDEX_OIDC_REDIRECT_URL", "http://cavendex.example/auth/oidc/callback")


def _sign_id_token(mock_idp, nonce, **overrides):
    claims = {
        "iss": mock_idp.issuer,
        "aud": "test-client",
        "sub": "user-123",
        "preferred_username": "j.smith",
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
        "nonce": nonce,
    }
    claims.update(overrides)
    return jwt.encode(claims, _PRIVATE_KEY, algorithm="RS256", headers={"kid": "test-key-1"})


def _extract_state_and_nonce(login_response):
    location = login_response.headers["location"]
    query = parse_qs(urlparse(location).query)
    state = query["state"][0]
    nonce = query["nonce"][0]
    return state, nonce


# ---------- /auth/oidc/status ----------


def test_status_false_when_unconfigured(monkeypatch):
    for var in ("CAVENDEX_OIDC_ISSUER_URL", "CAVENDEX_OIDC_CLIENT_ID", "CAVENDEX_OIDC_CLIENT_SECRET", "CAVENDEX_OIDC_REDIRECT_URL"):
        monkeypatch.delenv(var, raising=False)
    response = client.get("/auth/oidc/status")
    assert response.status_code == 200
    assert response.json() == {"enabled": False}


def test_status_true_when_configured(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    response = client.get("/auth/oidc/status")
    assert response.json() == {"enabled": True}


# ---------- /auth/oidc/login ----------


def test_login_404s_when_unconfigured(monkeypatch):
    for var in ("CAVENDEX_OIDC_ISSUER_URL", "CAVENDEX_OIDC_CLIENT_ID", "CAVENDEX_OIDC_CLIENT_SECRET", "CAVENDEX_OIDC_REDIRECT_URL"):
        monkeypatch.delenv(var, raising=False)
    response = client.get("/auth/oidc/login")
    assert response.status_code == 404


def test_login_redirects_to_real_idp_authorization_endpoint(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    response = client.get("/auth/oidc/login")
    assert response.status_code in (302, 307)
    assert response.headers["location"].startswith(mock_idp.issuer + "/authorize?")


def test_tenant_scoped_login_encodes_the_right_tenant_in_state(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    response = client.get("/tenants/acme-corp/auth/oidc/login")
    state, _ = _extract_state_and_nonce(response)
    import utils.oidc as oidc_module

    claims = jwt.decode(unquote(state), oidc_module._STATE_SECRET, algorithms=["HS256"])
    assert claims["tenant_id"] == "acme-corp"


# ---------- /auth/oidc/callback ----------


def test_callback_issues_a_real_working_session(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    login_response = client.get("/auth/oidc/login")
    state, nonce = _extract_state_and_nonce(login_response)
    state = unquote(state)

    mock_idp.next_id_token = _sign_id_token(mock_idp, nonce)

    callback_response = client.get("/auth/oidc/callback", params={"code": "real-auth-code", "state": state})
    assert callback_response.status_code in (302, 307)

    location = callback_response.headers["location"]
    query = parse_qs(urlparse(location).query)
    assert query["oidc_username"][0] == "j.smith"
    assert query["oidc_role"][0] == "analyst"
    assert query["oidc_tenant"][0] == "default"

    token = query["oidc_token"][0]
    session = validate_session("default", token)
    assert session == {"username": "j.smith", "role": "analyst"}

    # The issued session actually authenticates a protected route.
    protected = client.get("/incidents/stats", headers={"Authorization": f"Bearer {token}"})
    assert protected.status_code == 200


def test_callback_rejects_bad_state_with_401(monkeypatch, mock_idp):
    _configure(monkeypatch, mock_idp)
    response = client.get("/auth/oidc/callback", params={"code": "code", "state": "not-a-real-state"})
    assert response.status_code == 401
