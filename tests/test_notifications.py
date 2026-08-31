"""Tests notifications/webhook.py against a real local HTTP server (same
technique as test_polling_connector.py — a real POST request over a real
socket, not a mocked requests.post) and notifications/pipeline.py's
should-we-notify decision logic, plus that workflows/incident_pipeline.py
actually calls it from the right places and not the wrong ones."""

import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from notifications.pipeline import build_notification_payload, notify_if_needed, should_notify
from notifications.webhook import send_webhook_notification, sign_payload, webhook_configured
from state import Incident


class _RecordingHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.seen.append(json.loads(body) if body else None)
        self.seen_bodies.append(body)
        self.seen_headers.append({k.lower(): v for k, v in self.headers.items()})
        self.send_response(self.status_code)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def http_server():
    seen = []
    seen_bodies = []
    seen_headers = []

    class Handler(_RecordingHandler):
        pass

    Handler.seen = seen
    Handler.seen_bodies = seen_bodies
    Handler.seen_headers = seen_headers
    Handler.status_code = 200

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    server.seen = seen
    server.seen_bodies = seen_bodies
    server.seen_headers = seen_headers
    server.set_status = lambda code: setattr(Handler, "status_code", code)
    server.url = f"http://127.0.0.1:{server.server_address[1]}/webhook"

    yield server

    server.shutdown()
    server.server_close()


def _incident(**overrides):
    defaults = dict(id="inc-1", description="Suspicious login", severity="medium", status="investigating")
    defaults.update(overrides)
    return Incident(**defaults)


# ---------- webhook.py ----------


def test_webhook_not_configured_by_default(monkeypatch):
    monkeypatch.delenv("CAVENDEX_ALERT_WEBHOOK_URL", raising=False)
    assert webhook_configured() is False
    assert send_webhook_notification({"text": "x"}) is False


def test_webhook_sends_a_real_post_request(monkeypatch, http_server):
    monkeypatch.setenv("CAVENDEX_ALERT_WEBHOOK_URL", http_server.url)
    assert webhook_configured() is True

    result = send_webhook_notification({"text": "hello", "severity": "high"})

    assert result is True
    assert http_server.seen == [{"text": "hello", "severity": "high"}]


def test_webhook_returns_false_on_non_2xx(monkeypatch, http_server):
    monkeypatch.setenv("CAVENDEX_ALERT_WEBHOOK_URL", http_server.url)
    http_server.set_status(500)

    assert send_webhook_notification({"text": "x"}) is False


def test_webhook_returns_false_on_connection_failure(monkeypatch):
    # Nothing listens on this port — a real connection failure, not mocked.
    monkeypatch.setenv("CAVENDEX_ALERT_WEBHOOK_URL", "http://127.0.0.1:1/webhook")
    assert send_webhook_notification({"text": "x"}) is False


def test_webhook_unsigned_by_default(monkeypatch, http_server):
    monkeypatch.setenv("CAVENDEX_ALERT_WEBHOOK_URL", http_server.url)
    monkeypatch.delenv("CAVENDEX_WEBHOOK_SIGNING_SECRET", raising=False)

    send_webhook_notification({"text": "hello"})

    assert "x-cavendex-signature" not in http_server.seen_headers[0]


def test_webhook_signs_body_when_secret_configured(monkeypatch, http_server):
    monkeypatch.setenv("CAVENDEX_ALERT_WEBHOOK_URL", http_server.url)
    monkeypatch.setenv("CAVENDEX_WEBHOOK_SIGNING_SECRET", "shh-its-a-secret")

    send_webhook_notification({"text": "hello", "severity": "high"})

    received_body = http_server.seen_bodies[0]
    received_signature = http_server.seen_headers[0].get("x-cavendex-signature")
    expected_signature = "sha256=" + hmac.new(b"shh-its-a-secret", received_body, hashlib.sha256).hexdigest()
    assert received_signature == expected_signature


def test_webhook_signature_changes_if_secret_differs(monkeypatch, http_server):
    monkeypatch.setenv("CAVENDEX_ALERT_WEBHOOK_URL", http_server.url)
    monkeypatch.setenv("CAVENDEX_WEBHOOK_SIGNING_SECRET", "secret-a")
    send_webhook_notification({"text": "hello"})
    sig_a = http_server.seen_headers[0]["x-cavendex-signature"]

    monkeypatch.setenv("CAVENDEX_WEBHOOK_SIGNING_SECRET", "secret-b")
    send_webhook_notification({"text": "hello"})
    sig_b = http_server.seen_headers[1]["x-cavendex-signature"]

    assert sig_a != sig_b


def test_sign_payload_matches_raw_hmac_sha256():
    body = b'{"text": "hi"}'
    assert sign_payload(body, "secret") == "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()


# ---------- pipeline.py: should_notify ----------


def test_pending_approval_always_notifies(monkeypatch):
    monkeypatch.delenv("CAVENDEX_ALERT_MIN_SEVERITY", raising=False)
    assert should_notify(_incident(severity="low", status="pending_approval")) is True


def test_high_severity_notifies_regardless_of_status(monkeypatch):
    monkeypatch.delenv("CAVENDEX_ALERT_MIN_SEVERITY", raising=False)
    assert should_notify(_incident(severity="high", status="investigating")) is True
    assert should_notify(_incident(severity="critical", status="open")) is True


def test_low_medium_severity_non_pending_does_not_notify(monkeypatch):
    monkeypatch.delenv("CAVENDEX_ALERT_MIN_SEVERITY", raising=False)
    assert should_notify(_incident(severity="low", status="investigating")) is False
    assert should_notify(_incident(severity="medium", status="open")) is False


def test_min_severity_threshold_is_configurable(monkeypatch):
    monkeypatch.setenv("CAVENDEX_ALERT_MIN_SEVERITY", "critical")
    assert should_notify(_incident(severity="high", status="investigating")) is False
    assert should_notify(_incident(severity="critical", status="investigating")) is True


def test_none_incident_never_notifies():
    assert should_notify(None) is False


def test_closed_low_severity_does_not_notify():
    assert should_notify(_incident(severity="low", status="closed")) is False


# ---------- pipeline.py: build_notification_payload ----------


def test_payload_includes_core_fields():
    state = {"incident": _incident(severity="high", status="pending_approval"), "tenant_id": "acme"}
    payload = build_notification_payload(state, reason="new_incident")

    assert payload["thread_id"] == "inc-1"
    assert payload["tenant_id"] == "acme"
    assert payload["severity"] == "high"
    assert payload["status"] == "pending_approval"
    assert payload["reason"] == "new_incident"
    assert "HIGH" in payload["text"]
    assert "inc-1" in payload["text"]


def test_payload_includes_dashboard_link_when_base_url_configured(monkeypatch):
    monkeypatch.setenv("CAVENDEX_DASHBOARD_BASE_URL", "https://cavendex.internal.example.com")
    state = {"incident": _incident(status="pending_approval"), "tenant_id": "acme"}

    payload = build_notification_payload(state, reason="new_incident")

    assert payload["dashboard_url"] == "https://cavendex.internal.example.com/tenants/acme/incidents/inc-1"
    assert payload["dashboard_url"] in payload["text"]


def test_payload_omits_dashboard_link_when_not_configured(monkeypatch):
    monkeypatch.delenv("CAVENDEX_DASHBOARD_BASE_URL", raising=False)
    state = {"incident": _incident(status="pending_approval"), "tenant_id": "default"}

    payload = build_notification_payload(state, reason="new_incident")

    assert "dashboard_url" not in payload


def test_default_tenant_omitted_from_dashboard_path(monkeypatch):
    monkeypatch.setenv("CAVENDEX_DASHBOARD_BASE_URL", "https://cavendex.example.com")
    state = {"incident": _incident(status="pending_approval"), "tenant_id": "default"}

    payload = build_notification_payload(state, reason="new_incident")

    assert payload["dashboard_url"] == "https://cavendex.example.com/incidents/inc-1"


# ---------- notify_if_needed: end-to-end against a real server ----------


def test_notify_if_needed_sends_when_pending_approval(monkeypatch, http_server):
    monkeypatch.setenv("CAVENDEX_ALERT_WEBHOOK_URL", http_server.url)
    state = {"incident": _incident(status="pending_approval"), "tenant_id": "acme"}

    notify_if_needed(state, reason="new_incident")

    assert len(http_server.seen) == 1
    assert http_server.seen[0]["thread_id"] == "inc-1"


def test_notify_if_needed_silent_when_nothing_warrants_it(monkeypatch, http_server):
    monkeypatch.setenv("CAVENDEX_ALERT_WEBHOOK_URL", http_server.url)
    state = {"incident": _incident(severity="low", status="investigating"), "tenant_id": "acme"}

    notify_if_needed(state, reason="new_incident")

    assert http_server.seen == []


def test_notify_if_needed_never_raises_even_with_malformed_state(monkeypatch, http_server):
    monkeypatch.setenv("CAVENDEX_ALERT_WEBHOOK_URL", http_server.url)
    notify_if_needed({}, reason="new_incident")  # no "incident" key at all
    notify_if_needed({"incident": None}, reason="new_incident")
    # no exception raised is the assertion here


# ---------- Wired into workflows/incident_pipeline.py at the right spots ----------


def test_run_new_incident_calls_notify(monkeypatch):
    import workflows.incident_pipeline as wip

    calls = []
    monkeypatch.setattr(wip, "notify_if_needed", lambda state, reason=None: calls.append(reason))
    monkeypatch.setattr(wip, "_persist", lambda *a, **kw: None)
    monkeypatch.setattr(
        wip, "get_app",
        lambda tenant_id: type("FakeApp", (), {"invoke": lambda self, *a, **kw: {"incident": None}})(),
    )

    wip.run_new_incident(description="x", tenant_id="notify-test-1")

    assert calls == ["new_incident"]


def test_merge_correlated_alert_calls_notify(monkeypatch):
    import itertools

    import workflows.incident_pipeline as wip
    from graph import get_app

    tenant = f"notify-merge-test-{next(itertools.count())}"
    app = get_app(tenant)
    config = {"configurable": {"thread_id": "inc-1"}}
    app.update_state(
        config,
        {
            "messages": [], "incident": Incident(id="inc-1", description="x", status="investigating"),
            "long_term_summary": "", "audit_log": [], "next_agent": None, "proposed_actions": [],
            "token_usage": {}, "tenant_id": tenant, "threat_intel": [], "attack_technique": None,
        },
    )

    calls = []
    monkeypatch.setattr(wip, "notify_if_needed", lambda state, reason=None: calls.append(reason))

    wip.merge_correlated_alert(
        thread_id="inc-1", description="y", severity="medium", affected_assets=[], iocs=[],
        source="test", tenant_id=tenant,
    )

    assert calls == ["correlated_merge"]


def test_resolve_proposed_actions_does_not_call_notify(monkeypatch):
    """A human just acted — re-notifying them of their own decision is
    noise, not a real 'someone needs to look at this' moment."""
    import itertools

    import workflows.incident_pipeline as wip
    from graph import get_app
    from state import ProposedAction

    tenant = f"notify-resolve-test-{next(itertools.count())}"
    app = get_app(tenant)
    config = {"configurable": {"thread_id": "inc-1"}}
    app.update_state(
        config,
        {
            "messages": [], "incident": Incident(id="inc-1", description="x", status="pending_approval"),
            "long_term_summary": "", "audit_log": [], "next_agent": None,
            "proposed_actions": [ProposedAction(action="block", target="1.2.3.4", rationale="r")],
            "token_usage": {}, "tenant_id": tenant, "threat_intel": [], "attack_technique": None,
        },
    )

    calls = []
    monkeypatch.setattr(wip, "notify_if_needed", lambda state, reason=None: calls.append(reason))

    wip.resolve_proposed_actions("inc-1", approve=True, tenant_id=tenant)

    assert calls == []
