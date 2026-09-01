"""Dashboard-serving and list-endpoint tests. No LLM provider needed."""

from fastapi.testclient import TestClient

from api import api
from state import Incident
from utils.incident_index import reset_for_tests, upsert_incident_summary

client = TestClient(api)


def setup_function():
    reset_for_tests()


def test_dashboard_shell_is_served_unauthenticated(monkeypatch):
    monkeypatch.setenv("CAVENDEX_API_KEY", "secret-key-123")
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Cavendex" in response.text


def test_static_assets_are_served_unauthenticated(monkeypatch):
    monkeypatch.setenv("CAVENDEX_API_KEY", "secret-key-123")
    js = client.get("/static/app.js")
    css = client.get("/static/style.css")
    assert js.status_code == 200
    assert "javascript" in js.headers["content-type"]
    assert css.status_code == 200
    assert "css" in css.headers["content-type"]


def test_list_incidents_requires_auth_when_configured(monkeypatch):
    monkeypatch.setenv("CAVENDEX_API_KEY", "secret-key-123")
    response = client.get("/tenants/dash-test/incidents")
    assert response.status_code == 401


def test_list_incidents_returns_seeded_summaries(monkeypatch, tmp_path):
    monkeypatch.delenv("CAVENDEX_API_KEY", raising=False)
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))

    upsert_incident_summary(
        "dash-test",
        {"incident": Incident(id="inc-1", description="test", severity="high", status="pending_approval"),
         "tenant_id": "dash-test"},
    )

    response = client.get("/tenants/dash-test/incidents")
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 1
    assert rows[0]["thread_id"] == "inc-1"
    assert rows[0]["has_pending_actions"] == 1


def test_list_incidents_empty_for_unknown_tenant(monkeypatch, tmp_path):
    monkeypatch.delenv("CAVENDEX_API_KEY", raising=False)
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    response = client.get("/tenants/never-used-tenant/incidents")
    assert response.status_code == 200
    assert response.json() == []


def _seed_two(tenant, tmp_path, monkeypatch):
    monkeypatch.delenv("CAVENDEX_API_KEY", raising=False)
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    upsert_incident_summary(
        tenant,
        {"incident": Incident(id="inc-1", description="Brute force from 1.2.3.4", severity="high", status="open"),
         "tenant_id": tenant},
    )
    upsert_incident_summary(
        tenant,
        {"incident": Incident(id="inc-2", description="Malware on DC-01", severity="critical", status="pending_approval"),
         "tenant_id": tenant},
    )


def test_list_incidents_filters_by_severity_via_query_param(monkeypatch, tmp_path):
    _seed_two("dash-test", tmp_path, monkeypatch)
    response = client.get("/tenants/dash-test/incidents", params={"severity": "critical"})
    assert response.status_code == 200
    rows = response.json()
    assert [r["thread_id"] for r in rows] == ["inc-2"]


def test_list_incidents_filters_by_search_via_query_param(monkeypatch, tmp_path):
    _seed_two("dash-test", tmp_path, monkeypatch)
    response = client.get("/tenants/dash-test/incidents", params={"search": "brute"})
    assert response.status_code == 200
    rows = response.json()
    assert [r["thread_id"] for r in rows] == ["inc-1"]


def test_default_tenant_list_route_also_accepts_filters(monkeypatch, tmp_path):
    from utils.tenancy import DEFAULT_TENANT

    _seed_two(DEFAULT_TENANT, tmp_path, monkeypatch)
    response = client.get("/incidents", params={"status": "pending_approval"})
    assert response.status_code == 200
    rows = response.json()
    assert [r["thread_id"] for r in rows] == ["inc-2"]


def test_incident_stats_route_returns_aggregate_counts(monkeypatch, tmp_path):
    _seed_two("dash-test", tmp_path, monkeypatch)
    response = client.get("/tenants/dash-test/incidents/stats")
    assert response.status_code == 200
    stats = response.json()
    assert stats["total"] == 2
    assert stats["pending_approval"] == 1
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["high"] == 1


def test_incident_stats_route_does_not_collide_with_thread_id_route(monkeypatch, tmp_path):
    """/incidents/stats must resolve to the stats route, not be swallowed
    by GET /incidents/{thread_id} treating "stats" as a thread_id."""
    _seed_two("dash-test", tmp_path, monkeypatch)
    response = client.get("/tenants/dash-test/incidents/stats")
    assert response.status_code == 200
    assert "total" in response.json()  # stats shape, not a 404 "incident not found"


def test_default_tenant_stats_route(monkeypatch, tmp_path):
    from utils.tenancy import DEFAULT_TENANT

    _seed_two(DEFAULT_TENANT, tmp_path, monkeypatch)
    response = client.get("/incidents/stats")
    assert response.status_code == 200
    assert response.json()["total"] == 2


def test_kpis_route_returns_the_aggregate_shape(monkeypatch, tmp_path):
    _seed_two("dash-test", tmp_path, monkeypatch)
    response = client.get("/tenants/dash-test/incidents/kpis")
    assert response.status_code == 200
    stats = response.json()
    assert stats["total"] == 2
    assert "mttr_seconds" in stats and "mean" in stats["mttr_seconds"]
    assert "dwell_seconds" in stats and "mean" in stats["dwell_seconds"]
    assert "escalation_rate" in stats
    assert "volume_by_day" in stats


def test_kpis_route_does_not_collide_with_thread_id_route(monkeypatch, tmp_path):
    _seed_two("dash-test", tmp_path, monkeypatch)
    response = client.get("/tenants/dash-test/incidents/kpis")
    assert response.status_code == 200
    assert "total" in response.json()  # kpis shape, not a 404 "incident not found"


def test_kpis_route_requires_auth_when_configured(monkeypatch):
    monkeypatch.setenv("CAVENDEX_API_KEY", "secret-key-123")
    response = client.get("/tenants/dash-test/incidents/kpis")
    assert response.status_code == 401


def test_default_tenant_kpis_route(monkeypatch, tmp_path):
    from utils.tenancy import DEFAULT_TENANT

    _seed_two(DEFAULT_TENANT, tmp_path, monkeypatch)
    response = client.get("/incidents/kpis")
    assert response.status_code == 200
    assert response.json()["total"] == 2


def test_kpis_route_accepts_since_query_param(monkeypatch, tmp_path):
    _seed_two("dash-test", tmp_path, monkeypatch)
    response = client.get("/tenants/dash-test/incidents/kpis", params={"since": "2099-01-01T00:00:00+00:00"})
    assert response.status_code == 200
    assert response.json()["total"] == 0  # both seeded incidents predate this future "since"
