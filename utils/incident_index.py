"""A lightweight per-tenant index of incident summaries.

LangGraph's checkpoint schema (graph.py's SqliteSaver) isn't designed for
"list all incidents with summary metadata, sorted by recency" queries —
that's not what a checkpointer is for. This is a small, separate SQLite
table per tenant, upserted every time an incident's vault report is
written, that exists purely to make the dashboard's incident list fast
and simple without reaching into LangGraph internals.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import List, Optional

from graph import tenant_data_dir
from state import OPEN_STATUSES
from utils.tenancy import DEFAULT_TENANT, sanitize_tenant_id

_lock = threading.Lock()
_connections: dict = {}


def _get_connection(tenant_id: str) -> sqlite3.Connection:
    tenant_id = sanitize_tenant_id(tenant_id)

    if tenant_id in _connections:
        return _connections[tenant_id]

    with _lock:
        if tenant_id in _connections:
            return _connections[tenant_id]

        tenant_dir = tenant_data_dir(tenant_id)
        os.makedirs(tenant_dir, exist_ok=True)
        db_path = os.path.join(tenant_dir, "incident_index.db")

        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                thread_id TEXT PRIMARY KEY,
                report_type TEXT,
                description TEXT,
                severity TEXT,
                status TEXT,
                source TEXT,
                has_pending_actions INTEGER,
                updated_at TEXT
            )
            """
        )
        _ensure_correlation_columns(conn)
        conn.commit()
        _connections[tenant_id] = conn
        return conn


def _ensure_correlation_columns(conn: sqlite3.Connection) -> None:
    """Add columns that may not exist on a table created before they were
    needed — an ALTER TABLE migration instead of a schema bump, since
    this is a disposable index the dashboard rebuilds from vault writes,
    not a system worth a real migration framework. `assigned_to` is
    deliberately never written by upsert_incident_summary below (only by
    set_assigned_to) — leaving it out of that INSERT/UPDATE entirely
    means a routine pipeline re-upsert can never silently wipe an
    analyst's assignment.
    """
    existing = {row[1] for row in conn.execute("PRAGMA table_info(incidents)")}
    for column in (
        "iocs", "affected_assets", "created_at", "attack_technique_id", "attack_technique_name", "assigned_to",
    ):
        if column not in existing:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {column} TEXT")


def upsert_incident_summary(tenant_id: str, state: dict, report_type: str = "incident") -> None:
    if not state:
        return
    incident = state.get("incident")
    if incident is None:
        return

    # Only ever persist a *verified* technique — an unverified (possibly
    # hallucinated) citation has no place becoming "known ground truth" a
    # later semantic-correlation judgment treats as evidence for merging
    # two incidents. See enrichment/mitre_attack.py for how verification
    # itself works.
    attack_technique = state.get("attack_technique") or {}
    if not attack_technique.get("verified"):
        attack_technique = {}

    conn = _get_connection(tenant_id)
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn.execute(
            """
            INSERT INTO incidents
                (thread_id, report_type, description, severity, status, source,
                 has_pending_actions, iocs, affected_assets, attack_technique_id,
                 attack_technique_name, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(thread_id) DO UPDATE SET
                report_type=excluded.report_type,
                description=excluded.description,
                severity=excluded.severity,
                status=excluded.status,
                source=excluded.source,
                has_pending_actions=excluded.has_pending_actions,
                iocs=excluded.iocs,
                affected_assets=excluded.affected_assets,
                attack_technique_id=excluded.attack_technique_id,
                attack_technique_name=excluded.attack_technique_name,
                updated_at=excluded.updated_at
            """,
            (
                incident.id,
                report_type,
                incident.description[:300],
                incident.severity,
                incident.status,
                incident.source or "",
                1 if incident.status == "pending_approval" else 0,
                json.dumps(incident.iocs),
                json.dumps(incident.affected_assets),
                attack_technique.get("id"),
                attack_technique.get("name"),
                now,
                now,
            ),
        )
        conn.commit()


def list_incidents(
    tenant_id: str = DEFAULT_TENANT,
    limit: int = 100,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
) -> List[dict]:
    """Lists incidents, most recently updated first, optionally filtered
    by exact severity/status and/or a case-insensitive substring match on
    description. Filtering happens in SQL against the index rather than
    over just the page already fetched, so it stays correct regardless
    of how many incidents exist beyond `limit` — the same reasoning
    every other query in this file already applies.
    """
    conn = _get_connection(tenant_id)
    clauses = []
    params: List = []
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if search:
        clauses.append("description LIKE ? ESCAPE '\\'")
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params.append(f"%{escaped}%")
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(max(1, min(limit, 500)))

    cursor = conn.execute(
        f"""
        SELECT thread_id, report_type, description, severity, status, source, has_pending_actions,
               assigned_to, updated_at
        FROM incidents {where_sql} ORDER BY updated_at DESC LIMIT ?
        """,
        params,
    )
    columns = [d[0] for d in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def set_assigned_to(tenant_id: str, thread_id: str, assigned_to: Optional[str]) -> bool:
    """Sets (or clears, if `assigned_to` is None/empty) which analyst is
    working an incident — a free-text label, not an authenticated
    identity, the same accountability caveat as `approved_by` everywhere
    else in this project. Returns False if the incident isn't in the
    index at all (nothing to assign), True otherwise.
    """
    conn = _get_connection(tenant_id)
    with _lock:
        cursor = conn.execute(
            "UPDATE incidents SET assigned_to = ? WHERE thread_id = ?",
            (assigned_to or None, thread_id),
        )
        conn.commit()
    return cursor.rowcount > 0


def get_attack_technique_stats(tenant_id: str = DEFAULT_TENANT) -> List[dict]:
    """How many incidents cited each ATT&CK technique — only ever
    *verified* citations, since upsert_incident_summary() never persists
    an unverified one here in the first place (see its own docstring
    below). The tactic each technique belongs to isn't looked up here —
    that needs enrichment/mitre_attack.py's dataset, a different module
    this one doesn't import, to avoid a layering dependency the other
    direction doesn't have; callers combine the two (see api.py).
    """
    conn = _get_connection(tenant_id)
    rows = conn.execute(
        """
        SELECT attack_technique_id, attack_technique_name, COUNT(*) as cnt
        FROM incidents WHERE attack_technique_id IS NOT NULL
        GROUP BY attack_technique_id, attack_technique_name
        ORDER BY cnt DESC
        """
    ).fetchall()
    return [{"id": r[0], "name": r[1], "count": r[2]} for r in rows]


def get_incident_stats(tenant_id: str = DEFAULT_TENANT) -> dict:
    """Aggregate counts for the dashboard's summary bar — real SQL
    COUNT()s against the whole index, not just whatever page of rows
    list_incidents() happens to return, so this stays correct regardless
    of how many incidents exist beyond any UI page size.
    """
    conn = _get_connection(tenant_id)
    total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    pending_approval = conn.execute("SELECT COUNT(*) FROM incidents WHERE has_pending_actions = 1").fetchone()[0]
    open_placeholders = ",".join("?" for _ in OPEN_STATUSES)
    open_count = conn.execute(
        f"SELECT COUNT(*) FROM incidents WHERE status IN ({open_placeholders})", OPEN_STATUSES
    ).fetchone()[0]
    severity_rows = conn.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity").fetchall()
    by_severity_counts = dict(severity_rows)
    return {
        "total": total,
        "open": open_count,
        "pending_approval": pending_approval,
        "by_severity": {sev: by_severity_counts.get(sev, 0) for sev in ("low", "medium", "high", "critical")},
    }


def list_open_incidents(tenant_id: str = DEFAULT_TENANT) -> List[dict]:
    """Every incident in this tenant that isn't contained/closed, with its
    IOCs and affected assets decoded, plus its verified MITRE ATT&CK
    technique (id/name, or None if none was cited or it wasn't verified)
    — the candidate pool ingestion/correlation.py and
    ingestion/semantic_correlation.py check a new alert against. Small
    enough at realistic open-incident counts to filter in Python rather
    than push IOC/asset matching into SQL.
    """
    conn = _get_connection(tenant_id)
    placeholders = ",".join("?" for _ in OPEN_STATUSES)
    cursor = conn.execute(
        f"""
        SELECT thread_id, description, severity, status, source, iocs, affected_assets,
               attack_technique_id, attack_technique_name, created_at, updated_at
        FROM incidents WHERE status IN ({placeholders})
        ORDER BY updated_at DESC
        """,
        OPEN_STATUSES,
    )
    columns = [d[0] for d in cursor.description]
    rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    for row in rows:
        row["iocs"] = json.loads(row["iocs"]) if row.get("iocs") else []
        row["affected_assets"] = json.loads(row["affected_assets"]) if row.get("affected_assets") else []
    return rows


def reset_for_tests() -> None:
    with _lock:
        for conn in _connections.values():
            conn.close()
        _connections.clear()
