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
from typing import List

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
    """Add the columns correlation needs (iocs/affected_assets/created_at)
    to a table that may already exist from before correlation was built —
    an ALTER TABLE migration instead of a schema bump, since this is a
    disposable index the dashboard rebuilds from vault writes, not a
    system worth a real migration framework.
    """
    existing = {row[1] for row in conn.execute("PRAGMA table_info(incidents)")}
    for column in ("iocs", "affected_assets", "created_at", "attack_technique_id", "attack_technique_name"):
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


def list_incidents(tenant_id: str = DEFAULT_TENANT, limit: int = 100) -> List[dict]:
    conn = _get_connection(tenant_id)
    cursor = conn.execute(
        """
        SELECT thread_id, report_type, description, severity, status, source, has_pending_actions, updated_at
        FROM incidents ORDER BY updated_at DESC LIMIT ?
        """,
        (max(1, min(limit, 500)),),
    )
    columns = [d[0] for d in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


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
