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
from state import OPEN_STATUSES, SEVERITY_RANK
from utils.tenancy import DEFAULT_TENANT, sanitize_tenant_id

# Terminal statuses for SOC KPI purposes (see get_kpi_stats) — anything not
# in OPEN_STATUSES. An incident's resolved_at is set exactly once, the
# first time its status is observed in this set.
_TERMINAL_STATUSES = ("closed", "contained")

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
        # SOC KPI reporting (see get_kpi_stats): pending_approval_at/resolved_at
        # are each set exactly once, the first time that status is observed,
        # and never overwritten afterward — same "set once, like created_at"
        # convention already used above. max_severity_rank tracks the highest
        # SEVERITY_RANK this incident has ever reached (an incident later
        # downgraded, correlation-merged, or reclassified never loses the
        # fact that it was once high/critical) for escalation-rate reporting.
        "pending_approval_at", "resolved_at",
        # Jira Cloud case sync (see notifications/case_sync.py) -- like
        # assigned_to, deliberately never written by upsert_incident_summary
        # itself (only by set_jira_issue_key), so a routine pipeline
        # re-upsert can never silently lose track of an already-created
        # Jira issue and create a duplicate.
        "jira_issue_key",
    ):
        if column not in existing:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {column} TEXT")
    if "max_severity_rank" not in existing:
        conn.execute("ALTER TABLE incidents ADD COLUMN max_severity_rank INTEGER")


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
    severity_rank = SEVERITY_RANK.get(incident.severity, 0)
    pending_approval_at = now if incident.status == "pending_approval" else None
    resolved_at = now if incident.status in _TERMINAL_STATUSES else None
    with _lock:
        conn.execute(
            """
            INSERT INTO incidents
                (thread_id, report_type, description, severity, status, source,
                 has_pending_actions, iocs, affected_assets, attack_technique_id,
                 attack_technique_name, created_at, updated_at,
                 pending_approval_at, resolved_at, max_severity_rank)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                updated_at=excluded.updated_at,
                pending_approval_at=COALESCE(incidents.pending_approval_at, excluded.pending_approval_at),
                resolved_at=COALESCE(incidents.resolved_at, excluded.resolved_at),
                max_severity_rank=MAX(incidents.max_severity_rank, excluded.max_severity_rank)
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
                pending_approval_at,
                resolved_at,
                severity_rank,
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


def get_jira_issue_key(tenant_id: str, thread_id: str) -> Optional[str]:
    """The Jira issue key already created for this incident (see
    notifications/case_sync.py), or None if one hasn't been created yet
    -- the signal case_sync.sync_incident() uses to decide create vs.
    add-a-comment.
    """
    conn = _get_connection(tenant_id)
    row = conn.execute("SELECT jira_issue_key FROM incidents WHERE thread_id = ?", (thread_id,)).fetchone()
    return row[0] if row else None


def set_jira_issue_key(tenant_id: str, thread_id: str, jira_issue_key: str) -> bool:
    """Records the Jira issue key created for this incident. Returns
    False if the incident isn't in the index at all, True otherwise.
    """
    conn = _get_connection(tenant_id)
    with _lock:
        cursor = conn.execute(
            "UPDATE incidents SET jira_issue_key = ? WHERE thread_id = ?",
            (jira_issue_key, thread_id),
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


def _mean_median(values: List[float]) -> dict:
    if not values:
        return {"mean": None, "median": None, "count": 0}
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    median = ordered[mid] if n % 2 == 1 else (ordered[mid - 1] + ordered[mid]) / 2
    return {"mean": sum(ordered) / n, "median": median, "count": n}


def get_kpi_stats(tenant_id: str = DEFAULT_TENANT, since: Optional[str] = None) -> dict:
    """SOC KPI aggregates for the dashboard's KPI tab: MTTR, time-to-
    decision ("dwell time"), escalation rate, and incident volume by
    severity/day.

    MTTR (mean+median, seconds) = resolved_at - created_at, only over
    incidents that have actually reached a terminal status (closed/
    contained) at some point -- resolved_at is set exactly once, the
    first time that happens (see upsert_incident_summary), never
    overwritten after.

    Dwell time (mean+median, seconds) = resolved_at - pending_approval_at,
    only over incidents that both reached pending_approval and have since
    resolved. This is a direct measurement from two real, set-once
    timestamps, not an approximation from updated_at.

    Escalation rate = share of ALL incidents in scope (resolved or not)
    whose max_severity_rank has ever reached "high" or above. Correlation
    only ever escalates severity, never downgrades it (see README's Alert
    Correlation section), so this is a durable fact about the incident
    regardless of its *current* severity.

    `since` (an ISO timestamp string, compared against created_at)
    optionally scopes every metric to a time window, e.g. "this month".
    """
    conn = _get_connection(tenant_id)
    since_clause = "created_at >= ?" if since else None
    since_params = [since] if since else []

    def _scoped(extra_clause: Optional[str] = None, extra_params: Optional[list] = None):
        clauses = ([since_clause] if since_clause else []) + ([extra_clause] if extra_clause else [])
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where_sql, since_params + (extra_params or [])

    where_sql, params = _scoped()
    total = conn.execute(f"SELECT COUNT(*) FROM incidents {where_sql}", params).fetchone()[0]

    where_sql, params = _scoped("max_severity_rank >= ?", [SEVERITY_RANK["high"]])
    escalated = conn.execute(f"SELECT COUNT(*) FROM incidents {where_sql}", params).fetchone()[0]

    where_sql, params = _scoped("resolved_at IS NOT NULL AND created_at IS NOT NULL")
    mttr_rows = conn.execute(
        f"SELECT (julianday(resolved_at) - julianday(created_at)) * 86400 FROM incidents {where_sql}", params
    ).fetchall()

    where_sql, params = _scoped("resolved_at IS NOT NULL AND pending_approval_at IS NOT NULL")
    dwell_rows = conn.execute(
        f"SELECT (julianday(resolved_at) - julianday(pending_approval_at)) * 86400 FROM incidents {where_sql}",
        params,
    ).fetchall()

    where_sql, params = _scoped()
    volume_rows = conn.execute(
        f"""
        SELECT date(created_at) as day, severity, COUNT(*) as cnt
        FROM incidents {where_sql}
        GROUP BY day, severity
        ORDER BY day ASC
        """,
        params,
    ).fetchall()

    return {
        "total": total,
        "escalation_rate": (escalated / total) if total else 0.0,
        "mttr_seconds": _mean_median([r[0] for r in mttr_rows if r[0] is not None]),
        "dwell_seconds": _mean_median([r[0] for r in dwell_rows if r[0] is not None]),
        "volume_by_day": [{"date": r[0], "severity": r[1], "count": r[2]} for r in volume_rows if r[0]],
    }


def list_open_incidents(tenant_id: str = DEFAULT_TENANT, limit: int = 1000) -> List[dict]:
    """Every incident in this tenant that isn't contained/closed, with its
    IOCs and affected assets decoded, plus its verified MITRE ATT&CK
    technique (id/name, or None if none was cited or it wasn't verified)
    — the candidate pool ingestion/correlation.py and
    ingestion/semantic_correlation.py check a new alert against. Small
    enough at realistic open-incident counts to filter in Python rather
    than push IOC/asset matching into SQL.

    Capped at `limit` most-recently-updated incidents (default 1000,
    same ceiling style as get_incident_graph) — this query previously had
    no LIMIT at all, unlike every sibling query in this file, letting a
    tenant with an unusually large number of open incidents make the
    correlation candidate pool (and, transitively, identity
    correlation's real per-candidate VirusTotal lookups) grow without
    bound. Ordered by updated_at DESC, so only the *oldest*-updated
    incidents — the ones least likely to still be within any
    correlation window — are ever the ones dropped.
    """
    conn = _get_connection(tenant_id)
    placeholders = ",".join("?" for _ in OPEN_STATUSES)
    cursor = conn.execute(
        f"""
        SELECT thread_id, description, severity, status, source, iocs, affected_assets,
               attack_technique_id, attack_technique_name, created_at, updated_at
        FROM incidents WHERE status IN ({placeholders})
        ORDER BY updated_at DESC
        LIMIT ?
        """,
        (*OPEN_STATUSES, max(1, min(limit, 5000))),
    )
    columns = [d[0] for d in cursor.description]
    rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    for row in rows:
        row["iocs"] = json.loads(row["iocs"]) if row.get("iocs") else []
        row["affected_assets"] = json.loads(row["affected_assets"]) if row.get("affected_assets") else []
    return rows


def get_incident_graph(tenant_id: str = DEFAULT_TENANT, limit: int = 300) -> dict:
    """Builds the node/edge graph behind the dashboard's "Strand Map" —
    every incident in this tenant (any status, not just open, since a
    campaign's full history has real analytical value) plus its IOCs and
    affected assets, as one connected graph: an IOC or asset referenced
    by more than one incident becomes a single shared node, visually
    linking those incidents the same way ingestion/correlation.py's
    exact-match tier already reasons about them internally.

    IOC/asset node identity is exact-string match, deliberately not
    normalized (no case-folding) — matching _first_exact_match's own set
    intersection in ingestion/correlation.py exactly, not a stricter
    notion of "same indicator" the correlation engine itself doesn't use.

    Capped at `limit` most-recently-updated incidents (default 300, same
    ceiling style as list_incidents) so one tenant's full history can't
    make the canvas unusably dense — the response says how many
    incidents exist in total versus how many are actually included, so a
    caller can tell whether anything was left out rather than silently
    assuming a complete picture.
    """
    conn = _get_connection(tenant_id)
    total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    limit = max(1, min(limit, 1000))
    cursor = conn.execute(
        """
        SELECT thread_id, description, severity, status, iocs, affected_assets, assigned_to
        FROM incidents ORDER BY updated_at DESC LIMIT ?
        """,
        (limit,),
    )
    columns = [d[0] for d in cursor.description]
    rows = [dict(zip(columns, row)) for row in cursor.fetchall()]

    nodes: dict = {}
    edges: List[dict] = []
    for row in rows:
        incident_id = f"incident:{row['thread_id']}"
        nodes[incident_id] = {
            "id": incident_id,
            "type": "incident",
            "thread_id": row["thread_id"],
            "label": row["description"][:80],
            "severity": row["severity"],
            "status": row["status"],
            "assigned_to": row["assigned_to"],
        }
        for value in json.loads(row["iocs"]) if row["iocs"] else []:
            ioc_id = f"ioc:{value}"
            nodes.setdefault(ioc_id, {"id": ioc_id, "type": "ioc", "label": value})
            edges.append({"source": incident_id, "target": ioc_id})
        for value in json.loads(row["affected_assets"]) if row["affected_assets"] else []:
            asset_id = f"asset:{value}"
            nodes.setdefault(asset_id, {"id": asset_id, "type": "asset", "label": value})
            edges.append({"source": incident_id, "target": asset_id})

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "incidents_included": len(rows),
        "incidents_total": total,
    }


def reset_for_tests() -> None:
    with _lock:
        for conn in _connections.values():
            conn.close()
        _connections.clear()
