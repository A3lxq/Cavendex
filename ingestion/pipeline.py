"""Turns a normalized alert into one of: a full incident-response pipeline
run ("promoted"), evidence merged into an already-open incident
("correlated"), or a lightweight logged-but-not-escalated entry
("deduped" / "suppressed_low_severity") — the prefilter that keeps
continuous log ingestion from burning an LLM call on every single event a
detection tool emits. A real SOC generates far more raw events than are
worth a full Triage->Investigator->Responder run; this is deliberately a
cheap, rule-based gate in front of the expensive one.

utils/dedup.py catches exact repeats of the same dedup_key. That's not
the same problem as a NIDS port-scan alert and an EDR brute-force alert
against the same host ten minutes apart — different signatures, same
story. ingestion/correlation.py catches that case by matching a new
alert's IOCs/affected assets against already-open incidents (exactly, or
via a fuzzy subnet/domain-family signal); when it matches, the alert is
folded into that incident's evidence instead of spawning a parallel one,
and — because it's clearly relevant to something an analyst is already
looking at — that happens even if the alert alone would've been below
the severity threshold.

A third case neither of those catches: two alerts that are genuinely the
same campaign but share no IOC, no subnet, no domain family at all — the
same attack technique against a completely different, unrelated-looking
host, say. ingestion/semantic_correlation.py handles that with a real
LLM judgment call, which is why it's checked *after* the severity floor
below rather than before like the free tiers: it only ever runs for an
alert that's already about to trigger a full (far more expensive) agent
pipeline run, so a match replaces that cost rather than adding a new one
on top of routine noise that would've been suppressed anyway.

Nothing is ever silently discarded — every outcome, including suppressed
and deduped events, is appended to the tenant's ingestion_log.jsonl so
"continuous monitoring" doesn't quietly mean "continuously ignored."

A per-tenant rate limit (SENTINELOS_INGEST_RATE_LIMIT_PER_MINUTE) is the
very first check in ingest_normalized_alert(), ahead of dedup — the one
piece of this gate that exists purely for abuse resistance rather than
noise reduction. It matters most for syslog_listener.py and
poll_connector.py, which call into this module directly rather than
through api.py's own (HTTP-only) rate limiting.
"""

import json
import os
from datetime import datetime, timezone

from graph import tenant_data_dir
from ingestion.correlation import find_correlated_incident
from ingestion.normalizers import NORMALIZERS
from ingestion.schemas import NormalizedAlert
from ingestion.semantic_correlation import find_semantic_correlation
from state import SEVERITY_RANK
from utils.dedup import is_duplicate
from utils.rate_limit import check_rate_limit
from utils.tenancy import DEFAULT_TENANT, sanitize_tenant_id


def _min_severity_rank() -> int:
    threshold = os.getenv("SENTINELOS_INGEST_MIN_SEVERITY", "medium")
    return SEVERITY_RANK.get(threshold, 1)


def _ingest_rate_limit_per_minute() -> int:
    try:
        return int(os.getenv("SENTINELOS_INGEST_RATE_LIMIT_PER_MINUTE", "60"))
    except ValueError:
        return 60


def _log_raw_event(tenant_id: str, alert: NormalizedAlert, outcome: str, **extra) -> None:
    tenant_dir = tenant_data_dir(tenant_id)
    os.makedirs(tenant_dir, exist_ok=True)
    log_path = os.path.join(tenant_dir, "ingestion_log.jsonl")
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "outcome": outcome,
        "source": alert.source,
        "severity": alert.severity,
        "description": alert.description,
        "dedup_key": alert.dedup_key,
        **extra,
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def ingest_alert(source: str, payload: dict, tenant_id: str = DEFAULT_TENANT) -> dict:
    """Normalize a raw alert from `source` (looked up in NORMALIZERS) and
    hand it to ingest_normalized_alert(). Returns a dict describing what
    happened — always has an "outcome" key:

    - "unknown_source": no normalizer registered for `source`
    - "not_an_alert": the normalizer recognized the format but this
      particular event isn't alert-worthy (e.g. a Suricata flow record)
    - everything else: see ingest_normalized_alert()
    """
    tenant_id = sanitize_tenant_id(tenant_id)

    normalizer = NORMALIZERS.get(source)
    if normalizer is None:
        return {"outcome": "unknown_source", "source": source}

    alert = normalizer(payload)
    if alert is None:
        return {"outcome": "not_an_alert", "source": source}

    return ingest_normalized_alert(alert, tenant_id)


def ingest_normalized_alert(alert: NormalizedAlert, tenant_id: str = DEFAULT_TENANT) -> dict:
    """The dedup -> correlate (exact/fuzzy) -> severity floor -> correlate
    (semantic) -> promote gate, for a caller that has already produced a
    NormalizedAlert itself. ingest_alert() (a raw payload plus a
    NORMALIZERS-registered, fixed-format normalizer) is one such caller;
    ingestion/polling.py's generic SIEM/EDR connector is another — its own
    configurable field-mapping *is* the normalization step, so there's no
    fixed-format function to look up by name the way ingest_alert() does.

    Returns a dict describing what happened — always has an "outcome" key:

    - "rate_limited": this tenant exceeded SENTINELOS_INGEST_RATE_LIMIT_PER_MINUTE
    - "deduped": an identical (tenant, dedup_key) was seen recently
    - "correlated": merged into an already-open incident — exact IOC/asset
      match, fuzzy subnet/domain-family match, or (opt-in) a semantic
      match from an LLM judgment call; includes thread_id/status of the
      incident it joined plus match_type/reason
    - "suppressed_low_severity": below SENTINELOS_INGEST_MIN_SEVERITY
    - "promoted": a full incident was created; includes thread_id/status

    This is THE choke point every ingestion path shares — the API's
    `/ingest/{source}` route, ingest_watch.py, syslog_listener.py, and
    poll_connector.py all funnel through here whether or not they ever
    touch api.py. That matters because api.py's own rate limiting is a
    FastAPI dependency: it protects HTTP callers, but syslog_listener.py
    and poll_connector.py normally call this function directly, in-process
    — and a CEF-formatted syslog line's severity and dedup-key-driving
    fields (signature_id/src/dst) are entirely attacker-controlled. Without
    a rate limit *here*, anyone who could reach the syslog listener could
    send an unbounded stream of distinct-looking high-severity fake alerts
    — each bypassing dedup by construction — and force an unbounded number
    of paid-LLM-provider pipeline runs. This check is what closes that.
    """
    tenant_id = sanitize_tenant_id(tenant_id)

    retry_after = check_rate_limit(f"ingest:{tenant_id}", limit=_ingest_rate_limit_per_minute())
    if retry_after is not None:
        _log_raw_event(tenant_id, alert, "rate_limited")
        return {"outcome": "rate_limited", "retry_after": retry_after}

    if is_duplicate(tenant_id, alert.dedup_key):
        _log_raw_event(tenant_id, alert, "deduped")
        return {"outcome": "deduped", "dedup_key": alert.dedup_key}

    correlation = find_correlated_incident(tenant_id, alert)
    if correlation:
        from workflows.incident_pipeline import merge_correlated_alert

        final_state = merge_correlated_alert(
            thread_id=correlation["thread_id"],
            description=alert.description,
            severity=alert.severity,
            affected_assets=alert.affected_assets,
            iocs=alert.iocs,
            source=f"ingestion:{alert.source}",
            tenant_id=tenant_id,
            match_reason=correlation["reason"],
        )
        _log_raw_event(
            tenant_id, alert, "correlated",
            match_type=correlation["match_type"], reason=correlation["reason"],
        )
        incident = final_state.get("incident")
        return {
            "outcome": "correlated",
            "thread_id": incident.id if incident else correlation["thread_id"],
            "status": incident.status if incident else None,
            "match_type": correlation["match_type"],
            "reason": correlation["reason"],
        }

    if SEVERITY_RANK.get(alert.severity, 1) < _min_severity_rank():
        _log_raw_event(tenant_id, alert, "suppressed_low_severity")
        return {"outcome": "suppressed_low_severity", "severity": alert.severity}

    semantic_match, semantic_usage = find_semantic_correlation(tenant_id, alert)
    if semantic_match:
        from workflows.incident_pipeline import merge_correlated_alert

        final_state = merge_correlated_alert(
            thread_id=semantic_match["thread_id"],
            description=alert.description,
            severity=alert.severity,
            affected_assets=alert.affected_assets,
            iocs=alert.iocs,
            source=f"ingestion:{alert.source}",
            tenant_id=tenant_id,
            match_reason=semantic_match["reason"],
            usage=semantic_usage,
        )
        _log_raw_event(
            tenant_id, alert, "correlated",
            match_type=semantic_match["match_type"], reason=semantic_match["reason"],
            confidence=semantic_match["confidence"],
        )
        incident = final_state.get("incident")
        return {
            "outcome": "correlated",
            "thread_id": incident.id if incident else semantic_match["thread_id"],
            "status": incident.status if incident else None,
            "match_type": semantic_match["match_type"],
            "reason": semantic_match["reason"],
        }

    from workflows.incident_pipeline import run_new_incident

    final_state = run_new_incident(
        description=alert.description,
        severity=alert.severity,
        affected_assets=alert.affected_assets,
        iocs=alert.iocs,
        source=f"ingestion:{alert.source}",
        tenant_id=tenant_id,
        seed_usage=semantic_usage if semantic_usage.get("total_tokens") else None,
    )
    _log_raw_event(tenant_id, alert, "promoted")

    incident = final_state.get("incident")
    return {
        "outcome": "promoted",
        "thread_id": incident.id if incident else None,
        "status": incident.status if incident else None,
    }
