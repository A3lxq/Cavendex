"""The third, LLM-assisted correlation tier: genuine semantic/behavioral
campaign matching, for the cases ingestion/correlation.py's exact and
fuzzy tiers structurally cannot catch — two alerts connected by a shared
MITRE ATT&CK technique with no shared IOC at all, or a renamed host whose
new name has no lexical relationship to its old one.

This tier is fundamentally different from the other two, and that
difference drives every design decision below:

- **It costs a real LLM call**, so it is opt-in
  (CAVENDEX_CORRELATION_SEMANTIC_ENABLED, default off) and only ever
  runs for an alert that already passed the severity floor — i.e. one
  that's about to trigger a full, far more expensive agent pipeline run
  anyway. Checked here, a match *replaces* that expensive run with a
  cheap merge instead of adding a new cost on top of it. Unlike the free
  exact/fuzzy tiers, it deliberately does NOT run before the severity
  filter and cannot rescue an alert that would otherwise be suppressed —
  that would mean spending tokens on routine noise, not campaign
  evidence.
- **It's a judgment call, not a deterministic match**, so its result is
  never trusted blindly: the model must name which candidate it means
  (validated against the real candidate list — a hallucinated or
  out-of-list thread_id is rejected, the same "verify before trust"
  principle enrichment/mitre_attack.py already applies to technique
  citations), and a confidence below CAVENDEX_CORRELATION_SEMANTIC_MIN_CONFIDENCE
  is treated as no match at all.
- **It never fabricates evidence for the model to reason over.** A
  candidate's MITRE ATT&CK technique is only ever shown if
  Investigator/Threat Hunter's citation was itself verified (see
  utils.incident_index.upsert_incident_summary) — an unverified guess
  doesn't get to become "known fact" for a second judgment call to build
  on.
- **It never raises.** Same contract as ingestion/correlation.py and
  enrichment/providers.py: no configured provider, a malformed response,
  or any other failure all just mean "no semantic match," and the alert
  falls through to normal promotion exactly as if this tier didn't exist.
"""

import os
from typing import List, Literal, Optional, Tuple

from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field

from ingestion.correlation import recent_open_candidates
from ingestion.schemas import NormalizedAlert
from utils.llm import get_llm, invoke_structured, usage_from_exception

_NO_USAGE = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


class CampaignMatch(BaseModel):
    correlates: bool = Field(
        description=(
            "True only if this alert plausibly belongs to the same attacker "
            "campaign/incident as one specific candidate below — a shared "
            "technique/behavior against a different, unrelated-looking "
            "indicator or host, not just a vague thematic resemblance."
        )
    )
    thread_id: Optional[str] = Field(
        default=None,
        description=(
            "The exact thread_id of the one matching candidate, copied "
            "verbatim from the candidate list. Null if correlates is false "
            "or you are not looking at one specific candidate."
        ),
    )
    confidence: Literal["low", "medium", "high"] = "low"
    reason: str = Field(
        max_length=300,
        description="One or two sentences citing the specific shared evidence that justifies the judgment.",
    )


_PROMPT = ChatPromptTemplate.from_template(
    """You are a SOC correlation analyst. A new alert has just come in. Decide \
whether it plausibly belongs to the SAME ongoing incident/campaign as ONE of \
the open incidents listed below — for example, the same attack technique \
used against a different, unrelated-looking host, or a renamed asset — \
rather than a coincidental thematic resemblance. If you are not reasonably \
confident, say so: a wrong merge pollutes a real incident's evidence trail, \
which is worse than missing a connection.

New alert:
{alert_summary}

Open incidents (their thread_id is required if you say correlates=true; \
never invent a thread_id that isn't listed here):
{candidates_summary}
"""
)


def _semantic_enabled() -> bool:
    return os.getenv("CAVENDEX_CORRELATION_SEMANTIC_ENABLED", "false").strip().lower() in (
        "1",
        "true",
        "yes",
    )


def _max_candidates() -> int:
    try:
        n = int(os.getenv("CAVENDEX_CORRELATION_SEMANTIC_MAX_CANDIDATES", "5"))
    except ValueError:
        return 5
    return max(1, n)


def _min_confidence_rank() -> int:
    threshold = os.getenv("CAVENDEX_CORRELATION_SEMANTIC_MIN_CONFIDENCE", "medium").strip().lower()
    return _CONFIDENCE_RANK.get(threshold, 1)


def _format_alert(alert: NormalizedAlert) -> str:
    return (
        f"description: {alert.description}\n"
        f"severity: {alert.severity}\n"
        f"source: {alert.source}\n"
        f"iocs: {alert.iocs or 'none'}\n"
        f"affected_assets: {alert.affected_assets or 'none'}"
    )


def _format_candidate(candidate: dict) -> str:
    technique_id = candidate.get("attack_technique_id")
    technique_name = candidate.get("attack_technique_name")
    technique = f"{technique_id} ({technique_name})" if technique_id else "none cited/verified"
    return (
        f"- thread_id: {candidate['thread_id']}\n"
        f"  description: {candidate.get('description', '')}\n"
        f"  severity: {candidate.get('severity', 'unknown')}\n"
        f"  iocs: {candidate.get('iocs') or 'none'}\n"
        f"  affected_assets: {candidate.get('affected_assets') or 'none'}\n"
        f"  verified technique: {technique}"
    )


def _invoke_judge(alert_summary: str, candidates_summary: str) -> Tuple[CampaignMatch, dict]:
    """The actual LLM call, isolated behind one function so tests can
    monkeypatch a single seam (like the rest of this codebase does for
    workflow boundaries) instead of reconstructing LangChain's Runnable
    composition to fake a chain response.
    """
    llm = get_llm(temperature=0)
    chain = _PROMPT | llm.with_structured_output(CampaignMatch, include_raw=True)
    return invoke_structured(chain, {"alert_summary": alert_summary, "candidates_summary": candidates_summary})


def find_semantic_correlation(
    tenant_id: str, alert: NormalizedAlert, candidates: Optional[List[dict]] = None
) -> Tuple[Optional[dict], dict]:
    """Look for a semantic/behavioral match for `alert` among this tenant's
    open incidents. Returns `(match_or_none, usage)`:

    - `match_or_none` is `{"thread_id", "match_type": "semantic", "reason",
      "confidence"}` on a match, else `None`.
    - `usage` is the real token usage of the LLM call actually made (zeros
      if the tier is disabled, there were no candidates, or no call was
      ever attempted) — the caller is responsible for folding this into
      whichever incident (the one it merges into, or the new one it was
      checked on behalf of) actually gets created, so this check's cost
      is never silently dropped from token-usage accounting.
    """
    if not _semantic_enabled():
        return None, dict(_NO_USAGE)

    pool = recent_open_candidates(tenant_id) if candidates is None else candidates
    pool = pool[: _max_candidates()]
    if not pool:
        return None, dict(_NO_USAGE)

    valid_ids = {c["thread_id"] for c in pool}

    try:
        parsed, usage = _invoke_judge(
            _format_alert(alert), "\n".join(_format_candidate(c) for c in pool)
        )
    except Exception as exc:
        # usage_from_exception recovers the real (non-zero) cost of a
        # StructuredOutputError's failed attempts; a provider that never
        # got called at all (e.g. get_llm() raised) correctly reports zero.
        return None, usage_from_exception(exc)

    if not parsed.correlates or not parsed.thread_id or parsed.thread_id not in valid_ids:
        return None, usage

    if _CONFIDENCE_RANK.get(parsed.confidence, 0) < _min_confidence_rank():
        return None, usage

    return (
        {
            "thread_id": parsed.thread_id,
            "match_type": "semantic",
            "reason": parsed.reason,
            "confidence": parsed.confidence,
        },
        usage,
    )
