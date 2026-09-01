"""LLM provider selection.

Prefers Groq (free-tier friendly), then OpenAI, then Anthropic, then
Google AI Studio (Gemini), then a locally-hosted model via Ollama —
whichever is configured first, in that order. Keeping this in one
place makes it easy to swap providers later without touching agent
code.
"""

import logging
import os

logger = logging.getLogger(__name__)


def _build_groq(temperature: float, api_key: str | None = None):
    key = api_key or os.getenv("GROQ_API_KEY")
    if not key:
        return None
    from langchain_groq import ChatGroq

    return ChatGroq(model="llama-3.3-70b-versatile", temperature=temperature, groq_api_key=key)


def _build_openai(temperature: float, api_key: str | None = None):
    key = api_key or os.getenv("OPENAI_API_KEY")
    if not key:
        return None
    from langchain_openai import ChatOpenAI

    return ChatOpenAI(model="gpt-4o-mini", temperature=temperature, openai_api_key=key)


def _build_anthropic(temperature: float, api_key: str | None = None):
    key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return None
    from langchain_anthropic import ChatAnthropic

    return ChatAnthropic(model="claude-sonnet-4-5", temperature=temperature, anthropic_api_key=key)


def _build_google(temperature: float, api_key: str | None = None):
    key = api_key or os.getenv("GOOGLE_API_KEY")
    if not key:
        return None
    from langchain_google_genai import ChatGoogleGenerativeAI

    return ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=temperature, google_api_key=key)


def _build_ollama(temperature: float, api_key: str | None = None):
    ollama_model = os.getenv("OLLAMA_MODEL")
    if not ollama_model:
        return None
    # Local models need no API key — opt in by naming a model you've
    # pulled with `ollama pull <model>` (e.g. llama3.1, qwen2.5).
    from langchain_ollama import ChatOllama

    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    return ChatOllama(model=ollama_model, base_url=base_url, temperature=temperature)


# Default fallback order: first one whose own env var is actually set wins.
_PROVIDER_ORDER = [_build_groq, _build_openai, _build_anthropic, _build_google, _build_ollama]

# Fast-path escape hatch: CAVENDEX_FASTPATH_PROVIDER names one of these
# explicitly, independent of the default order above.
_FASTPATH_BUILDERS = {
    "groq": _build_groq,
    "openai": _build_openai,
    "anthropic": _build_anthropic,
    "google": _build_google,
}


def _build_fastpath_llm(temperature: float):
    """Best-effort fast-path provider build. Returns None (never raises) if
    fast-path isn't configured or CAVENDEX_FASTPATH_API_KEY is missing —
    either way the caller falls through to the normal order unchanged.

    Deliberately uses its own CAVENDEX_FASTPATH_API_KEY, never the named
    provider's own GROQ_API_KEY/OPENAI_API_KEY/etc. — those are read by the
    normal default order above, so if fast-path reused them here, merely
    setting one (required to name it as the fast-path provider at all)
    would silently make that provider the default for *every* incident,
    every severity, defeating the entire point of choosing a slower/local
    default (cost, privacy, air-gap) and reserving a cloud provider only
    for genuinely time-critical incidents. A separate credential keeps the
    two concerns — "what's my everyday default" and "what do I fall back to
    when it's critical" — genuinely independent.
    """
    provider = os.getenv("CAVENDEX_FASTPATH_PROVIDER", "").strip().lower()
    if not provider:
        return None
    builder = _FASTPATH_BUILDERS.get(provider)
    if builder is None:
        logger.warning(
            "CAVENDEX_FASTPATH_PROVIDER=%r is not a recognized provider "
            "(groq/openai/anthropic/google) — ignoring fast-path for this call.",
            provider,
        )
        return None
    fastpath_key = os.getenv("CAVENDEX_FASTPATH_API_KEY")
    if not fastpath_key:
        logger.warning(
            "CAVENDEX_FASTPATH_PROVIDER=%s but CAVENDEX_FASTPATH_API_KEY is not "
            "set — falling back to the normal provider order for this call.",
            provider,
        )
        return None
    return builder(temperature, api_key=fastpath_key)


def get_llm(temperature: float = 0, prefer_fast: bool = False):
    """Build the LLM for one call.

    prefer_fast: an explicit, opt-in escape hatch for a deployment that
    deliberately defaults to a slower/free/local provider (cost, privacy,
    air-gap — e.g. only OLLAMA_MODEL is set) but doesn't want a high/critical
    incident stuck behind it. Only takes effect when CAVENDEX_FASTPATH_ENABLED
    is also set; even then, it only changes anything if CAVENDEX_FASTPATH_PROVIDER
    names a provider AND CAVENDEX_FASTPATH_API_KEY is set — otherwise this
    falls straight through to the normal Groq->OpenAI->Anthropic->Google->Ollama
    order below, unchanged. Fast-path uses its own dedicated
    CAVENDEX_FASTPATH_API_KEY, deliberately never the named provider's own
    GROQ_API_KEY/OPENAI_API_KEY/etc. — reusing those would mean simply
    naming a fast-path provider silently makes it the default for *every*
    incident regardless of severity (since the normal order already tries
    every configured cloud key before Ollama), defeating the reason a
    deployment chose a slower/local default in the first place.
    """
    if prefer_fast and os.getenv("CAVENDEX_FASTPATH_ENABLED", "false").lower() == "true":
        fast_llm = _build_fastpath_llm(temperature)
        if fast_llm is not None:
            return fast_llm

    for builder in _PROVIDER_ORDER:
        llm = builder(temperature)
        if llm is not None:
            return llm

    raise RuntimeError(
        "No LLM provider configured. Set GROQ_API_KEY (preferred, free "
        "tier), OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, or "
        "OLLAMA_MODEL (for a local model, no key required) in your .env "
        "file. Copy .env.example to .env and fill in one before running "
        "Cavendex."
    )


_EMPTY_USAGE = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}


class StructuredOutputError(Exception):
    """Raised by invoke_structured() when every attempt failed. Carries the
    summed token usage across all attempts (in `.usage`) so callers can
    still record what was actually spent even though nothing usable came
    back — a totally-failed call still cost real tokens on a paid provider.
    """

    def __init__(self, original_exc: Exception, usage: dict):
        super().__init__(str(original_exc))
        self.usage = usage
        self.__cause__ = original_exc


def _extract_usage(message) -> dict:
    usage = getattr(message, "usage_metadata", None) or {}
    return {
        "input_tokens": usage.get("input_tokens", 0) or 0,
        "output_tokens": usage.get("output_tokens", 0) or 0,
        "total_tokens": usage.get("total_tokens", 0) or 0,
    }


def invoke_structured(chain, payload: dict, retries: int = 1):
    """Invoke a structured-output chain built with `include_raw=True`,
    retrying on transient failures. Returns `(parsed_result, usage_dict)`.

    Smaller/local models occasionally emit malformed JSON for a structured
    output schema on the first try (observed live with a complex nested
    schema via Ollama) — one retry clears most of these without masking a
    genuinely broken provider/schema.

    `chain` must end in `llm.with_structured_output(Schema, include_raw=True)`
    — with `include_raw=True`, a parsing failure returns `parsed=None` and
    `parsing_error=<exc>` instead of raising, so this function re-raises
    that error itself to preserve the raise-on-total-failure contract
    callers rely on. The returned usage_dict sums *every* attempt, not just
    the successful one — a retry that got a malformed response still
    consumed real tokens (and, on a paid provider, real cost), so a failed
    attempt disappearing from the total would undercount actual usage.
    """
    last_exc = None
    total_usage = dict(_EMPTY_USAGE)
    for _ in range(retries + 1):
        try:
            raw_result = chain.invoke(payload)
        except Exception as exc:
            last_exc = exc
            continue

        usage = _extract_usage(raw_result.get("raw"))
        for key in total_usage:
            total_usage[key] += usage.get(key, 0)

        parsed = raw_result.get("parsed")
        if parsed is None:
            last_exc = raw_result.get("parsing_error") or RuntimeError(
                "Structured output parsing failed with no result"
            )
            continue

        return parsed, total_usage
    raise StructuredOutputError(last_exc, total_usage)


def safe_error_message(agent_name: str, exc: Exception) -> str:
    """A provider-call failure message safe to put in state["audit_log"]/
    state["messages"] — durable, widely-visible records (the vault
    report, the dashboard, API responses), unlike server-side logs.

    Never embeds the raw exception text. Provider SDK error messages
    routinely echo back request details, and several (a real, documented
    OpenAI behavior, for one) include a truncated form of the API key
    itself in "invalid API key" errors — e.g. "Incorrect API key
    provided: sk-abc1...xyz9". Interpolating that straight into an
    audit-trail entry would leak a credential into exactly the kind of
    record this project already treats as durable and potentially
    shared (Obsidian vault git history, a dashboard viewer, an API
    response body).

    The full exception is still logged via the standard `logging` module
    here — an operator watching server logs (already a trusted vantage
    point, the same tier as reading `.env`) can fully diagnose the real
    problem; only the durable, more-widely-visible audit trail is kept
    generic.
    """
    logger.error("%s failed to reach the LLM provider", agent_name, exc_info=exc)
    return f"{agent_name} failed to reach the LLM provider ({type(exc).__name__} — see server logs for details)."


def usage_from_exception(exc: Exception) -> dict:
    """Best-effort usage extraction from a caught exception — returns the
    StructuredOutputError's summed usage if present, otherwise all zeros
    (e.g. get_llm() raised before any call was ever made, so nothing was
    spent). Safe to pass straight into accumulate_usage() either way.
    """
    return getattr(exc, "usage", None) or dict(_EMPTY_USAGE)


def accumulate_usage(state: dict, agent_name: str, usage: dict) -> None:
    """Add one agent call's token usage into state["token_usage"], both as
    a running total and broken out per agent — mutates state in place.
    """
    totals = dict(state.get("token_usage") or {**_EMPTY_USAGE, "by_agent": {}})
    for key in ("input_tokens", "output_tokens", "total_tokens"):
        totals[key] = totals.get(key, 0) + usage.get(key, 0)

    by_agent = dict(totals.get("by_agent") or {})
    prev = by_agent.get(agent_name, dict(_EMPTY_USAGE))
    by_agent[agent_name] = {
        key: prev.get(key, 0) + usage.get(key, 0) for key in ("input_tokens", "output_tokens", "total_tokens")
    }
    totals["by_agent"] = by_agent

    state["token_usage"] = totals
