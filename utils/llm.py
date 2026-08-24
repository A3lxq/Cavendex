"""LLM provider selection.

Prefers Groq (free-tier friendly), then OpenAI, then Anthropic, then
Google AI Studio (Gemini), then a locally-hosted model via Ollama —
whichever is configured first, in that order. Keeping this in one
place makes it easy to swap providers later without touching agent
code.
"""

import os


def get_llm(temperature: float = 0):
    groq_key = os.getenv("GROQ_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    google_key = os.getenv("GOOGLE_API_KEY")
    ollama_model = os.getenv("OLLAMA_MODEL")

    if groq_key:
        from langchain_groq import ChatGroq

        return ChatGroq(model="llama-3.3-70b-versatile", temperature=temperature)

    if openai_key:
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(model="gpt-4o-mini", temperature=temperature)

    if anthropic_key:
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(model="claude-sonnet-4-5", temperature=temperature)

    if google_key:
        from langchain_google_genai import ChatGoogleGenerativeAI

        return ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=temperature)

    if ollama_model:
        # Local models need no API key — opt in by naming a model you've
        # pulled with `ollama pull <model>` (e.g. llama3.1, qwen2.5).
        from langchain_ollama import ChatOllama

        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        return ChatOllama(model=ollama_model, base_url=base_url, temperature=temperature)

    raise RuntimeError(
        "No LLM provider configured. Set GROQ_API_KEY (preferred, free "
        "tier), OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, or "
        "OLLAMA_MODEL (for a local model, no key required) in your .env "
        "file. Copy .env.example to .env and fill in one before running "
        "SentinelOS."
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
