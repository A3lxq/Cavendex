import pytest

from utils.llm import (
    StructuredOutputError,
    accumulate_usage,
    invoke_structured,
    usage_from_exception,
)


class _FakeMessage:
    def __init__(self, usage_metadata):
        self.usage_metadata = usage_metadata


class _FakeChain:
    """Mimics `prompt | llm.with_structured_output(Schema, include_raw=True)`
    without any real LLM call — returns pre-scripted results in sequence."""

    def __init__(self, results):
        self._results = list(results)

    def invoke(self, payload):
        return self._results.pop(0)


def _raw_result(parsed, usage, parsing_error=None):
    return {
        "raw": _FakeMessage(usage),
        "parsed": parsed,
        "parsing_error": parsing_error,
    }


def test_invoke_structured_returns_usage_on_success():
    chain = _FakeChain(
        [_raw_result(parsed="ok", usage={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15})]
    )
    result, usage = invoke_structured(chain, {})
    assert result == "ok"
    assert usage == {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}


def test_invoke_structured_sums_usage_across_failed_retries_before_succeeding():
    chain = _FakeChain(
        [
            _raw_result(parsed=None, usage={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}, parsing_error=ValueError("bad json")),
            _raw_result(parsed="ok", usage={"input_tokens": 8, "output_tokens": 4, "total_tokens": 12}),
        ]
    )
    result, usage = invoke_structured(chain, {}, retries=1)
    assert result == "ok"
    assert usage == {"input_tokens": 18, "output_tokens": 9, "total_tokens": 27}


def test_invoke_structured_raises_with_summed_usage_when_every_attempt_fails():
    chain = _FakeChain(
        [
            _raw_result(parsed=None, usage={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}, parsing_error=ValueError("bad json 1")),
            _raw_result(parsed=None, usage={"input_tokens": 7, "output_tokens": 3, "total_tokens": 10}, parsing_error=ValueError("bad json 2")),
        ]
    )
    with pytest.raises(StructuredOutputError) as exc_info:
        invoke_structured(chain, {}, retries=1)
    assert exc_info.value.usage == {"input_tokens": 17, "output_tokens": 8, "total_tokens": 25}


def test_usage_from_exception_extracts_from_structured_output_error():
    exc = StructuredOutputError(ValueError("boom"), {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3})
    assert usage_from_exception(exc) == {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3}


def test_usage_from_exception_returns_zeros_for_plain_exception():
    assert usage_from_exception(RuntimeError("no provider configured")) == {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
    }


def test_accumulate_usage_sums_totals_and_per_agent():
    state = {}
    accumulate_usage(state, "Triage Agent", {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15})
    accumulate_usage(state, "Investigator Agent", {"input_tokens": 20, "output_tokens": 8, "total_tokens": 28})
    accumulate_usage(state, "Triage Agent", {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})

    usage = state["token_usage"]
    assert usage["total_tokens"] == 45
    assert usage["by_agent"]["Triage Agent"]["total_tokens"] == 17
    assert usage["by_agent"]["Investigator Agent"]["total_tokens"] == 28
