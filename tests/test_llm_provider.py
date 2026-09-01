import pytest

from utils.llm import get_llm

_ALL_KEYS = ["GROQ_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "OLLAMA_MODEL"]
_FASTPATH_KEYS = ["CAVENDEX_FASTPATH_ENABLED", "CAVENDEX_FASTPATH_PROVIDER", "CAVENDEX_FASTPATH_API_KEY"]


def _clear_all(monkeypatch):
    for key in _ALL_KEYS + _FASTPATH_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_get_llm_raises_without_any_provider(monkeypatch):
    _clear_all(monkeypatch)
    with pytest.raises(RuntimeError):
        get_llm()


def test_get_llm_prefers_groq_over_everything(monkeypatch):
    _clear_all(monkeypatch)
    monkeypatch.setenv("GROQ_API_KEY", "fake")
    monkeypatch.setenv("OPENAI_API_KEY", "fake")
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.1")
    assert type(get_llm()).__name__ == "ChatGroq"


def test_get_llm_falls_back_to_openai(monkeypatch):
    _clear_all(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "fake")
    assert type(get_llm()).__name__ == "ChatOpenAI"


def test_get_llm_falls_back_to_anthropic(monkeypatch):
    _clear_all(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake")
    assert type(get_llm()).__name__ == "ChatAnthropic"


def test_get_llm_falls_back_to_google(monkeypatch):
    _clear_all(monkeypatch)
    monkeypatch.setenv("GOOGLE_API_KEY", "fake")
    assert type(get_llm()).__name__ == "ChatGoogleGenerativeAI"


def test_get_llm_falls_back_to_ollama(monkeypatch):
    _clear_all(monkeypatch)
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.1")
    assert type(get_llm()).__name__ == "ChatOllama"


def test_prefer_fast_ignored_when_fastpath_disabled(monkeypatch):
    # Ollama is the deployment's only default; fast-path isn't enabled at
    # all, so prefer_fast=True must have zero effect even with a fast-path
    # provider+key fully configured.
    _clear_all(monkeypatch)
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.1")
    monkeypatch.setenv("CAVENDEX_FASTPATH_PROVIDER", "groq")
    monkeypatch.setenv("CAVENDEX_FASTPATH_API_KEY", "fake-fastpath-key")
    assert type(get_llm(prefer_fast=True)).__name__ == "ChatOllama"


def test_prefer_fast_ignored_when_prefer_fast_false(monkeypatch):
    _clear_all(monkeypatch)
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.1")
    monkeypatch.setenv("CAVENDEX_FASTPATH_ENABLED", "true")
    monkeypatch.setenv("CAVENDEX_FASTPATH_PROVIDER", "openai")
    monkeypatch.setenv("CAVENDEX_FASTPATH_API_KEY", "fake-fastpath-key")
    assert type(get_llm(prefer_fast=False)).__name__ == "ChatOllama"


def test_fastpath_escape_hatch_overrides_ollama_default_without_touching_normal_key(monkeypatch):
    # The real scenario this feature exists for: Ollama is the deployment's
    # only *default* (privacy/cost), and a *separate* fast-path credential
    # (never the provider's own GROQ_API_KEY/etc.) is held in reserve for
    # high/critical incidents only. Naming "groq" as the fast-path provider
    # must NOT make Groq the default for every severity -- GROQ_API_KEY
    # itself is never set here at all.
    _clear_all(monkeypatch)
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.1")
    monkeypatch.setenv("CAVENDEX_FASTPATH_ENABLED", "true")
    monkeypatch.setenv("CAVENDEX_FASTPATH_PROVIDER", "groq")
    monkeypatch.setenv("CAVENDEX_FASTPATH_API_KEY", "fake-fastpath-key")

    assert type(get_llm(prefer_fast=False)).__name__ == "ChatOllama"  # unaffected default path
    assert type(get_llm(prefer_fast=True)).__name__ == "ChatGroq"  # fast-path escape hatch


def test_fastpath_falls_through_when_api_key_missing(monkeypatch):
    _clear_all(monkeypatch)
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.1")
    monkeypatch.setenv("CAVENDEX_FASTPATH_ENABLED", "true")
    monkeypatch.setenv("CAVENDEX_FASTPATH_PROVIDER", "groq")  # named but CAVENDEX_FASTPATH_API_KEY unset
    assert type(get_llm(prefer_fast=True)).__name__ == "ChatOllama"


def test_fastpath_falls_through_on_unrecognized_provider_name(monkeypatch):
    _clear_all(monkeypatch)
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.1")
    monkeypatch.setenv("CAVENDEX_FASTPATH_ENABLED", "true")
    monkeypatch.setenv("CAVENDEX_FASTPATH_PROVIDER", "not-a-real-provider")
    monkeypatch.setenv("CAVENDEX_FASTPATH_API_KEY", "fake-fastpath-key")
    assert type(get_llm(prefer_fast=True)).__name__ == "ChatOllama"


def test_fastpath_key_never_leaks_into_normal_default_selection(monkeypatch):
    # Setting CAVENDEX_FASTPATH_API_KEY must never make any *normal* call
    # (prefer_fast=False, or fast-path disabled) pick a cloud provider --
    # GROQ_API_KEY/etc. are the only thing the default order ever reads.
    _clear_all(monkeypatch)
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.1")
    monkeypatch.setenv("CAVENDEX_FASTPATH_PROVIDER", "groq")
    monkeypatch.setenv("CAVENDEX_FASTPATH_API_KEY", "fake-fastpath-key")
    assert type(get_llm()).__name__ == "ChatOllama"
    monkeypatch.setenv("CAVENDEX_FASTPATH_ENABLED", "true")
    assert type(get_llm(prefer_fast=False)).__name__ == "ChatOllama"
