import pytest

from utils.llm import get_llm

_ALL_KEYS = ["GROQ_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "OLLAMA_MODEL"]


def _clear_all(monkeypatch):
    for key in _ALL_KEYS:
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
