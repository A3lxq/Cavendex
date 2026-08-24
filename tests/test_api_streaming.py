"""SSE streaming endpoint test. No LLM provider needs to be configured —
Triage still runs (and fails cleanly, as tested elsewhere), which is
enough to exercise the "started" -> "agent_step" -> "complete" event
sequence end to end."""

import json

from fastapi.testclient import TestClient

from api import api

client = TestClient(api)


def test_incident_stream_emits_started_step_and_complete_events(monkeypatch):
    for key in ["GROQ_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "OLLAMA_MODEL"]:
        monkeypatch.delenv(key, raising=False)

    with client.stream(
        "POST",
        "/incidents/stream",
        json={"description": "test incident for streaming", "severity": "low"},
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")

        events = []
        for line in response.iter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[len("data: "):]))

    event_types = [e["event"] for e in events]
    assert event_types[0] == "started"
    assert "agent_step" in event_types
    assert event_types[-1] == "complete"

    triage_step = next(e for e in events if e["event"] == "agent_step")
    assert triage_step["agent"] == "Triage Agent"
    assert "failed to reach the LLM provider" in triage_step["content"]
