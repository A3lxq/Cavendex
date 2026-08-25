"""Tests the /incidents/events SSE route (utils/incident_events.py's
pub/sub, bridged into an async streaming response).

Deliberately does NOT drive this through FastAPI's TestClient with
client.stream(): Starlette's TestClient runs the whole ASGI request
through an in-process anyio portal and only returns control to the
caller once that coroutine completes -- fine for the existing finite
/incidents/stream route (its generator naturally ends), but this
route's generator runs forever by design (heartbeats + pushed events
until the client disconnects), so TestClient would simply hang forever
trying to fully drain it before `client.stream(...)` even returns.

Real end-to-end delivery -- a live uvicorn process, a real curl client,
a concurrent second process publishing while the connection is open --
was verified manually against a scratch server instance; see the batch
3 verification notes. What's tested here is the generator's own logic
in isolation (still real asyncio, real threads, real queue.Queue), plus
the one HTTP-layer thing that's safe to check without opening the
stream: that auth gating rejects an unauthenticated request before the
generator (and its unbounded body) is ever created.
"""

import asyncio
import itertools
import json

from fastapi.testclient import TestClient

from api import _incident_events_stream, api
from utils import incident_events as incident_events_module
from utils.incident_events import publish, reset_for_tests

client = TestClient(api)
_tenant_counter = itertools.count()


def setup_function():
    reset_for_tests()


def _tenant():
    return f"events-gen-test-{next(_tenant_counter)}"


def test_first_chunk_is_a_connected_event(monkeypatch):
    monkeypatch.setenv("SENTINELOS_EVENTS_HEARTBEAT_SECONDS", "5")

    async def run():
        gen = _incident_events_stream(_tenant())
        try:
            first = await asyncio.wait_for(gen.__anext__(), timeout=5)
            assert first == 'data: {"type": "connected"}\n\n'
        finally:
            await gen.aclose()

    asyncio.run(run())


def test_an_idle_connection_gets_a_heartbeat_comment(monkeypatch):
    monkeypatch.setenv("SENTINELOS_EVENTS_HEARTBEAT_SECONDS", "1")

    async def run():
        gen = _incident_events_stream(_tenant())
        try:
            await asyncio.wait_for(gen.__anext__(), timeout=5)  # connected
            heartbeat = await asyncio.wait_for(gen.__anext__(), timeout=5)
            assert heartbeat == ": heartbeat\n\n"
        finally:
            await gen.aclose()

    asyncio.run(run())


def test_a_real_concurrent_publish_is_delivered_to_the_stream(monkeypatch):
    monkeypatch.setenv("SENTINELOS_EVENTS_HEARTBEAT_SECONDS", "5")
    tenant = _tenant()

    async def run():
        gen = _incident_events_stream(tenant)
        try:
            await asyncio.wait_for(gen.__anext__(), timeout=5)  # connected

            async def publish_soon():
                await asyncio.sleep(0.2)
                publish(tenant, {"type": "incident_updated", "thread_id": "inc-42"})

            publisher = asyncio.create_task(publish_soon())
            chunk = await asyncio.wait_for(gen.__anext__(), timeout=5)
            await publisher
            assert chunk.startswith("data: ")
            assert json.loads(chunk[len("data: "):]) == {"type": "incident_updated", "thread_id": "inc-42"}
        finally:
            await gen.aclose()

    asyncio.run(run())


def test_two_tenants_stay_isolated_on_the_same_stream_generator_pair(monkeypatch):
    monkeypatch.setenv("SENTINELOS_EVENTS_HEARTBEAT_SECONDS", "1")
    tenant_a, tenant_b = _tenant(), _tenant()

    async def run():
        gen_a = _incident_events_stream(tenant_a)
        gen_b = _incident_events_stream(tenant_b)
        try:
            await asyncio.wait_for(gen_a.__anext__(), timeout=5)  # connected
            await asyncio.wait_for(gen_b.__anext__(), timeout=5)  # connected

            publish(tenant_a, {"type": "incident_updated", "thread_id": "inc-a"})
            chunk_a = await asyncio.wait_for(gen_a.__anext__(), timeout=5)
            assert json.loads(chunk_a[len("data: "):]) == {"type": "incident_updated", "thread_id": "inc-a"}

            # tenant_b's stream should see only its own heartbeat, never tenant_a's event.
            chunk_b = await asyncio.wait_for(gen_b.__anext__(), timeout=5)
            assert chunk_b == ": heartbeat\n\n"
        finally:
            await gen_a.aclose()
            await gen_b.aclose()

    asyncio.run(run())


def test_closing_the_stream_unsubscribes_it():
    tenant = _tenant()

    async def run():
        gen = _incident_events_stream(tenant)
        await gen.__anext__()  # connected -- subscription now exists
        assert tenant in incident_events_module._subscribers
        await gen.aclose()
        assert tenant not in incident_events_module._subscribers

    asyncio.run(run())


def test_events_route_requires_auth_when_configured(monkeypatch):
    monkeypatch.setenv("SENTINELOS_API_KEY", "secret-key-123")
    # A plain (non-streaming) GET is safe here specifically because auth
    # rejection happens in the router dependency, before the route
    # function -- and its unbounded generator -- ever runs; the 401
    # response itself is a normal, immediately-complete JSON body.
    response = client.get(f"/tenants/{_tenant()}/incidents/events")
    assert response.status_code == 401
