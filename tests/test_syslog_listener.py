"""Tests syslog_listener.py against real sockets — a real UDP datagram
and a real TCP connection are sent to a real listener bound to
127.0.0.1 on an ephemeral port, exercising the actual network I/O path
rather than mocking it. ingestion.pipeline.ingest_alert itself is
mocked (its promote/dedup/correlate decision logic is already covered by
test_ingestion_pipeline.py) — these tests are about the listener's own
job: accepting a connection/datagram, enforcing --allow-from, framing
messages correctly, and building the right payload shape."""

import socket
import threading
import time

import pytest

import syslog_listener as sl


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_server(server_cls, handler_cls, port, **attrs):
    server = server_cls(("127.0.0.1", port), handler_cls)
    server.source = attrs.get("source", "syslog_cef")
    server.tenant_id = attrs.get("tenant_id", "t1")
    server.api_url = attrs.get("api_url")
    server.api_key = attrs.get("api_key")
    server.allowed_networks = attrs.get("allowed_networks")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.fixture
def fake_ingest_alert(monkeypatch):
    calls = []

    def _fake(source, payload, tenant_id=None):
        calls.append({"source": source, "payload": payload, "tenant_id": tenant_id})
        return {"outcome": "promoted", "thread_id": "fake-id", "status": "open"}

    monkeypatch.setattr("ingestion.pipeline.ingest_alert", _fake)
    return calls


def test_udp_listener_ingests_a_real_packet(fake_ingest_alert):
    port = _free_port()
    server = _make_server(sl._ThreadingUDPServer, sl._UDPHandler, port, tenant_id="udp-test")
    try:
        msg = b"CEF:0|Acme|Firewall|1.0|100|Port Scan|7|src=198.51.100.9 dst=10.0.0.5"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(msg, ("127.0.0.1", port))
        s.close()
        time.sleep(0.3)

        assert len(fake_ingest_alert) == 1
        call = fake_ingest_alert[0]
        assert call["source"] == "syslog_cef"
        assert call["tenant_id"] == "udp-test"
        assert call["payload"] == {"raw": msg.decode()}
    finally:
        server.shutdown()
        server.server_close()


def test_tcp_listener_ingests_a_real_connection(fake_ingest_alert):
    port = _free_port()
    server = _make_server(sl._ThreadingTCPServer, sl._TCPHandler, port, tenant_id="tcp-test")
    try:
        msg = b"CEF:0|Acme|Firewall|1.0|101|Brute Force|8|src=198.51.100.10 dst=10.0.0.6\n"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", port))
        s.sendall(msg)
        s.close()
        time.sleep(0.3)

        assert len(fake_ingest_alert) == 1
        assert fake_ingest_alert[0]["payload"] == {"raw": msg.decode().strip()}
    finally:
        server.shutdown()
        server.server_close()


def test_tcp_listener_handles_multiple_lines_in_one_connection(fake_ingest_alert):
    port = _free_port()
    server = _make_server(sl._ThreadingTCPServer, sl._TCPHandler, port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", port))
        s.sendall(b"CEF:0|A|B|1.0|1|First|5|src=1.1.1.1 dst=2.2.2.2\nCEF:0|A|B|1.0|2|Second|5|src=3.3.3.3 dst=4.4.4.4\n")
        s.close()
        time.sleep(0.3)

        assert len(fake_ingest_alert) == 2
    finally:
        server.shutdown()
        server.server_close()


def test_generic_source_uses_description_payload_shape(fake_ingest_alert):
    port = _free_port()
    server = _make_server(sl._ThreadingUDPServer, sl._UDPHandler, port, source="generic")
    try:
        msg = b"plain text syslog message, not CEF"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(msg, ("127.0.0.1", port))
        s.close()
        time.sleep(0.3)

        assert fake_ingest_alert[0]["source"] == "generic"
        assert fake_ingest_alert[0]["payload"] == {"description": msg.decode(), "source": "syslog"}
    finally:
        server.shutdown()
        server.server_close()


def test_allow_from_rejects_a_real_connection_outside_the_range(fake_ingest_alert):
    port = _free_port()
    server = _make_server(
        sl._ThreadingUDPServer, sl._UDPHandler, port,
        allowed_networks=sl._parse_allowed_networks(["10.0.0.0/8"]),
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"CEF:0|A|B|1.0|1|X|5|src=1.1.1.1 dst=2.2.2.2", ("127.0.0.1", port))
        s.close()
        time.sleep(0.3)

        assert fake_ingest_alert == []  # 127.0.0.1 is not in 10.0.0.0/8 -> rejected
    finally:
        server.shutdown()
        server.server_close()


def test_allow_from_accepts_a_real_connection_inside_the_range(fake_ingest_alert):
    port = _free_port()
    server = _make_server(
        sl._ThreadingUDPServer, sl._UDPHandler, port,
        allowed_networks=sl._parse_allowed_networks(["127.0.0.0/8"]),
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"CEF:0|A|B|1.0|1|X|5|src=1.1.1.1 dst=2.2.2.2", ("127.0.0.1", port))
        s.close()
        time.sleep(0.3)

        assert len(fake_ingest_alert) == 1
    finally:
        server.shutdown()
        server.server_close()


# ---------- Pure logic, no sockets needed ----------


def test_is_allowed_with_no_restriction_accepts_anything():
    assert sl._is_allowed("203.0.113.9", None) is True


def test_is_allowed_rejects_unparseable_address_when_restricted():
    networks = sl._parse_allowed_networks(["10.0.0.0/8"])
    assert sl._is_allowed("not-an-ip", networks) is False


def test_payload_for_cef_source():
    assert sl._payload_for("syslog_cef", "some line") == {"raw": "some line"}


def test_payload_for_generic_source():
    assert sl._payload_for("generic", "some line") == {"description": "some line", "source": "syslog"}


class _FakeServer:
    source = "syslog_cef"
    tenant_id = "t1"
    api_url = None
    api_key = None


def test_ingest_line_truncates_oversized_messages(monkeypatch):
    seen = {}

    def _fake(source, payload, tenant_id=None):
        seen["payload"] = payload
        return {"outcome": "promoted"}

    monkeypatch.setattr("ingestion.pipeline.ingest_alert", _fake)

    huge_line = "CEF:0|A|B|1.0|1|X|5|" + ("a" * 100000)
    sl._ingest_line(_FakeServer(), huge_line)
    assert len(seen["payload"]["raw"]) <= sl._MAX_MESSAGE_BYTES


def test_ingest_line_skips_blank_lines(monkeypatch):
    def _fail(*a, **kw):
        raise AssertionError("must not ingest a blank line")

    monkeypatch.setattr("ingestion.pipeline.ingest_alert", _fail)
    result = sl._ingest_line(_FakeServer(), "   \n")
    assert result == {"outcome": "empty"}
