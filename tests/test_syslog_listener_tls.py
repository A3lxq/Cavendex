"""Tests syslog_listener.py's TLS support against real sockets and a real
TLS handshake -- self-signed certs generated via the real `openssl` CLI
(skipped if unavailable), a real ssl.SSLContext client connecting to a
real _TLSThreadingTCPServer, not a mocked handshake. Mirrors
test_syslog_listener.py's "real I/O, mocked ingest_alert" split."""

import shutil
import socket
import ssl
import subprocess
import threading
import time

import pytest

import syslog_listener as sl

_HAS_OPENSSL = shutil.which("openssl") is not None
pytestmark = pytest.mark.skipif(not _HAS_OPENSSL, reason="openssl CLI not available in this environment")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _gen_self_signed_cert(tmp_path, cn="localhost", name="server"):
    key_path = tmp_path / f"{name}.key"
    crt_path = tmp_path / f"{name}.crt"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(crt_path),
            "-days", "1", "-nodes", "-subj", f"/CN={cn}",
        ],
        check=True, capture_output=True,
    )
    return str(crt_path), str(key_path)


@pytest.fixture
def fake_ingest_alert(monkeypatch):
    calls = []

    def _fake(source, payload, tenant_id=None):
        calls.append({"source": source, "payload": payload, "tenant_id": tenant_id})
        return {"outcome": "promoted", "thread_id": "fake-id", "status": "open"}

    monkeypatch.setattr("ingestion.pipeline.ingest_alert", _fake)
    return calls


def _make_tls_server(port, ssl_context, **attrs):
    server = sl._TLSThreadingTCPServer(("127.0.0.1", port), sl._TCPHandler)
    server.source = attrs.get("source", "syslog_cef")
    server.tenant_id = attrs.get("tenant_id", "t1")
    server.api_url = attrs.get("api_url")
    server.api_key = attrs.get("api_key")
    server.allowed_networks = attrs.get("allowed_networks")
    server.ssl_context = ssl_context
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _client_context_trusting(ca_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=ca_path)
    return context


def test_build_ssl_context_loads_cert_and_key(tmp_path):
    crt, key = _gen_self_signed_cert(tmp_path)
    context = sl._build_ssl_context(crt, key)
    assert context.verify_mode == ssl.CERT_NONE


def test_build_ssl_context_with_client_ca_requires_client_cert(tmp_path):
    crt, key = _gen_self_signed_cert(tmp_path)
    context = sl._build_ssl_context(crt, key, client_ca=crt)
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_tls_listener_ingests_a_real_encrypted_connection(tmp_path, fake_ingest_alert):
    crt, key = _gen_self_signed_cert(tmp_path)
    server_context = sl._build_ssl_context(crt, key)
    port = _free_port()
    server = _make_tls_server(port, server_context, tenant_id="tls-test")
    try:
        client_context = _client_context_trusting(crt)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw_sock:
            with client_context.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock:
                msg = b"CEF:0|Acme|Firewall|1.0|100|Port Scan|7|src=198.51.100.9 dst=10.0.0.5\n"
                tls_sock.sendall(msg)
        time.sleep(0.3)

        assert len(fake_ingest_alert) == 1
        call = fake_ingest_alert[0]
        assert call["tenant_id"] == "tls-test"
        assert call["payload"] == {"raw": msg.decode().strip()}
    finally:
        server.shutdown()
        server.server_close()


def test_plaintext_connection_to_tls_listener_is_rejected(tmp_path, fake_ingest_alert):
    """A sender that can't/doesn't speak TLS hitting the TLS port must not
    silently get ingested as if it were an encrypted, authenticated
    message -- the handshake should fail and nothing should reach
    ingest_alert."""
    crt, key = _gen_self_signed_cert(tmp_path)
    server_context = sl._build_ssl_context(crt, key)
    port = _free_port()
    server = _make_tls_server(port, server_context)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", port))
        s.sendall(b"CEF:0|A|B|1.0|1|X|5|src=1.1.1.1 dst=2.2.2.2\n")
        s.close()
        time.sleep(0.3)

        assert fake_ingest_alert == []
    finally:
        server.shutdown()
        server.server_close()


def test_mutual_tls_rejects_a_client_with_no_certificate(tmp_path, fake_ingest_alert):
    server_crt, server_key = _gen_self_signed_cert(tmp_path, cn="localhost", name="server")
    ca_crt, _ca_key = _gen_self_signed_cert(tmp_path, cn="test-ca", name="ca")
    server_context = sl._build_ssl_context(server_crt, server_key, client_ca=ca_crt)
    port = _free_port()
    server = _make_tls_server(port, server_context)
    try:
        client_context = _client_context_trusting(server_crt)
        # TLS 1.3 can complete the client-side handshake optimistically
        # before the server's rejection (sent as a post-handshake alert)
        # arrives -- so the failure can surface as either an SSLError
        # during wrap_socket() or a ConnectionResetError on the first
        # write. Both are OSError subclasses; either one proves the
        # server never accepted this connection.
        with pytest.raises(OSError):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw_sock:
                with client_context.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock:
                    tls_sock.sendall(b"CEF:0|A|B|1.0|1|X|5|src=1.1.1.1 dst=2.2.2.2\n")
        time.sleep(0.3)

        assert fake_ingest_alert == []
    finally:
        server.shutdown()
        server.server_close()


def test_mutual_tls_accepts_a_client_presenting_a_ca_signed_certificate(tmp_path, fake_ingest_alert):
    ca_key = tmp_path / "ca.key"
    ca_crt = tmp_path / "ca.crt"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(ca_key), "-out", str(ca_crt),
            "-days", "1", "-nodes", "-subj", "/CN=test-ca",
        ],
        check=True, capture_output=True,
    )

    server_crt, server_key = _gen_self_signed_cert(tmp_path, cn="localhost", name="server")

    client_key = tmp_path / "client.key"
    client_csr = tmp_path / "client.csr"
    client_crt = tmp_path / "client.crt"
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048", "-keyout", str(client_key),
            "-out", str(client_csr), "-nodes", "-subj", "/CN=test-client",
        ],
        check=True, capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "x509", "-req", "-in", str(client_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(client_crt), "-days", "1",
        ],
        check=True, capture_output=True,
    )

    server_context = sl._build_ssl_context(server_crt, server_key, client_ca=str(ca_crt))
    port = _free_port()
    server = _make_tls_server(port, server_context, tenant_id="mtls-test")
    try:
        client_context = _client_context_trusting(server_crt)
        client_context.load_cert_chain(certfile=str(client_crt), keyfile=str(client_key))
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw_sock:
            with client_context.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock:
                msg = b"CEF:0|A|B|1.0|1|X|5|src=1.1.1.1 dst=2.2.2.2\n"
                tls_sock.sendall(msg)
        time.sleep(0.3)

        assert len(fake_ingest_alert) == 1
        assert fake_ingest_alert[0]["tenant_id"] == "mtls-test"
    finally:
        server.shutdown()
        server.server_close()


# ---------- CLI argument validation, no sockets needed ----------


def test_main_rejects_tls_cert_without_tls_key(monkeypatch):
    monkeypatch.setattr("sys.argv", ["syslog_listener.py", "--tls-cert", "server.crt"])
    with pytest.raises(SystemExit):
        sl.main()


def test_main_rejects_tls_over_udp(monkeypatch, tmp_path):
    crt, key = _gen_self_signed_cert(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        ["syslog_listener.py", "--protocol", "udp", "--tls-cert", crt, "--tls-key", key],
    )
    with pytest.raises(SystemExit):
        sl.main()


def test_main_rejects_client_ca_without_cert(monkeypatch, tmp_path):
    crt, _key = _gen_self_signed_cert(tmp_path)
    monkeypatch.setattr("sys.argv", ["syslog_listener.py", "--tls-client-ca", crt])
    with pytest.raises(SystemExit):
        sl.main()
