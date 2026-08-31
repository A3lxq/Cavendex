"""A real UDP/TCP network listener that receives syslog (optionally
CEF-formatted) messages directly over the network and feeds each one into
Cavendex's ingestion pipeline — the network-facing counterpart to
ingest_watch.py, which requires a forwarder to already be writing to a
local file.

Usage:
    # UDP (the common case — most routers/firewalls/appliances default to
    # UDP syslog):
    python syslog_listener.py --protocol udp --port 5514 --source syslog_cef

    # TCP (newline-delimited framing):
    python syslog_listener.py --protocol tcp --port 5514 --source syslog_cef

    # Plain-text (non-CEF) syslog lines, treated as a generic alert
    # description rather than parsed as CEF key=value pairs:
    python syslog_listener.py --protocol udp --port 5514 --source generic

    # Only accept traffic from a trusted management subnet:
    python syslog_listener.py --protocol udp --port 5514 --allow-from 10.0.0.0/24

    # Remote — POST to a Cavendex API running elsewhere instead of
    # ingesting in-process:
    python syslog_listener.py --protocol udp --port 5514 \
        --api-url http://cavendex-host:8000 --api-key secret

    # TCP wrapped in real TLS (encrypted transport, TCP only -- see the
    # "no DTLS" note below for UDP senders):
    python syslog_listener.py --protocol tcp --port 6514 \
        --tls-cert server.crt --tls-key server.key

    # ...and requiring a client certificate too (mutual TLS), verified
    # against a CA file rather than trusting any client that presents one:
    python syslog_listener.py --protocol tcp --port 6514 \
        --tls-cert server.crt --tls-key server.key --tls-client-ca ca.crt

Run one instance per protocol you need (like ingest_watch.py, one
instance per log file) — this deliberately does not multiplex UDP and
TCP in a single process, for the same "one script, one job" simplicity
as the rest of this project's ingestion tooling.

READ THIS BEFORE EXPOSING IT BEYOND LOCALHOST: classic syslog (UDP or
plain TCP) has no built-in authentication, encryption, or integrity
protection — a UDP source IP is trivially spoofable, and anyone who can
reach this port can inject fabricated alerts. That's not a bug in this
implementation, it's what syslog *is*; the same reason README's Known
Gaps originally called a network listener "a materially different
risk/ops profile than an HTTP endpoint behind your own auth." Mitigate
what's mitigable:
  - This binds to 127.0.0.1 by default. Passing --bind 0.0.0.0 (or a
    specific interface) to accept traffic from other hosts is a
    deliberate, explicit choice you have to make — the same
    "insecure exposure requires opting in" default api.py uses for
    CAVENDEX_API_KEY.
  - --allow-from restricts accepted source IPs to one or more CIDR
    ranges (repeatable) — real syslog senders almost always live on a
    trusted management network/VLAN, not the open internet, so this
    should usually be set in production.
  - Real TLS transport is supported for TCP via --tls-cert/--tls-key
    (stdlib `ssl`, no extra dependency) -- see DEPLOYMENT.md's "Syslog
    over TLS" section for a full self-signed-cert recipe. This is
    TLS-wrapped newline-delimited TCP, not full RFC 5425 (which also
    specifies octet-counting message framing this listener doesn't
    implement) -- most real TLS syslog senders (e.g. rsyslog's `omfwd`
    with a `gtls` StreamDriver) don't require octet-counting and work
    against this directly. --tls-client-ca additionally requires and
    verifies a client certificate (mutual TLS) instead of trusting any
    client that completes the handshake.
  - UDP has no TLS equivalent here (DTLS is a materially bigger
    undertaking this project doesn't implement). If a UDP-only appliance
    needs encrypted transport, or a TCP sender can't speak TLS itself,
    run this behind a VPN/stunnel/WireGuard tunnel between the sender and
    this host instead -- see DEPLOYMENT.md for a concrete stunnel recipe,
    the same way DEPLOYMENT.md recommends a reverse proxy for the API's
    TLS rather than reimplementing it there either.
  - Every accepted message still goes through the exact same
    dedup/correlation/severity-prefilter gate as file-tailed or
    API-pushed alerts (see ingestion/pipeline.py) — a flood of injected
    junk costs at most one suppressed/deduped log line each, not an LLM
    call, unless it's severe enough (or correlates with something
    already open) to warrant one.

Real syslog's traditional port (514) requires root/CAP_NET_BIND_SERVICE
on Linux — this defaults to 5514 so it runs unprivileged. Point real
appliances at 5514 directly (most support a custom destination port), or
run this with the necessary privilege/capability for 514 if you need the
standard port.
"""

import argparse
import ipaddress
import socketserver
import ssl
from typing import List, Optional

from dotenv import load_dotenv

load_dotenv(override=True)

# Generous but bounded — NormalizedAlert length-caps everything that
# actually reaches an incident anyway, but an unbounded read from an
# untrusted network socket is its own (memory-exhaustion) risk regardless
# of what happens downstream.
_MAX_MESSAGE_BYTES = 16384


def _parse_allowed_networks(specs: Optional[List[str]]):
    if not specs:
        return None
    return [ipaddress.ip_network(s, strict=False) for s in specs]


def _is_allowed(ip_str: str, allowed_networks) -> bool:
    """True if `allowed_networks` is None (no restriction configured) or
    `ip_str` falls inside at least one of them. Invalid/unparseable
    addresses are always rejected once an allowlist is configured — fail
    closed, not open.
    """
    if allowed_networks is None:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in allowed_networks)


def _payload_for(source: str, line: str) -> dict:
    if source == "syslog_cef":
        return {"raw": line}
    return {"description": line, "source": "syslog"}


def _ingest_line(server, line: str) -> dict:
    line = line.strip()
    if not line:
        return {"outcome": "empty"}

    line = line[:_MAX_MESSAGE_BYTES]
    payload = _payload_for(server.source, line)

    if server.api_url:
        import requests

        if server.tenant_id and server.tenant_id != "default":
            url = f"{server.api_url.rstrip('/')}/tenants/{server.tenant_id}/ingest/{server.source}"
        else:
            url = f"{server.api_url.rstrip('/')}/ingest/{server.source}"
        headers = {"Authorization": f"Bearer {server.api_key}"} if server.api_key else {}
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()

    from ingestion.pipeline import ingest_alert

    return ingest_alert(server.source, payload, tenant_id=server.tenant_id)


def _report(result: dict) -> None:
    outcome = result.get("outcome")
    if outcome == "promoted":
        print(f"  -> promoted to incident {result.get('thread_id')} (status={result.get('status')})")
    elif outcome == "correlated":
        print(f"  -> correlated into incident {result.get('thread_id')} ({result.get('match_type')})")
    elif outcome not in ("deduped", "suppressed_low_severity", "not_an_alert", "empty"):
        print(f"  ! {outcome}: {result}")


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, _sock = self.request
        client_ip = self.client_address[0]
        if not _is_allowed(client_ip, self.server.allowed_networks):
            return
        try:
            line = data[:_MAX_MESSAGE_BYTES].decode("utf-8", errors="replace")
        except Exception:
            return
        try:
            _report(_ingest_line(self.server, line))
        except Exception as exc:
            print(f"  error ingesting UDP message from {client_ip}: {exc}")


class _ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        client_ip = self.client_address[0]
        if not _is_allowed(client_ip, self.server.allowed_networks):
            return
        while True:
            raw = self.rfile.readline(_MAX_MESSAGE_BYTES)
            if not raw:
                break
            try:
                line = raw.decode("utf-8", errors="replace")
            except Exception:
                continue
            try:
                _report(_ingest_line(self.server, line))
            except Exception as exc:
                print(f"  error ingesting TCP message from {client_ip}: {exc}")


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _build_ssl_context(certfile: str, keyfile: str, client_ca: Optional[str] = None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    if client_ca:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=client_ca)
    return context


class _TLSThreadingTCPServer(_ThreadingTCPServer):
    """TLS-wrapped version of _ThreadingTCPServer -- socketserver has no
    built-in TLS support, so this overrides get_request() to wrap the
    accepted socket the same way the standard library's own docs show.
    Known tradeoff: the handshake happens in this single accept loop
    (get_request runs before a handler thread is spun up), so one slow or
    hostile handshake briefly delays accepting the next connection --
    acceptable for a syslog listener's expected connection rate, not
    appropriate for a high-concurrency TLS server.
    """

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        try:
            connstream = self.ssl_context.wrap_socket(newsocket, server_side=True)
        except ssl.SSLError as exc:
            # A failed handshake (bad/missing client cert under mutual
            # TLS, a port scanner, a plaintext sender pointed at the TLS
            # port) is routine noise on a network-facing listener, not a
            # crash -- log one short line and let it propagate as the
            # OSError socketserver's accept loop already knows to swallow
            # (ssl.SSLError subclasses OSError) instead of tearing down
            # the whole listener.
            print(f"  TLS handshake failed from {fromaddr[0]}: {exc}")
            newsocket.close()
            raise
        return connstream, fromaddr


def main():
    parser = argparse.ArgumentParser(description="Receive syslog messages over the network into Cavendex")
    parser.add_argument("--protocol", choices=["udp", "tcp"], default="udp")
    parser.add_argument("--bind", default="127.0.0.1", help="Interface to bind to (default: loopback only)")
    parser.add_argument("--port", type=int, default=5514)
    parser.add_argument("--source", choices=["syslog_cef", "generic"], default="syslog_cef")
    parser.add_argument("--tenant", default="default")
    parser.add_argument(
        "--allow-from",
        action="append",
        default=None,
        metavar="CIDR",
        help="Only accept messages from this CIDR range; repeatable. Default: accept from anywhere reachable.",
    )
    parser.add_argument(
        "--api-url", default=None, help="POST to this Cavendex API instead of ingesting in-process"
    )
    parser.add_argument("--api-key", default=None)
    parser.add_argument(
        "--tls-cert",
        default=None,
        help="Enable real TLS (TCP only): path to a PEM server certificate. Requires --tls-key. "
        "See DEPLOYMENT.md's 'Syslog over TLS' section for a self-signed-cert recipe.",
    )
    parser.add_argument("--tls-key", default=None, help="Path to the PEM private key for --tls-cert.")
    parser.add_argument(
        "--tls-client-ca",
        default=None,
        help="Optional: require and verify a client certificate against this CA PEM file (mutual TLS). "
        "Requires --tls-cert/--tls-key.",
    )
    args = parser.parse_args()

    if args.tls_cert or args.tls_key:
        if not (args.tls_cert and args.tls_key):
            parser.error("--tls-cert and --tls-key must be given together")
        if args.protocol != "tcp":
            parser.error(
                "--tls-cert/--tls-key require --protocol tcp -- there is no UDP/DTLS support here, "
                "see the module docstring for the VPN/tunnel alternative"
            )
    elif args.tls_client_ca:
        parser.error("--tls-client-ca requires --tls-cert/--tls-key")

    allowed_networks = _parse_allowed_networks(args.allow_from)

    if args.tls_cert:
        server_cls = _TLSThreadingTCPServer
        handler_cls = _TCPHandler
    else:
        server_cls = _ThreadingUDPServer if args.protocol == "udp" else _ThreadingTCPServer
        handler_cls = _UDPHandler if args.protocol == "udp" else _TCPHandler

    server = server_cls((args.bind, args.port), handler_cls)
    server.source = args.source
    server.tenant_id = args.tenant
    server.api_url = args.api_url
    server.api_key = args.api_key
    server.allowed_networks = allowed_networks
    if args.tls_cert:
        server.ssl_context = _build_ssl_context(args.tls_cert, args.tls_key, args.tls_client_ca)

    tls_note = ""
    if args.tls_cert:
        tls_note = " [TLS" + (", mutual" if args.tls_client_ca else "") + "]"
    print(
        f"Listening for {args.protocol.upper()} syslog on {args.bind}:{args.port}{tls_note} "
        f"(source={args.source}, tenant={args.tenant})..."
    )
    if allowed_networks:
        print(f"Restricted to: {', '.join(str(n) for n in allowed_networks)}")
    if args.api_url:
        print(f"Forwarding to API at {args.api_url}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
