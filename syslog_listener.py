"""A real UDP/TCP network listener that receives syslog (optionally
CEF-formatted) messages directly over the network and feeds each one into
SentinelOS's ingestion pipeline — the network-facing counterpart to
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

    # Remote — POST to a SentinelOS API running elsewhere instead of
    # ingesting in-process:
    python syslog_listener.py --protocol udp --port 5514 \
        --api-url http://sentinelos-host:8000 --api-key secret

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
    SENTINELOS_API_KEY.
  - --allow-from restricts accepted source IPs to one or more CIDR
    ranges (repeatable) — real syslog senders almost always live on a
    trusted management network/VLAN, not the open internet, so this
    should usually be set in production.
  - There is no TLS/DTLS here (real "syslog over TLS," RFC 5425, is a
    materially bigger undertaking). If you need encrypted transport, run
    this behind a VPN/stunnel/WireGuard tunnel between the sender and
    this host, the same way DEPLOYMENT.md recommends a reverse proxy for
    the API's TLS rather than reimplementing it here.
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


def main():
    parser = argparse.ArgumentParser(description="Receive syslog messages over the network into SentinelOS")
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
        "--api-url", default=None, help="POST to this SentinelOS API instead of ingesting in-process"
    )
    parser.add_argument("--api-key", default=None)
    args = parser.parse_args()

    allowed_networks = _parse_allowed_networks(args.allow_from)

    server_cls = _ThreadingUDPServer if args.protocol == "udp" else _ThreadingTCPServer
    handler_cls = _UDPHandler if args.protocol == "udp" else _TCPHandler

    server = server_cls((args.bind, args.port), handler_cls)
    server.source = args.source
    server.tenant_id = args.tenant
    server.api_url = args.api_url
    server.api_key = args.api_key
    server.allowed_networks = allowed_networks

    print(
        f"Listening for {args.protocol.upper()} syslog on {args.bind}:{args.port} "
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
