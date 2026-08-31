"""Continuously tail a JSON-lines alert log (e.g. Suricata's eve.json) and
feed each new line into Cavendex's ingestion pipeline — this is the
concrete "continuous monitoring" piece: point it at a real detection
tool's log file and it keeps creating/deduping/suppressing incidents as
new events arrive, indefinitely.

Usage:
    # In-process (same machine as Cavendex's data/vault/db):
    python ingest_watch.py --path /var/log/suricata/eve.json --source suricata

    python ingest_watch.py --path /var/log/suricata/eve.json --source suricata \
        --tenant acme-corp

    # Process the whole existing file once, not just new lines from now on:
    python ingest_watch.py --path /var/log/suricata/eve.json --source suricata \
        --from-start

    # Remote — POST to a Cavendex API running elsewhere instead of
    # calling the ingestion pipeline in-process:
    python ingest_watch.py --path /var/log/suricata/eve.json --source suricata \
        --api-url http://cavendex-host:8000 --api-key secret

Only JSON-lines sources are supported here (suricata, wazuh, generic) —
a raw CEF-formatted syslog line needs either a syslog-to-webhook
forwarder POSTing straight to /ingest/syslog_cef, or syslog_listener.py,
which receives syslog directly over UDP/TCP instead of tailing a file at
all. To tail a Wazuh manager's alert log directly:

    python ingest_watch.py --path /var/ossec/logs/alerts/alerts.json --source wazuh

(Wazuh can also push directly via a custom integration script instead of
being tailed — see examples/wazuh_integration.py.)
"""

import argparse
import json
import os
import time

from dotenv import load_dotenv

load_dotenv(override=True)


def _follow(path: str, from_start: bool = False):
    """Yield new lines appended to `path`, like `tail -f`. Tolerates the
    file not existing yet and log rotation (file replaced with a new
    inode) by reopening.
    """
    f = None
    inode = None
    while True:
        if f is None:
            try:
                f = open(path, "r", encoding="utf-8")
            except FileNotFoundError:
                time.sleep(1)
                continue
            inode = os.fstat(f.fileno()).st_ino
            if not from_start:
                f.seek(0, os.SEEK_END)

        line = f.readline()
        if line:
            yield line
            continue

        try:
            current_inode = os.stat(path).st_ino
        except FileNotFoundError:
            current_inode = None
        if current_inode != inode:
            f.close()
            f = None
        time.sleep(1)


def _ingest_local(source: str, payload: dict, tenant_id: str) -> dict:
    from ingestion.pipeline import ingest_alert

    return ingest_alert(source, payload, tenant_id=tenant_id)


def _ingest_via_api(api_url: str, api_key: str, source: str, payload: dict, tenant_id: str) -> dict:
    import requests

    if tenant_id and tenant_id != "default":
        url = f"{api_url.rstrip('/')}/tenants/{tenant_id}/ingest/{source}"
    else:
        url = f"{api_url.rstrip('/')}/ingest/{source}"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    response = requests.post(url, json=payload, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json()


def main():
    parser = argparse.ArgumentParser(description="Tail a JSON-lines alert log into Cavendex")
    parser.add_argument("--path", required=True, help="Path to the JSON-lines log file")
    parser.add_argument("--source", required=True, choices=["suricata", "wazuh", "generic"])
    parser.add_argument("--tenant", default="default")
    parser.add_argument(
        "--from-start", action="store_true", help="Process the whole existing file, not just new lines"
    )
    parser.add_argument(
        "--api-url", default=None, help="POST to this Cavendex API instead of ingesting in-process"
    )
    parser.add_argument("--api-key", default=None)
    args = parser.parse_args()

    print(f"Watching {args.path} (source={args.source}, tenant={args.tenant})...")
    if args.api_url:
        print(f"Forwarding to API at {args.api_url}")

    for raw_line in _follow(args.path, from_start=args.from_start):
        line = raw_line.strip()
        if not line:
            continue

        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            print(f"  skip: not valid JSON: {line[:100]}")
            continue

        try:
            if args.api_url:
                result = _ingest_via_api(args.api_url, args.api_key, args.source, payload, args.tenant)
            else:
                result = _ingest_local(args.source, payload, args.tenant)
        except Exception as exc:
            print(f"  error ingesting event: {exc}")
            continue

        outcome = result.get("outcome")
        if outcome == "promoted":
            print(f"  -> promoted to incident {result.get('thread_id')} (status={result.get('status')})")
        elif outcome not in ("deduped", "suppressed_low_severity", "not_an_alert"):
            # Anything other than the expected quiet-common-case outcomes
            # is worth surfacing (unknown_source, a normalizer bug, etc).
            print(f"  ! {outcome}: {result}")


if __name__ == "__main__":
    main()
