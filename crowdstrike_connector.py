#!/usr/bin/env python3
"""Continuously (or once, for cron-style use) poll CrowdStrike Falcon's
Detects API for new detections — see ingestion/crowdstrike_polling.py
for why this is a dedicated connector rather than a
poll_connector.py/PollerConfig config file (OAuth2 plus a two-step
query-then-summarize API CrowdStrike requires, which PollerConfig's
single-GET/POST-per-poll model can't express), and
examples/crowdstrike_poller_config.example.json for an annotated config
to copy.

Usage:
    export CROWDSTRIKE_CLIENT_ID=...
    export CROWDSTRIKE_CLIENT_SECRET=...
    python crowdstrike_connector.py --config examples/crowdstrike_poller_config.example.json

    # One batch and exit -- for a cron job instead of a systemd service:
    python crowdstrike_connector.py --config examples/crowdstrike_poller_config.example.json --once

The config file never contains a real secret — client_id_env/
client_secret_env name environment variables (set them in your real
.env, or the calling environment) that hold the actual OAuth2 client
credentials.
"""

import argparse
import time

from dotenv import load_dotenv

load_dotenv(override=True)


def main():
    parser = argparse.ArgumentParser(description="Poll CrowdStrike Falcon's Detects API into Cavendex")
    parser.add_argument("--config", required=True, help="Path to a CrowdStrike connector config JSON file")
    parser.add_argument("--once", action="store_true", help="Poll a single batch and exit")
    args = parser.parse_args()

    from ingestion.crowdstrike_polling import load_config, poll_once

    config = load_config(args.config)
    print(f"Polling CrowdStrike Falcon at {config.base_url} as '{config.name}' (tenant={config.tenant})...")

    while True:
        try:
            results = poll_once(config)
        except Exception as exc:
            print(f"  error polling: {exc}")
            results = []

        for result in results:
            outcome = result.get("outcome")
            if outcome == "promoted":
                print(f"  -> promoted to incident {result.get('thread_id')} (status={result.get('status')})")
            elif outcome == "correlated":
                print(f"  -> correlated into incident {result.get('thread_id')} ({result.get('match_type')})")
            elif outcome == "auth_failed":
                print(
                    "  ! OAuth2 authentication not configured -- "
                    "check CROWDSTRIKE_CLIENT_ID/CROWDSTRIKE_CLIENT_SECRET"
                )
            elif outcome not in ("deduped", "suppressed_low_severity"):
                print(f"  ! {outcome}: {result}")

        if not results:
            print("  (no new detections)")

        if args.once:
            break
        time.sleep(config.poll_interval_seconds)


if __name__ == "__main__":
    main()
