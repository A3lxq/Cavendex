#!/usr/bin/env python3
"""Continuously (or once, for cron-style use) poll Microsoft Sentinel's
Log Analytics workspace for new SecurityAlert records — see
ingestion/sentinel_polling.py for why this is a dedicated connector
rather than a poll_connector.py/PollerConfig config file (Azure AD
OAuth2 plus a KQL query call PollerConfig's single-GET/POST-per-poll
model can't express), and examples/sentinel_poller_config.example.json
for an annotated config to copy.

Usage:
    export AZURE_SENTINEL_TENANT_ID=...
    export AZURE_SENTINEL_CLIENT_ID=...
    export AZURE_SENTINEL_CLIENT_SECRET=...
    python sentinel_connector.py --config examples/sentinel_poller_config.example.json

    # One batch and exit -- for a cron job instead of a systemd service:
    python sentinel_connector.py --config examples/sentinel_poller_config.example.json --once

The config file never contains a real secret — azure_ad_tenant_id_env/
client_id_env/client_secret_env name environment variables (set them in
your real .env, or the calling environment) that hold the actual Azure
AD app registration's directory ID and OAuth2 client credentials.
"""

import argparse
import time

from dotenv import find_dotenv, load_dotenv

# find_dotenv(usecwd=True): search from the caller's working directory,
# not this file's location — matters once this module is installed
# into site-packages and run as `cavendex ingest sentinel` from
# wherever a user's .env actually lives.
load_dotenv(find_dotenv(usecwd=True), override=True)


def main():
    parser = argparse.ArgumentParser(description="Poll Microsoft Sentinel's Log Analytics workspace into Cavendex")
    parser.add_argument("--config", required=True, help="Path to a Sentinel connector config JSON file")
    parser.add_argument("--once", action="store_true", help="Poll a single batch and exit")
    args = parser.parse_args()

    from ingestion.sentinel_polling import load_config, poll_once

    config = load_config(args.config)
    print(f"Polling Microsoft Sentinel workspace {config.workspace_id} as '{config.name}' (tenant={config.tenant})...")

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
                    "  ! Azure AD authentication not configured -- check "
                    "AZURE_SENTINEL_TENANT_ID/AZURE_SENTINEL_CLIENT_ID/AZURE_SENTINEL_CLIENT_SECRET"
                )
            elif outcome not in ("deduped", "suppressed_low_severity"):
                print(f"  ! {outcome}: {result}")

        if not results:
            print("  (no new alerts)")

        if args.once:
            break
        time.sleep(config.poll_interval_seconds)


if __name__ == "__main__":
    main()
