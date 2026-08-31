"""Continuously (or once, for cron-style use) poll a SIEM/EDR's own REST
API for alerts, using a JSON config describing that API's shape — see
ingestion/polling.py for what a config can express, and
examples/poller_config.example.json for an annotated one to copy.

Usage:
    # Long-running, polling on the interval the config specifies:
    python poll_connector.py --config examples/poller_config.example.json

    # One batch and exit — for a cron job instead of a systemd service:
    python poll_connector.py --config examples/poller_config.example.json --once

The config file never contains a real secret — auth_token_env names an
environment variable (set it in your real .env, or the calling
environment) that holds the actual API token.
"""

import argparse
import time

from dotenv import load_dotenv

load_dotenv(override=True)


def main():
    parser = argparse.ArgumentParser(description="Poll a SIEM/EDR REST API into Cavendex")
    parser.add_argument("--config", required=True, help="Path to a poller config JSON file")
    parser.add_argument("--once", action="store_true", help="Poll a single batch and exit")
    args = parser.parse_args()

    from ingestion.polling import load_config, poll_once

    config = load_config(args.config)
    print(f"Polling {config.base_url} as '{config.name}' (tenant={config.tenant}, source={config.source_name})...")

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
            elif outcome not in ("deduped", "suppressed_low_severity"):
                print(f"  ! {outcome}: {result}")

        if not results:
            print("  (no new records)")

        if args.once:
            break
        time.sleep(config.poll_interval_seconds)


if __name__ == "__main__":
    main()
