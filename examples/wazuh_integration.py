#!/usr/bin/env python3
"""Wazuh custom-integration script: forwards a Wazuh alert straight to
Cavendex's /ingest/wazuh endpoint as its own real JSON shape — no field
remapping needed, since ingestion/normalizers.py:normalize_wazuh() already
understands Wazuh's native alert schema (rule/agent/data).

This is the PUSH alternative to tailing /var/ossec/logs/alerts/alerts.json
with ingest_watch.py — use this one if Cavendex doesn't have (or
shouldn't have) filesystem access to the Wazuh manager, or if you only
want alerts at/above a specific rule level forwarded, which Wazuh's own
<level> integration setting already filters for you before this script
ever runs.

HONESTY NOTE: this follows Wazuh's documented custom-integration script
contract (positional argv: alert file, api_key, hook_url) — it has not
been tested against a real Wazuh manager, since this project doesn't
have one to verify against (the same caveat README's Known Gaps gives
for any vendor-specific integration). Test this against your own
environment's actual Wazuh version before relying on it; the exact
number/order of arguments has shifted across Wazuh versions before.

Install (on the Wazuh manager host):
    sudo cp wazuh_integration.py /var/ossec/integrations/custom-cavendex.py
    sudo chmod 750 /var/ossec/integrations/custom-cavendex.py
    sudo chown root:wazuh /var/ossec/integrations/custom-cavendex.py

Add to /var/ossec/ossec.conf (inside <ossec_config>):
    <integration>
      <name>custom-cavendex</name>
      <hook_url>http://cavendex-host:8000/ingest/wazuh</hook_url>
      <api_key>your-cavendex-api-key-if-set</api_key>
      <alert_format>json</alert_format>
      <level>7</level>
    </integration>

Then restart the manager: sudo systemctl restart wazuh-manager

<level>7</level> above means "only forward alerts at rule level 7+" —
tune it, or drop it to forward everything and let Cavendex's own
CAVENDEX_INGEST_MIN_SEVERITY do the filtering instead.
"""

import json
import sys

import requests


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: custom-cavendex.py <alert_file> <api_key> <hook_url>\n")
        sys.exit(1)

    alert_file = sys.argv[1]
    api_key = sys.argv[2] or None
    hook_url = sys.argv[3] if len(sys.argv) > 3 else None

    if not hook_url:
        sys.stderr.write("no hook_url configured in ossec.conf's <integration> block\n")
        sys.exit(1)

    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"could not read/parse alert file {alert_file}: {exc}\n")
        sys.exit(1)

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        response = requests.post(hook_url, json=alert, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.RequestException as exc:
        sys.stderr.write(f"failed to forward alert to Cavendex: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
