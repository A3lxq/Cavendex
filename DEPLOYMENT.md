# SentinelOS Deployment Guide

This is the "install it on a real machine and run it continuously" guide.
`README.md` covers architecture, features, and a quick local dev
walkthrough — start there if you just want to try it. This file is for
standing SentinelOS up as a service that watches real logs and stays
running.

Read **Section 12 (Known Limitations to Plan Around)** before you point
this at production infrastructure. Nothing in this project is dishonest
about what it is: an analyst's assistant with a mandatory human-approval
gate, not an unattended SOC.

---

## 1. Prerequisites

- **Python 3.10+** (developed and tested on 3.14; nothing in the codebase
  is version-pinned to a specific minor version).
- **Git**, to clone the repo and pull updates.
- **An LLM provider.** One of:
  - A paid API key (Groq, OpenAI, Anthropic, or Google AI Studio) — the
    realistic choice for a production SOC that needs fast, reliable
    turnaround on every incident.
  - [Ollama](https://ollama.com) running locally or on a reachable host,
    with a model already pulled (`ollama pull llama3.1`, or similar) —
    free and keeps incident data off third-party APIs entirely, but see
    the honest performance note in Section 12 before relying on it for
    time-sensitive response.
- **(Optional) AbuseIPDB and/or VirusTotal API keys** — free tiers exist
  for both — for real IOC reputation lookups instead of LLM recall alone.
- **A reverse proxy** (nginx or Caddy) if this will be reachable by
  anyone other than you on localhost. SentinelOS itself does not
  terminate TLS.
- A Linux host with `systemd`, if you want it to run as a proper service
  and survive a reboot (the instructions below assume this; adapt as
  needed for other init systems).

---

## 2. Install

```bash
git clone <your-fork-or-repo-url> /opt/sentinelos
cd /opt/sentinelos

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.lock.txt

cp .env.example .env
```

Use `requirements.lock.txt` (exact-pinned) here, not `requirements.txt`
(floor-pinned `>=`, meant for development) — a production install
shouldn't silently pull a newer, not-yet-audited dependency version just
because `pip` resolved one. See the comment at the top of
`requirements.lock.txt` for how to regenerate it when you deliberately
want to bump something.

Edit `.env`:

- Set **one** LLM provider variable (`GROQ_API_KEY`, `OPENAI_API_KEY`,
  `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, or `OLLAMA_MODEL` +
  `OLLAMA_BASE_URL`). `utils/llm.py` tries them in that order and uses
  the first one that's configured.
- Set `SENTINELOS_API_KEY` to a long random value
  (`python -c "import secrets; print(secrets.token_urlsafe(32))"`) —
  **do this before exposing the API to any network beyond your own
  laptop.** Unset, every route except `/health`, `/`, and `/static/*`
  runs unauthenticated. **If you'll run more than one tenant and they
  shouldn't see each other's data, also set `SENTINELOS_TENANT_API_KEYS`**
  (a JSON object mapping each tenant_id to its own key) — without it, this
  one key authorizes every tenant, not just the one it's meant for.
- Point `SENTINELOS_DATA_DIR`, `CHROMA_PERSIST_DIR`, and
  `OBSIDIAN_VAULT_PATH` at real, persistent paths outside the repo
  checkout if you're deploying to a directory that might get wiped on
  redeploy — e.g. `/var/lib/sentinelos/{data,chroma,vault}`. These three
  directories are the entire state of the system; see Section 10.
- Optionally set `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` for real
  threat-intel lookups, and tune `SENTINELOS_INGEST_MIN_SEVERITY`,
  `SENTINELOS_DEDUP_WINDOW_SECONDS`, `SENTINELOS_CORRELATION_*` to your
  actual alert volume — the shipped defaults are reasonable starting
  points, not tuned to any specific environment. **In particular, set
  `SENTINELOS_CORRELATION_SUBNET_PREFIX_BITS`/`_V6` to match how your
  network is actually subnetted** — the `/24`/`/64` defaults assume a
  size most real businesses don't use; see README's "IP Ranges and
  Subnet Support" for a sizing guide.

Lock down the file once it has real secrets in it:

```bash
chmod 600 .env
```

---

## 3. Verify the install before trusting it

```bash
source venv/bin/activate
pytest                      # should show "149 passed" (or more) with no LLM configured
```

Then a real smoke test against your configured provider:

```bash
python cli.py new "Test incident: verifying SentinelOS install" --severity low --stream
```

You should see Triage run and produce a real decision. If it errors,
fix that before wiring up log ingestion — every downstream piece
(ingestion, correlation, the dashboard) depends on the same pipeline
working.

---

## 4. Run it as a service

**Default (no `SENTINELOS_REDIS_URL`): run SentinelOS as one `uvicorn`
process, not multiple workers or multiple replicas behind a load
balancer.** Rate limiting and the alert dedup window
(`utils/rate_limit.py`, `utils/dedup.py`) keep their state in-process by
default — a second worker has its own separate copy of that state, so
`--workers 4` doesn't scale this app, it silently breaks dedup and rate
limiting across whichever worker happens to handle each request.

**Set `SENTINELOS_REDIS_URL` and both switch to a real Redis-backed
implementation, safe to run behind `--workers N` or multiple host
replicas:**

```env
SENTINELOS_REDIS_URL=redis://redis.internal.example.com:6379/0
```

Same function signatures, same semantics — every caller of
`check_rate_limit()`/`is_duplicate()` behaves identically either way;
only the storage backing the shared state changes. Live-verified with
two genuinely independent `uvicorn` processes pointed at the same
Redis instance: a 3-requests/minute limit was correctly enforced as ONE
shared quota across both processes combined (not 3 each), and a
duplicate alert sent to two separate processes was correctly deduped on
the second one regardless of which process handled which request. A
Redis connection/command failure is never silently swallowed here —
rate limiting exists specifically to hold up under load, and quietly
admitting every request because Redis hiccuped would defeat the point;
expect a visible error (a 500 from the API, a logged-and-skipped message
from `syslog_listener.py`/`poll_connector.py`) instead, the same
"fail loud, not silently open" choice this project makes for other
protective controls.

**Correlation does NOT need (or use) Redis, and was never really
"per-process in-memory state" to begin with.** `ingestion/correlation.py`'s
candidate pool reads from `utils/incident_index.py`'s SQLite file, which
is durable and already shared correctly by multiple worker processes on
*one* host — a `--workers 4` setup was never silently breaking
correlation the way it broke rate limiting/dedup. What it doesn't do is
extend across multiple *hosts* without pointing `SENTINELOS_DATA_DIR` at
genuinely shared/networked storage, which introduces its own real
caveats (SQLite's locking model is not a great fit for a networked
filesystem like NFS under concurrent writers). If you need true
multi-host correlation with zero shared storage at all, that needs a
real client-server database in place of SQLite — a materially bigger
migration than adding Redis, and out of scope here; Redis (a fast
key/counter store) is also just the wrong tool for `incident_index.db`'s
actual job (structured queries with `WHERE`/`ORDER BY` across incident
fields the dashboard's search/filter/stats also depend on), not merely
an unbuilt feature.

Create `/etc/systemd/system/sentinelos-api.service`:

```ini
[Unit]
Description=SentinelOS API + dashboard
After=network.target

[Service]
Type=simple
User=sentinelos
WorkingDirectory=/opt/sentinelos
EnvironmentFile=/opt/sentinelos/.env
ExecStart=/opt/sentinelos/venv/bin/uvicorn api:api --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Bind to `127.0.0.1`, not `0.0.0.0` — put a reverse proxy in front (next
section) rather than exposing uvicorn directly.

Create the dedicated user and enable the service:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin sentinelos
sudo chown -R sentinelos:sentinelos /opt/sentinelos
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelos-api
sudo systemctl status sentinelos-api
curl http://127.0.0.1:8000/health   # {"status": "ok"}
```

---

## 5. Put a reverse proxy in front (TLS)

SentinelOS's SSE streaming endpoints (`/incidents/stream`, the
dashboard's live "New Incident"/"Threat Hunt" forms, and `/incidents/events`
behind the dashboard's real-time incident list) need two settings most
default reverse-proxy configs get wrong: **response buffering must be
off**, and the **read timeout must be long**, because a real
multi-agent pipeline run can legitimately take anywhere from a few
seconds (a fast hosted API) to well over ten minutes (a local model on
modest hardware — genuinely observed during this project's own live
testing, not a hypothetical). A default 60-second proxy timeout will cut
the stream off mid-incident.

`/incidents/events` is a different shape of stream — deliberately
open-ended (heartbeats keep it alive indefinitely, not just for one
pipeline run), so *any* finite proxy read timeout will eventually close
it. That's expected, not a bug: the dashboard reconnects automatically
with backoff, and falls back to its existing 15-second polling in the
meantime, so a periodic proxy-forced disconnect on this one endpoint is
invisible to an analyst using the dashboard normally.

**nginx** (`/etc/nginx/sites-available/sentinelos`):

```nginx
server {
    listen 443 ssl http2;
    server_name sentinelos.internal.example.com;

    ssl_certificate     /etc/letsencrypt/live/sentinelos.internal.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sentinelos.internal.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Required for SSE (/incidents/stream and the dashboard's
        # streaming forms) to actually stream instead of buffering
        # until the whole response is ready:
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1800s;
        chunked_transfer_encoding on;
    }
}

server {
    listen 80;
    server_name sentinelos.internal.example.com;
    return 301 https://$host$request_uri;
}
```

**Caddy** is simpler and gets SSE-friendly defaults mostly right out of
the box:

```caddyfile
sentinelos.internal.example.com {
    reverse_proxy 127.0.0.1:8000 {
        flush_interval -1
    }
}
```

Either way: this is a tool that reads and reasons about your security
incidents. Put it on an internal/VPN-only hostname, not a
publicly-routable one, regardless of the API key.

---

## 6. Feed it real alerts continuously

Four ways in, all already implemented — pick whichever matches your
environment (see README's "Adding an Ingestion Source" if you need a
normalizer for a format that isn't Suricata/Zeek eve.json, Wazuh, CEF
syslog, or generic JSON):

### Tailing a log file

One `ingest_watch.py` process per source/tenant. Create
`/etc/systemd/system/sentinelos-ingest-suricata.service`:

```ini
[Unit]
Description=SentinelOS ingestion - Suricata eve.json
After=network.target sentinelos-api.service

[Service]
Type=simple
User=sentinelos
WorkingDirectory=/opt/sentinelos
EnvironmentFile=/opt/sentinelos/.env
ExecStart=/opt/sentinelos/venv/bin/python ingest_watch.py \
    --path /var/log/suricata/eve.json \
    --source suricata \
    --tenant default \
    --api-url http://127.0.0.1:8000 \
    --api-key ${SENTINELOS_API_KEY}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

(`--api-url`/`--api-key` route through the API you already have running;
omit them to have `ingest_watch.py` call the pipeline in-process instead
— fine for a single-machine setup, but then it isn't rate-limited or
size-guarded the way the API route is.)

Enable one such unit per log file/tenant you're watching:

```bash
sudo systemctl enable --now sentinelos-ingest-suricata
```

**Running Wazuh?** Same mechanism, same unit shape — swap the path and
source:

```ini
ExecStart=/opt/sentinelos/venv/bin/python ingest_watch.py \
    --path /var/ossec/logs/alerts/alerts.json \
    --source wazuh \
    --tenant default \
    --api-url http://127.0.0.1:8000 \
    --api-key ${SENTINELOS_API_KEY}
```

This needs the `sentinelos` user to have read access to the Wazuh
manager's alert log — either run both on the same host and add
`sentinelos` to the appropriate group, or ship a copy of the file to
wherever SentinelOS runs. If SentinelOS doesn't have (or shouldn't have)
filesystem access to the Wazuh manager at all, use Wazuh's own
push-based integration instead — see README's "Wazuh Integration"
section and `examples/wazuh_integration.py` for the `ossec.conf` config
and honest caveats (verified against a real local HTTP server, not
against an actual Wazuh manager, since none is available to this
project to test against).

### Receiving syslog directly over the network

`syslog_listener.py` opens a real UDP or TCP socket instead of tailing a
file — for appliances that send syslog directly rather than writing to a
log a forwarder reads. **Read this before enabling it**: classic syslog
has no built-in authentication or encryption, and a UDP source IP is
trivially spoofable — that's the protocol, not a bug here. Two
mitigations you should actually use in production:

- Bind to a management-network interface, not `0.0.0.0` on a
  general-purpose host.
- Set `--allow-from` to the CIDR range your real syslog senders live on.

```ini
[Unit]
Description=SentinelOS syslog listener
After=network.target

[Service]
Type=simple
User=sentinelos
WorkingDirectory=/opt/sentinelos
EnvironmentFile=/opt/sentinelos/.env
ExecStart=/opt/sentinelos/venv/bin/python syslog_listener.py \
    --protocol udp \
    --bind 10.0.5.10 \
    --port 5514 \
    --source syslog_cef \
    --tenant default \
    --allow-from 10.0.5.0/24
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Real syslog's traditional port (514) needs root/`CAP_NET_BIND_SERVICE` on
Linux; this defaults to 5514 to run unprivileged. Either point your
appliances at 5514 directly (most support a custom destination port), or
grant the capability explicitly rather than running the whole service as
root:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

### Syslog over TLS

Binding to a management interface and restricting `--allow-from` doesn't
give you encryption or integrity on the wire — anyone on that segment
can still read or spoof plain UDP/TCP syslog. `syslog_listener.py`
supports real TLS for TCP via Python's standard-library `ssl` module (no
extra dependency): a self-signed cert is enough for most real syslog
senders, since (like most syslog-over-TLS setups) they're configured to
trust one specific cert or CA rather than a public one.

**1. Generate a self-signed cert** (swap in a real CA-issued one if your
org has an internal CA — nothing here requires a self-signed cert
specifically):

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
    -days 825 -nodes -subj "/CN=sentinelos-syslog.internal"
```

**2. Run the listener with `--tls-cert`/`--tls-key`:**

```ini
ExecStart=/opt/sentinelos/venv/bin/python syslog_listener.py \
    --protocol tcp \
    --bind 10.0.5.10 \
    --port 6514 \
    --source syslog_cef \
    --tenant default \
    --allow-from 10.0.5.0/24 \
    --tls-cert /opt/sentinelos/tls/server.crt \
    --tls-key /opt/sentinelos/tls/server.key
```

Port 6514 is IANA's registered "syslog-tls" port, used here by
convention (nothing enforces it — any port works, same as the plaintext
listener's 5514 default).

**3. Point a real TLS-capable sender at it.** rsyslog's `omfwd` action
with a `gtls` `StreamDriver` is the common case:

```
action(type="omfwd" target="sentinelos-syslog.internal" port="6514"
       protocol="tcp"
       StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="anon")
```

(`StreamDriverAuthMode="anon"` trusts the server cert without verifying
its identity against a CA — appropriate for a self-signed cert in a
closed environment; use `"x509/name"` with the CA imported into rsyslog's
trust store instead if you want real hostname verification.)

**Verify the handshake actually works** before relying on it — a quick
`openssl s_client` connection confirms the listener presents the
expected cert and completes a real handshake without needing a full
sender configured yet:

```bash
openssl s_client -connect sentinelos-syslog.internal:6514 -brief
```

**Mutual TLS** (`--tls-client-ca <CA file>`) additionally requires and
verifies a client certificate, so only a sender holding a key you've
actually issued can connect at all — not just anyone who can reach the
port and complete a one-way handshake. This is worth the extra
cert-issuing overhead when the syslog listener is reachable from a
shared network segment rather than a point-to-point link you already
trust.

**Honest limits:**
- This is TLS-wrapped newline-delimited TCP, not full RFC 5425 — RFC
  5425 also specifies octet-counting message framing, which this
  listener doesn't implement. Most real TLS syslog senders (rsyslog's
  `omfwd`/`gtls` included) don't require it and work against this
  directly; a sender that specifically demands octet-counted framing
  won't.
- There's no DTLS for UDP senders — if an appliance only speaks UDP
  syslog and needs encrypted transport, see "A VPN/tunnel alternative"
  below instead.
- The TLS handshake happens in the server's single accept loop before a
  connection is handed to a worker thread, so one slow or hostile
  handshake briefly delays accepting the next connection. Fine at a
  syslog listener's expected connection rate; not a general-purpose
  high-concurrency TLS server.

### A VPN/tunnel alternative

For a UDP-only appliance, or a TCP sender that genuinely can't be
configured to speak TLS itself, wrap the whole connection in a tunnel
instead of relying on `syslog_listener.py`'s own TLS support. `stunnel`
is the lightest-weight option for a single TCP stream — it terminates
TLS and forwards plaintext to the listener locally, so from
`syslog_listener.py`'s point of view the traffic looks like an ordinary
local plaintext connection (run `syslog_listener.py` without
`--tls-cert` in this setup):

```ini
# stunnel.conf on the SentinelOS host (server side)
[syslog-tls]
accept = 6514
connect = 127.0.0.1:5514
cert = /opt/sentinelos/tls/server.crt
key = /opt/sentinelos/tls/server.key
```

```ini
# stunnel.conf on the sending host (client side)
[syslog-tls]
client = yes
accept = 127.0.0.1:5514
connect = sentinelos-syslog.internal:6514
```

The sending appliance then points its plain syslog output at
`127.0.0.1:5514` on its own host, unaware TLS is involved at all —
useful for legacy appliances with no TLS support of their own. For a
UDP-only sender, or for encrypting more than just this one port,
a network-level VPN (WireGuard is the lightest-weight modern choice)
between the sender's network and this host is the more general fix —
outside this project's scope to configure for you, but the same
principle DEPLOYMENT.md already applies to the API's own TLS: terminate
it at a layer built and hardened for exactly that job, not inside this
project's own listener code.

(add that under `[Service]` and change `--port` to `514`). Run a second
instance with `--protocol tcp` if you need both transports — one process,
one protocol, the same pattern as one `ingest_watch.py` per log file.

### Polling your own SIEM/EDR's API

`poll_connector.py` calls a REST API on an interval and ingests whatever
it returns, described by a JSON config rather than vendor-specific code
— see `examples/poller_config.example.json` and README's "Syslog
Listener and SIEM/EDR Polling Connectors" for what a config can express.
Put your real config outside the repo checkout (e.g.
`/etc/sentinelos/my-siem.json`) and reference the environment variable
holding your API token from it, never the token itself:

```ini
[Unit]
Description=SentinelOS polling connector - my-siem
After=network.target

[Service]
Type=simple
User=sentinelos
WorkingDirectory=/opt/sentinelos
EnvironmentFile=/opt/sentinelos/.env
ExecStart=/opt/sentinelos/venv/bin/python poll_connector.py \
    --config /etc/sentinelos/my-siem.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Prefer a cron job over a long-running service? Pass `--once` and let cron
own the schedule instead of `poll_interval_seconds` in the config.

**Splunk** is a concrete, non-generic example of the same `poll_connector.py`
entrypoint: `examples/splunk_poller_config.example.json` targets Splunk's
REST Search API in `exec_mode=oneshot` mode (one blocking request, real
single-JSON results) with `"normalizer": "splunk"` so
`ingestion/normalizers.py:normalize_splunk()` handles Splunk ES's real
notable-event field shape — its five-value urgency scale and MITRE
ATT&CK annotations — instead of a flat `field_map`. See README's "Splunk
Integration" for the full config and the Webhook-alert-action push
alternative. Auth is a long-lived Splunk token (Settings → Tokens);
`SPLUNK_API_TOKEN` is the environment variable the shipped example
config expects, set in `/opt/sentinelos/.env` the same as any other
credential in this project.

### Polling CrowdStrike Falcon's Detects API

CrowdStrike needs a fully separate connector, `crowdstrike_connector.py`
(not `poll_connector.py`) — its real API requires an OAuth2
client-credentials exchange and a two-step query-then-summarize call
sequence that `poll_connector.py`'s generic single-request model can't
express. See README's "CrowdStrike Integration" for the full
explanation and `examples/crowdstrike_poller_config.example.json` for
an annotated config (including the real per-region base URLs).

```ini
[Unit]
Description=SentinelOS CrowdStrike Falcon connector
After=network.target

[Service]
Type=simple
User=sentinelos
WorkingDirectory=/opt/sentinelos
EnvironmentFile=/opt/sentinelos/.env
ExecStart=/opt/sentinelos/venv/bin/python crowdstrike_connector.py \
    --config /etc/sentinelos/crowdstrike.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`CROWDSTRIKE_CLIENT_ID`/`CROWDSTRIKE_CLIENT_SECRET` in `.env` hold the
real OAuth2 credentials — create the API client in the Falcon console
(Support and resources → API clients and keys) with the "Detections:
Read" scope. Same `--once` cron alternative as `poll_connector.py`.

### Pushing from a webhook or forwarder

Point it at `POST https://sentinelos.internal.example.com/ingest/{source}`
with your `SENTINELOS_API_KEY` as a Bearer token. This is the integration
point for anything that can make an HTTP call: a SIEM's webhook/
notification action, a small relay script reading from a message queue,
etc.

Every path runs through the same rate-limit → dedup → correlation →
severity-prefilter gate before spending an LLM call — see README's
Architecture Overview and "Alert Correlation" section for exactly how
that decision is made, and `data/{tenant}/ingestion_log.jsonl` for a
record of every alert and what happened to it, including the ones that
never became an incident. Tune `SENTINELOS_INGEST_RATE_LIMIT_PER_MINUTE`
if your real alert volume needs a higher (or lower) ceiling than the
default 60/minute — this limiter is separate from
`SENTINELOS_RATE_LIMIT_PER_MINUTE` (the API layer's own limit on
manually-created incidents) and is what actually protects
`syslog_listener.py`/`poll_connector.py`, which never touch the API.

---

## 7. Get notified instead of watching the dashboard

Set one line in `.env` and SentinelOS sends a webhook POST whenever an
incident reaches `pending_approval` or crosses a severity threshold:

```env
SENTINELOS_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
SENTINELOS_ALERT_MIN_SEVERITY=high
SENTINELOS_DASHBOARD_BASE_URL=https://sentinelos.internal.example.com
```

No vendor is hardcoded — this works with Slack, Discord, and Microsoft
Teams incoming webhooks (they all render the payload's `"text"` field
with no setup), PagerDuty's Events API, or your own relay script that
does something more specific (page on-call, open a ticket, etc.) with
the structured fields in the payload (`severity`, `status`, `thread_id`,
`tenant_id`). `SENTINELOS_DASHBOARD_BASE_URL` is optional — set it and
every notification includes a direct link back to the incident.

If your relay script needs to verify a notification genuinely came from
this instance (rather than anyone who obtained the webhook URL), also
set `SENTINELOS_WEBHOOK_SIGNING_SECRET` — every request then carries an
`X-SentinelOS-Signature: sha256=<hex>` header, an HMAC-SHA256 of the raw
request body. Slack/Discord/Teams ignore headers they don't check, so
enabling this never breaks them.

This requires no separate process — it's called synchronously from
inside the pipeline (`notifications.pipeline.notify_if_needed`) right
after an incident is persisted, and a webhook failure never blocks or
fails the incident itself; it's swallowed and printed nowhere by
default, so if notifications seem to have silently stopped, test the URL
directly with `curl -X POST -d '{"text":"test"}' -H "Content-Type:
application/json" "$SENTINELOS_ALERT_WEBHOOK_URL"` rather than assuming
the pipeline is broken.

---

## 8. Enable real remediation execution (opt-in, sandboxed)

By default, an approved proposed action stays exactly what it's always
been: data (action/target/rationale) an analyst reads, not something
SentinelOS acts on. `remediation/` (see README's "Remediation" section
for the full design) can go one step further — POSTing an already-
approved, eligible action to your own webhook so your own SOAR
platform, firewall API gateway, or custom script can actually carry it
out. SentinelOS never runs a local command or calls one specific
vendor's API itself; it only ever asks whatever's on the other end of
this webhook.

**Two independent switches, both required, plus a literal sandbox mode:**

```env
SENTINELOS_REMEDIATION_ENABLED=true
SENTINELOS_REMEDIATION_ACTION_TYPES=block_ip,isolate_host
SENTINELOS_REMEDIATION_WEBHOOK_URL=https://your-soar.internal.example.com/hooks/sentinelos
SENTINELOS_REMEDIATION_WEBHOOK_SIGNING_SECRET=a-different-secret-than-the-alert-webhook
# Leave this at its default (true) until you've confirmed the wiring below.
SENTINELOS_REMEDIATION_DRY_RUN=true
```

**Verify the wiring before it's live.** With `SENTINELOS_REMEDIATION_DRY_RUN=true` (the default whenever `SENTINELOS_REMEDIATION_ENABLED` is set at all), nothing is ever sent over the network — approve a test incident's eligible action and check `data/{tenant}/remediation_log.jsonl` for a `"outcome": "dry_run"` record showing exactly what *would* have been sent, and the incident's audit log for the matching `Remediation -> ...` line. Only once that looks right should you set `SENTINELOS_REMEDIATION_DRY_RUN=false` to actually start sending requests.

`action_type` is the Responder Agent's own structured classification of what it proposed (`block_ip`/`isolate_host`/`disable_account`/`reset_credentials`/`other`) — not guessed from the free-text action description afterward. `SENTINELOS_REMEDIATION_ACTION_TYPES` is the allowlist of which of those are actually eligible for automated execution; `"other"` (the Responder's fallback when nothing cleaner fits) is never eligible no matter what you put here. The shipped default (`block_ip,isolate_host`) deliberately excludes `disable_account`/`reset_credentials` — those two typically need more receiver-side context (which identity system, what "reset" actually means there) than a firewall block does, so they're left as manual-approval-only categories until you've confirmed your receiver can handle them safely.

A broken or unreachable remediation receiver never blocks the approve call itself — the same "never block real processing" contract every other external call in this project follows — but the failure is real and visible: `executed: false` on the action, the failure detail in both the audit log and `remediation_log.jsonl`. Test the webhook directly the same way Section 7 recommends for the alert webhook if executions seem to be silently failing.

---

## 9. Back up the incident vault off-box

Your `OBSIDIAN_VAULT_PATH` is the durable, human-readable record of
every incident — worth a copy somewhere other than this one host.
`vault_backup.py` is a separate, interval-based process, deliberately
decoupled from the incident pipeline so a git/network failure here can
never slow down real alert processing.

Create a **private** repository first (GitHub, GitLab, self-hosted —
anywhere `git push` reaches), then:

```ini
[Unit]
Description=SentinelOS vault backup
After=network.target

[Service]
Type=simple
User=sentinelos
WorkingDirectory=/opt/sentinelos
EnvironmentFile=/opt/sentinelos/.env
ExecStart=/opt/sentinelos/venv/bin/python vault_backup.py \
    --remote git@github.com:you/your-private-vault-repo.git \
    --interval-seconds 300
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now sentinelos-vault-backup
```

Authentication is entirely your own git setup's responsibility — an SSH
key already loaded for the `sentinelos` user (`sudo -u sentinelos
ssh-keygen`, then add the public key as a GitHub/GitLab deploy key with
write access), an HTTPS token embedded in the remote URL, or a
credential helper. `vault_backup.py` never stores or manages a
credential itself.

**The destination repository must be private.** It will contain real
incident descriptions, IOCs, and affected-asset names from your actual
environment — this is not optional, and the script cannot enforce it
for you.

Prefer a cron job over a long-running service? `--once` backs up a
single time and exits, so cron (or a systemd timer) can own the
schedule instead of `--interval-seconds`.

---

## 10. Persistent data and backups

Everything SentinelOS knows lives in three places — back all three up
together, since a per-tenant incident's checkpoint, vector memory, and
vault report are meant to stay in sync:

| Path (via env var)     | What's in it                                                          |
|-------------------------|------------------------------------------------------------------------|
| `SENTINELOS_DATA_DIR`   | Per-tenant SQLite: incident checkpoints (`sentinelos.db`), the dashboard/correlation index (`incident_index.db`), `ingestion_log.jsonl`, `audit_chain_ledger.jsonl`, `remediation_log.jsonl`, polling-connector cursor state (`poller_state/`); tenant-independent `auth_failures.jsonl` at the root |
| `CHROMA_PERSIST_DIR`    | Per-tenant ChromaDB collections — long-term incident memory used for recall |
| `OBSIDIAN_VAULT_PATH`   | Markdown incident/hunt reports with wikilinks — the durable, human-readable audit trail |

These are plain files and SQLite databases — a straightforward
file-level backup (`rsync`, your existing backup tool, a nightly
snapshot) covers all of it. SQLite files are safe to copy while idle;
for a live system, prefer a backup window during low alert volume, or
use `sqlite3 <file> ".backup <dest>"` per database if you need a
guaranteed-consistent copy while the service is running.

The JSONL logs above (`ingestion_log.jsonl`, `audit_chain_ledger.jsonl`,
`remediation_log.jsonl`, `auth_failures.jsonl`) rotate automatically once they cross
`SENTINELOS_LOG_MAX_BYTES` (default 10MB), keeping up to
`SENTINELOS_LOG_BACKUP_COUNT` (default 3) old copies as `.1`, `.2`, etc.
— back those up too if you rely on historical ingestion/audit data
beyond what's in the active file.

Treat this data as sensitive: it contains real IOCs, real incident
descriptions, and real affected-asset names from your environment.

### Restoring from backup

A backup nobody has ever restored from is a hypothesis, not a plan —
these exact steps were rehearsed end-to-end (real backup, real deleted
data, real restore, real integrity check) before being written down.

**The Obsidian vault (from `vault_backup.py`'s git remote):**

```bash
git clone --branch main git@github.com:you/your-vault-repo.git /var/lib/sentinelos/vault
```

**Use `--branch main` explicitly — don't just `git clone <remote>`.**
Rehearsing this caught a real gotcha: a bare remote's default branch is
still whatever `git init --bare` picked (often `master`) even after
`vault_backup.py` has been pushing to `main` all along, since a push
updates the `main` ref but never the remote's own default-branch
pointer. A plain `git clone` follows that stale default, finds no
`master` branch, and silently checks out an **empty** directory — no
error, just no files. `--branch main` (matching whatever `--branch` you
actually run `vault_backup.py` with) sidesteps this entirely. If you've
already cloned without it and got nothing, `git checkout main` in that
same directory recovers it — no need to re-clone.

**The SQLite databases (`SENTINELOS_DATA_DIR`) and ChromaDB
(`CHROMA_PERSIST_DIR`), from an `rsync`/snapshot or a `sqlite3 .backup`
file:** both are just files — restoring is copying them back to where
`SENTINELOS_DATA_DIR`/`CHROMA_PERSIST_DIR` point, with the service
stopped:

```bash
sudo systemctl stop sentinelos-api sentinelos-ingest-* sentinelos-vault-backup
cp /path/to/your/backup/incident_index.db  /var/lib/sentinelos/data/<tenant>/incident_index.db
cp /path/to/your/backup/sentinelos.db      /var/lib/sentinelos/data/<tenant>/sentinelos.db
# ...same for CHROMA_PERSIST_DIR's per-tenant collection directories
sudo systemctl start sentinelos-api sentinelos-ingest-* sentinelos-vault-backup
```

A `sqlite3 <file> ".backup <dest>"` output file *is* a complete,
standalone database — there's no separate "restore" command, copying it
back over the original path is the whole operation. Verify a restored
database is actually intact before trusting it:

```bash
sqlite3 /var/lib/sentinelos/data/<tenant>/incident_index.db "PRAGMA integrity_check;"
# expect: ok
```

After restoring, confirm the app actually sees the data —
`python cli.py --tenant <tenant> show <a-known-thread-id>` should return
the real incident, not a 404.

---

## 11. Security hardening checklist

Everything here is already discussed in more depth in README's Security
Notes — this is the short, do-it-before-go-live version:

- [ ] `SENTINELOS_API_KEY` is set to a real random value, not left unset.
- [ ] If more than one tenant runs on this deployment and they shouldn't
      see each other's incidents: each tenant that needs real isolation
      has its own entry in `SENTINELOS_TENANT_API_KEYS`. Without this,
      the single `SENTINELOS_API_KEY` authorizes every tenant — fine for
      one trusted operator organizing their own data, not a boundary
      between organizations.
- [ ] The service binds to `127.0.0.1`; only the reverse proxy is
      reachable from outside the host.
- [ ] TLS is terminated at the reverse proxy; the hostname is
      internal/VPN-only, not public DNS.
- [ ] `.env` is `chmod 600` and owned by the service user, never
      committed to version control (the shipped `.gitignore` already
      excludes it).
- [ ] The service runs as a dedicated non-root user (`sentinelos` above),
      not root and not your own login user.
- [ ] Exactly one `uvicorn` process — no `--workers`, no multiple
      replicas — unless `SENTINELOS_REDIS_URL` is set, in which case
      multiple workers/replicas are safe for rate limiting and dedup
      (see Section 4; correlation has its own, separate multi-host
      caveat there regardless of Redis).
- [ ] Backups of `SENTINELOS_DATA_DIR` / `CHROMA_PERSIST_DIR` /
      `OBSIDIAN_VAULT_PATH` are actually running, not just planned —
      **and you've actually restored from one at least once** (see
      "Restoring from backup" in Section 10). An untested backup is a
      hypothesis.
- [ ] Whoever gets the analyst-dashboard API key understands it's a
      `localStorage`-held bearer token, not a per-user login — treat
      dashboard access like SSH key access, not like a website password.
- [ ] Analysts know to set their name (dashboard's "Analyst name" field,
      the CLI's `--by`, or `SENTINELOS_ANALYST_NAME`) before approving or
      denying — otherwise the audit trail honestly records that decision
      as "unspecified" rather than attributing it to anyone. This is a
      typed label, not a login; it doesn't stop anyone from typing the
      wrong name.
- [ ] If `syslog_listener.py` is running: it's bound to a specific
      management-network interface (not `0.0.0.0` on a general-purpose
      host), and `--allow-from` is set to the real CIDR range your
      syslog senders live on. Plain UDP/TCP syslog has no built-in
      authentication or encryption — that's inherent to the protocol,
      not a missing setting. If a sender can speak TLS, prefer
      `--tls-cert`/`--tls-key` (see "Syslog over TLS" above) over relying
      on network position alone; if it can't, use the `stunnel`/VPN
      recipe there instead of exposing plaintext syslog beyond a link
      you already trust.
- [ ] If `poll_connector.py` is running: its config file lives outside
      the repo checkout (or is at least gitignored), and its
      `auth_token_env` variable is set in `.env`/the service's
      `EnvironmentFile`, never written into the config file itself.
- [ ] If `SENTINELOS_ALERT_WEBHOOK_URL` is set: the destination (Slack
      workspace, relay endpoint, etc.) is one you'd trust with real
      incident descriptions and severities, since that's what the
      payload contains.
- [ ] If `vault_backup.py` is running: its destination git repository is
      **private** — it will contain real incident data, and the script
      cannot enforce this for you — and the git credential it uses
      (SSH key / token) has write access to that repo only, not broader
      access than it needs.
- [ ] Installed from `requirements.lock.txt`, not `requirements.txt` —
      a production host shouldn't resolve dependency versions fresh on
      every install.
- [ ] If `SENTINELOS_ALERT_WEBHOOK_URL` is set and the receiver supports
      it: `SENTINELOS_WEBHOOK_SIGNING_SECRET` is also set, so a forged
      notification (from anyone who obtains the webhook URL) can be told
      apart from a real one.
- [ ] If `SENTINELOS_REMEDIATION_ENABLED=true`: you've confirmed the
      wiring under `SENTINELOS_REMEDIATION_DRY_RUN=true` first (Section 8)
      before setting it to `false`, `SENTINELOS_REMEDIATION_ACTION_TYPES`
      only lists categories your receiver actually knows how to act on
      safely, and — if the receiver supports it —
      `SENTINELOS_REMEDIATION_WEBHOOK_SIGNING_SECRET` is set to a value
      different from `SENTINELOS_WEBHOOK_SIGNING_SECRET` (a remediation
      receiver is a more sensitive trust boundary than a notification
      channel and may reasonably be a different system entirely).

---

## 12. Known limitations to plan around

Pulled forward from README's Known Gaps section because they specifically
affect a live deployment decision, not just a feature-completeness one:

- **Local models are genuinely slow on modest hardware.** During this
  project's own development, a full 4-agent incident run against a local
  Ollama model took anywhere from ~12 to ~14 minutes on a shared,
  loaded sandbox — this is a real, measured number, not a worst case.
  If you need fast turnaround and are running Ollama, budget for a real
  GPU host, or use a hosted API provider for anything response-time
  sensitive.
- **Rate limiting and dedup are single-process, in-memory state by
  default — but a real Redis-backed alternative exists now.** Set
  `SENTINELOS_REDIS_URL` (Section 4) and both become genuinely shared
  across multiple `uvicorn` workers/replicas, live-verified with two
  independent processes. Unconfigured, the original limitation still
  applies exactly as before: fine for one process, doesn't survive a
  restart, doesn't work correctly across multiple processes/replicas.
  **Correlation was never actually in-memory state** — its candidate
  pool reads from a durable SQLite file already shared correctly across
  multiple workers on one host; its own remaining limitation is
  multi-*host* replicas without shared storage, unrelated to Redis (see
  Section 4 for why Redis isn't the right tool for that specific gap).
- **No per-user accounts.** Multi-tenancy isolates *organizations* from
  each other, not individual analysts within one tenant. Within a
  tenant, the dashboard's auth is one shared key for everyone using it.
- **Cross-tenant authorization needs its own configuration step.**
  `SENTINELOS_TENANT_API_KEYS` lets each tenant require its own key —
  set it for every tenant you actually need isolated from the others.
  Skip it and `SENTINELOS_API_KEY` alone still authorizes every tenant,
  same as before this was added; storage isolation (separate DB/vault/
  vector-store per tenant) is unconditional, but authorization isolation
  is opt-in.
- **Correlation catches exact matches, IP subnets, domain families, and
  (opt-in) an LLM-judged shared-technique case — not every real campaign
  pattern.** The semantic tier can connect a shared-TTP/no-shared-IOC
  pair, but live testing showed it's deliberately conservative: it
  declined a real same-technique/different-host pair on the grounds that
  "technique similarity alone is insufficient to confirm a shared
  campaign." A renamed host with a wholly unrelated new name still won't
  correlate at all. See README's Known Gaps for the full picture,
  including a string-similarity signal that was built, tested, and
  rejected for making things worse, not just noisier.
- **No vendor-specific SIEM/EDR polling client for most vendors — but a
  real, generic one, and real ones for Wazuh, Splunk, and CrowdStrike
  specifically.** `poll_connector.py`/`ingestion/polling.py` polls any
  JSON-returning REST API given a config describing that API's shape
  (auth, pagination cursor, field-mapping, or a registered normalizer for
  a materially different scheme) — see Section 6 above. There's still no
  ready-made config for most other vendors (Sentinel, Elastic, etc.);
  you write the field-mapping for your own instance's actual API shape
  once, not code. Wazuh, Splunk, and CrowdStrike are the three
  exceptions with purpose-built normalizers (and, for CrowdStrike, a
  fully dedicated connector for its OAuth2 + two-step Detects API) — but
  none of the three is verified against a live vendor instance, since
  this project has none of any of them; each is verified against a real
  local HTTP server matching that vendor's *documented* API shape
  instead. Test each against your own deployment before relying on it —
  a documented shape and a live one can diverge.
- **Real remediation execution exists (Section 8) but only reaches as
  far as your own webhook.** SentinelOS still never calls a firewall/
  EDR/IAM API directly, or runs a local command — an approved, eligible
  action is POSTed to an operator-configured receiver, off by default
  and dry-run by default even when enabled. Whatever real action
  actually happens is entirely up to what your receiver does with that
  request; this project has no way to verify that from here.
- **The audit trail's tamper-evidence detects, it doesn't prevent.**
  `utils/audit_chain.py` hash-chains each incident's `audit_log` into a
  per-tenant append-only ledger (`audit_chain_ledger.jsonl`) and
  `cli.py verify-audit`/`GET /incidents/{id}/verify-audit` will flag a
  `MISMATCH` if it's been altered since — live-verified against a real
  simulated tampering attempt. An attacker with the same filesystem
  access needed to edit `audit_log` in the first place could, in
  principle, also rewrite the ledger to match, since both live on the
  same host with no external immutable anchor backing them. Back the
  ledger up alongside `SENTINELOS_DATA_DIR` and treat a `MISMATCH` as a
  serious signal, not "no detected tampering" as an absolute guarantee.
- **"Air-gapped" doesn't extend to enrichment or alerting.** The
  dashboard's own assets have no CDN dependency, but `enrichment/`
  (AbuseIPDB/VirusTotal/Shodan) and `notifications/webhook.py` make real
  outbound HTTP calls whenever configured. A genuinely air-gapped
  deployment needs those left unconfigured, not just the dashboard.

None of this means "don't deploy it" — it means deploy it as what it
actually is: a real, tested incident-response assistant that watches
your logs and does the first-pass triage/investigation/response-drafting
work, with a human still making every consequential decision. That's the
project's stated goal, not a hedge.

---

## 13. Day-to-day operation

- **Dashboard**: `https://your-host/` — incident queue, detail view,
  approve/deny (enter an analyst name once in the top bar — it's
  recorded on every decision you make), a live-streaming "New Incident"
  form for anything that needs an analyst-initiated pipeline run, and a
  standalone Threat Hunt form.
- **CLI**, for scripting or SSH-only access:
  ```bash
  python cli.py new "<description>" --severity high --iocs 1.2.3.4 --stream
  python cli.py show <thread_id>
  python cli.py approve <thread_id> --by <your-name>
  python cli.py deny <thread_id> --by <your-name>
  python cli.py hunt "<question about a broader campaign>"
  ```
  Add `--tenant <id>` to any command to operate on a specific tenant
  instead of the default one. Set `SENTINELOS_ANALYST_NAME` in a
  personal shell profile (not the shared service `.env`) if the same
  person always runs the CLI, so `--by` isn't needed every time.
- **Logs to watch**: `journalctl -u sentinelos-api -f`,
  `journalctl -u sentinelos-ingest-<source> -f`, and
  `journalctl -u sentinelos-vault-backup -f` for service-level issues;
  `data/{tenant}/ingestion_log.jsonl` for what happened to every ingested
  alert (promoted / correlated / suppressed / deduped / rate-limited), so
  "continuous monitoring" never quietly means "continuously ignored."
- **Alerting**: if `SENTINELOS_ALERT_WEBHOOK_URL` is set, high/critical
  incidents and anything reaching `pending_approval` show up there too —
  you shouldn't need to keep the dashboard open just to notice something
  needs attention.

---

## 14. Upgrading

```bash
sudo systemctl stop sentinelos-api sentinelos-ingest-*
cd /opt/sentinelos
git pull
source venv/bin/activate
pip install -r requirements.lock.txt
pytest   # confirm the upgrade didn't break anything before restarting
sudo systemctl start sentinelos-api sentinelos-ingest-*
```

Back up `SENTINELOS_DATA_DIR` before upgrading. The incident-index
schema migrates itself in place (an idempotent `ALTER TABLE` in
`utils/incident_index.py`), so no manual migration step is expected, but
a backup costs a minute and a bad one costs a lot more.

---

## 15. Troubleshooting

- **`/health` doesn't respond**: check `journalctl -u sentinelos-api -e`
  for a Python traceback — usually a missing/misconfigured provider
  variable in `.env`, or the venv path in the systemd unit not matching
  where you actually installed it.
- **A pipeline run never seems to finish**: if you're on Ollama, check
  whether the model process itself is actually consuming CPU (`top` /
  `htop`) — a genuine run can take minutes; a truly hung one shows zero
  CPU activity. `python cli.py show <thread_id>` shows the incident's
  current status without waiting for the stream.
- **The dashboard loads but every action 401s**: `SENTINELOS_API_KEY` is
  set server-side but the dashboard's own API Key field (top bar) is
  empty or wrong — it's a separate, client-side value you enter once
  and it's kept in the browser's `localStorage`.
- **SSE stream cuts off partway through a long run**: your reverse proxy
  is buffering or timing out the response — revisit Section 5.
- **Approve/deny decisions show up as "unspecified" in the audit log**:
  no `--by`, no `SENTINELOS_ANALYST_NAME`, and no dashboard "Analyst
  name" value was set at the time of the decision — this is recorded
  honestly rather than silently attributed to anyone; set one of those
  going forward.
- **Webhook notifications never arrive**: `notify_if_needed` swallows
  failures by design so a broken webhook can't break incident
  processing — test the URL directly (see Section 7) rather than
  assuming the pipeline itself is broken. Also confirm the incident
  actually met a trigger condition (`pending_approval`, or severity at/
  above `SENTINELOS_ALERT_MIN_SEVERITY`) — most other status changes
  intentionally don't notify.
- **`vault_backup.py` commits locally but never pushes**: check its
  service logs (`journalctl -u sentinelos-vault-backup -e`) for the git
  push error — almost always an SSH key that isn't loaded for the
  `sentinelos` user, or a deploy key without write access. The commit
  itself still succeeded and isn't lost; fix the credential and the next
  interval's push will include it.
