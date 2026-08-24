# SentinelOS

**A cybersecurity-focused agentic AI operating system for Security Operations Centers (SOCs).**

SentinelOS is a central intelligence layer that orchestrates specialized AI agents to help SOC teams triage alerts, investigate incidents, hunt threats, and coordinate response — with persistent memory, durable Markdown audit trails in an Obsidian vault, full multi-tenant isolation, and a human-in-the-loop approval gate for anything that touches production systems.

**New here?** **[GETTING_STARTED.md](GETTING_STARTED.md)** is a no-assumptions walkthrough — clone, run, click Approve on your first incident, in about ten minutes. This README is the full architecture/feature reference. Don't recognize a term? **[GLOSSARY.md](GLOSSARY.md)**. Running this as a real, always-on service — systemd units, TLS, backups, an honest checklist of what to know first — is **[DEPLOYMENT.md](DEPLOYMENT.md)**.

Licensed under [Apache 2.0](LICENSE).

---

## Features

- **An analyst-facing web dashboard, not just a CLI/API.** Open `http://localhost:8000/` for a single-page, no-build-step HTML/CSS/JS UI (served from `static/`, works fully offline — no CDN dependencies, no custom web fonts) with an incident queue, live agent findings, threat-intel/ATT&CK sections, one-click approve/deny with an attributed analyst name, a live-streaming "new incident" form, and a standalone threat-hunt form — styled as a deliberate dark "neural core console," not a default admin-panel template (see Design Lineage). A summary stats bar (total/open/pending-approval/by-severity, computed server-side so it stays correct beyond one page of results), server-side search/severity/status filtering, and `j`/`k`/`Enter`/`a`/`d`/`/` keyboard shortcuts round it out for an analyst living in the queue all day. A connected-timeline view for the audit log, bulk approve/deny across multiple selected incidents at once, a standalone "IOC Lookup" tab for checking an indicator's reputation without creating an incident, and a dismissible first-visit onboarding banner cover the rest.
- **Real threat-intel evidence, not just LLM recall.** `enrichment/` calls AbuseIPDB and VirusTotal for IP/domain/hash reputation and Shodan (opt-in, keyless) for exposed-port/known-CVE data on an incident's actual IOCs before Triage reasons about severity, and validates any MITRE ATT&CK technique ID against a local curated dataset — an invented or misremembered ID is flagged as unverified instead of silently trusted.
- **Continuous alert ingestion — four ways in, four real formats supported.** `ingestion/` normalizes real detection-tool output (Suricata/Zeek eve.json, Wazuh manager alerts, CEF syslog, generic JSON) into incidents automatically, with a rate limiter, dedup window, and severity prefilter in front of the expensive LLM pipeline. `ingest_watch.py` tails a log file; `syslog_listener.py` receives syslog directly over a real UDP/TCP socket; `poll_connector.py` pulls from any SIEM/EDR's REST API on an interval; `POST /ingest/{source}` accepts a push. See "Wazuh Integration" below for a concrete, non-generic example.
- **Alert correlation, not one incident per alert.** `ingestion/correlation.py` matches a new alert against open incidents by shared IOC/asset first, then — only if nothing matches exactly — two fuzzy signals grounded in real attacker behavior (same `/24` subnet, same registered/apex domain via the real Public Suffix List). A match folds new evidence into the existing incident instead of spawning a duplicate, without ever re-invoking the agent pipeline. See "Alert Correlation" below.
- **A third, opt-in correlation tier for genuine campaign matching an IOC can't catch.** `ingestion/semantic_correlation.py` spends one LLM judgment call to ask whether a new alert belongs to the same campaign as an open incident despite sharing no IOC/subnet/domain at all. Deliberately conservative — see Known Gaps for what it still won't catch.
- **A real four-agent incident-response pipeline.** Triage → Investigator → (optional) Threat Hunter → Responder, via [LangGraph](https://github.com/langchain-ai/langgraph). Each agent's routing decision is read from a typed, structured LLM output, never guessed from keyword substrings.
- **Human-in-the-loop by design, structurally enforced.** The Responder Agent only ever *proposes* remediation actions. Nothing executes until a human runs `python cli.py approve <id>` (or the dashboard/API equivalent) — and the decision is attributed to a named analyst (`approved_by`), not a generic "Human Reviewer." The schema the LLM's output is parsed into has no `approved` field to smuggle a value into in the first place; see Security Notes.
- **A permanent prompt-injection regression test, not a one-off manual check.** `tests/test_prompt_injection_regression.py` runs on every test invocation (a fast structural check that the approval field can't be set from LLM output) plus an optional slow live test against a real configured model, so this guarantee can't silently regress as the codebase changes.
- **Alerting, so you don't have to keep checking the dashboard.** `notifications/` sends a webhook POST whenever an incident needs approval or crosses a configurable severity threshold — works natively with Slack, Discord, Microsoft Teams, and PagerDuty webhooks, or your own relay. Opt-in: unset, nothing is ever sent.
- **A durable, off-box backup of your incident vault.** `vault_backup.py` commits and pushes your entire Obsidian vault to a git remote of your choice on an interval — decoupled from the incident pipeline so a git/network failure can never slow down real alert processing.
- **Multi-tenant, with full isolation.** Every tenant gets its own SQLite checkpoint DB, ChromaDB collection, and Obsidian vault subfolder — not a shared store with a tenant column. `--tenant <id>` on the CLI, `/tenants/{tenant_id}/...` on the API.
- **Durable, on-disk checkpointing.** Incident state is persisted via `langgraph-checkpoint-sqlite`, so an incident survives a process restart. A `thread_id` (the incident ID) resumes exactly where it left off.
- **Long-term memory via ChromaDB.** Every handled incident is embedded and stored per tenant; new incidents recall similar past ones for context.
- **Token usage tracked per incident, per agent.** Every structured LLM call's usage is captured (including failed/retried attempts) and surfaced in the vault report, CLI, and API.
- **A live streaming view.** `POST /incidents/stream` (SSE) or `cli.py new --stream` shows each agent's finding as it completes instead of only the final result.
- **Obsidian vault as the structured logging layer.** Every pipeline run and every approve/deny decision writes/updates a Markdown incident report with YAML frontmatter, plus auto-created stub notes per IOC/asset that backlink to it.
- **Two independent rate limiters, plus API key auth.** Optional `SENTINELOS_API_KEY` bearer auth on every route except `/health`; a per-tenant, per-client sliding-window limiter on the API's LLM-triggering endpoints, and a *second*, separate limiter inside the shared ingestion gate itself so `syslog_listener.py`/`poll_connector.py` (which never touch the API layer) are protected too.
- **Pluggable LLM provider.** Groq by default (free tier), with OpenAI, Anthropic, Google AI Studio (Gemini), and locally-hosted Ollama models all supported as fallbacks, selected automatically by whichever is configured.
- **Three interfaces to the same pipeline.** A quick demo script (`main.py`), a full CLI (`cli.py`), and a REST API (`api.py`) — all built on one shared orchestration module (`workflows/incident_pipeline.py`).
- **Pydantic-typed state** (`Incident`, `ProposedAction`, `SentinelState`) throughout, with `Literal`-constrained severity/status and length-capped free-text fields.

Every claim above with a live/verified component is backed by an actual run against real I/O (real sockets, real HTTP servers, a real local LLM) — see **Testing** below for exactly what was run and what it found, including the honest misses.

---

## Quick Start

New to this project? **[GETTING_STARTED.md](GETTING_STARTED.md)** covers the same ground with more hand-holding. This section assumes you're comfortable with a terminal.

### 1. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure a provider

```bash
cp .env.example .env
```

Edit `.env` and configure at least one:

```env
GROQ_API_KEY=gsk_your_groq_key_here          # preferred — free tier
OPENAI_API_KEY=sk-your_openai_key_here       # fallback
ANTHROPIC_API_KEY=sk-ant-your_key_here       # fallback
GOOGLE_API_KEY=your_google_ai_studio_key     # fallback
OLLAMA_MODEL=                                # fallback — local, no API key
OLLAMA_BASE_URL=http://localhost:11434
```

Selection order in `utils/llm.py`: Groq → OpenAI → Anthropic → Google AI Studio (Gemini) → Ollama — whichever is configured first. Get a free Groq key at [console.groq.com](https://console.groq.com), a free Google AI Studio key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey), or use an existing OpenAI/Anthropic key.

**Using a local model instead (Ollama):** no API key needed — [install Ollama](https://ollama.com), run `ollama pull llama3.1` (or any tool-calling-capable model), make sure `ollama serve` is running, then set `OLLAMA_MODEL=llama3.1` in `.env` and leave the cloud keys blank.

### 4. Run the demo

```bash
python main.py
```

Runs a sample incident (a brute-force login alert against a Domain Controller) through the full pipeline and prints every agent's findings, token usage, the audit log, and confirms the Obsidian vault report was written. If the pipeline reaches the Responder Agent, it prints the `cli.py approve`/`deny` command needed to resolve it.

### 5. Use the CLI for real incidents

```bash
python cli.py new "Multiple failed logins from 1.2.3.4 targeting DC-01" \
  --severity high --assets DC-01 --iocs 1.2.3.4 --source SIEM

python cli.py show <incident_id>
python cli.py approve <incident_id> --by j.smith   # or: deny
python cli.py hunt "any signs of a broader credential-stuffing campaign?"
python cli.py verify-audit <incident_id>   # tamper-evidence check — see Security Notes

# Live view — print each agent's finding as it completes:
python cli.py new "Suspicious login from 1.2.3.4" --stream

# Multi-tenant — scope everything to a specific org (goes before the subcommand):
python cli.py --tenant acme-corp new "Suspicious login from 1.2.3.4"
python cli.py --tenant acme-corp show <incident_id>
```

`--by` records who made an approve/deny call in the audit trail (`approved_by`). Omit it and set `SENTINELOS_ANALYST_NAME` in `.env` instead if the same person runs the CLI every time; omit both and the decision is recorded as "unspecified" — visible in the audit log, not silently attributed to anyone.

### 6. Or run the API — and the dashboard

```bash
uvicorn api:api --reload
```

Open **http://localhost:8000/** for the analyst dashboard — an incident queue, live-streaming new-incident form, threat-hunt form, and one-click approve/deny, with no separate frontend build step. Set the tenant, an analyst name (recorded on every approve/deny), and (if `SENTINELOS_API_KEY` is configured) an API key in the top bar.

The underlying REST API the dashboard uses:

- `GET /incidents` — list incident summaries (what the dashboard's queue reads)
- `POST /incidents` — submit a new incident, runs the full pipeline synchronously
- `POST /incidents/stream` — same, but streamed as Server-Sent Events (one event per agent step)
- `GET /incidents/{id}` — read current state
- `GET /incidents?search=&severity=&status=` — the same list route accepts optional filters, evaluated in SQL against the full index, not just whatever page of rows is returned
- `GET /incidents/stats` — aggregate counts (total/open/pending-approval/by-severity) for the dashboard's summary bar, computed the same way — real `COUNT()`s, not paginated-row math
- `GET /incidents/{id}/verify-audit` — tamper-evidence check against the audit chain ledger (see Security Notes)
- `POST /incidents/{id}/approve` / `POST /incidents/{id}/deny` — resolve pending Responder actions (optional JSON body: `{"approved_by": "j.smith"}`)
- `POST /hunts` — standalone threat hunt
- `POST /enrichment/lookup` — real threat-intel lookups on demand (`{"iocs": [...]}`), with no incident created; calls the exact same `enrich_iocs()` the pipeline uses internally
- `/tenants/{tenant_id}/...` — the same routes, explicitly scoped to a tenant instead of the `default` one

Set `SENTINELOS_API_KEY` to require `Authorization: Bearer <key>` on every data route except `/health`, `/`, and `/static/*` (the dashboard's HTML/CSS/JS shell contains no incident data — only its own fetch calls to the protected routes need the key, entered client-side). Set `SENTINELOS_RATE_LIMIT_PER_MINUTE` (default 10, `0` disables) to cap incident/hunt creation per client per tenant.

### 7. Open the Obsidian vault

Point Obsidian at `obsidian_vault/default/` (or `obsidian_vault/<your-tenant-id>/`) to browse incident reports, hunt reports, and the auto-generated Asset/IOC notes with full backlinks and graph view.

### 8. Continuous monitoring — feed it real alerts instead of typing them

Four ways in — pick whichever matches what you actually have:

```bash
# Tail a Suricata/Zeek-style JSON-lines alert log continuously:
python ingest_watch.py --path /var/log/suricata/eve.json --source suricata

# Or a Wazuh manager's own alert log — same tailing mechanism:
python ingest_watch.py --path /var/ossec/logs/alerts/alerts.json --source wazuh

# Receive syslog directly over the network instead of tailing a file
# (binds to 127.0.0.1 by default — see Security Notes before exposing
# this beyond a trusted management network):
python syslog_listener.py --protocol udp --port 5514 --source syslog_cef

# Poll your own SIEM/EDR's REST API on an interval — no vendor-specific
# code, just a JSON config describing that API's shape:
python poll_connector.py --config examples/poller_config.example.json

# Or push a single alert (from a webhook, script, or any tool that can POST):
curl -X POST http://localhost:8000/ingest/generic \
  -H "Content-Type: application/json" \
  -d '{"description": "Failed logins from 1.2.3.4", "severity": "high", "iocs": ["1.2.3.4"]}'
```

Every ingested alert — however it arrives — is normalized, rate-limited, deduped against recent identical alerts, checked for correlation against your already-open incidents, and filtered against `SENTINELOS_INGEST_MIN_SEVERITY` before spending an LLM call — anything below the threshold, rate-limited, or already seen is logged to `data/{tenant}/ingestion_log.jsonl`, not silently dropped. See Architecture Overview below for how to add a normalizer for your own alert source, or a polling connector config for your own SIEM/EDR.

### 9. Get notified instead of watching the dashboard

```env
SENTINELOS_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
SENTINELOS_ALERT_MIN_SEVERITY=high    # default; fires regardless of status at/above this
```

Set once in `.env`, and every incident that reaches `pending_approval` (a human needs to act now) or crosses this severity, regardless of status, sends a webhook POST. Unset, nothing is ever sent. See **Alerting** below for the payload shape and exactly which pipeline events trigger it.

### 10. Back up your incident vault off-box

```bash
python vault_backup.py --remote git@github.com:you/your-private-vault-repo.git
```

Commits and pushes your whole `OBSIDIAN_VAULT_PATH` on a 5-minute interval by default (`--interval-seconds` to change it, `--once` for cron, `--no-push` to try it locally first). **The destination repo must be private** — it will contain real incident data. See **Vault Backup** below.

---

## Architecture Overview

```
main.py                       Quick demo entry point (one hardcoded incident)
cli.py                        Full CLI: new [--stream] / show / approve [--by] / deny [--by] / hunt, --tenant
api.py                        FastAPI layer: auth, rate limiting, SSE streaming, tenant routing
graph.py                      LangGraph StateGraph + get_app(tenant_id): one compiled graph & SQLite DB per tenant
workflows/incident_pipeline.py  Shared, tenant-aware orchestration used by all three interfaces
state.py                      Pydantic/TypedDict state shared across all agents
agents/
  schemas.py                  Structured-output Pydantic schemas (one per agent)
  triage_agent.py              Assesses severity; escalate or close
  investigator_agent.py        Root-cause analysis; hunt, respond, or close
  threat_hunter_agent.py       Looks for a broader campaign; respond or close
  responder_agent.py           Proposes remediation actions — never executes
memory/vector_store.py        ChromaDB long-term incident memory, one collection per tenant
enrichment/
  schemas.py                  EnrichmentResult — what every provider lookup produces
  ioc_classifier.py            Classifies an IOC string as ip/domain/hash/unknown before spending an API call
  providers.py                 Real AbuseIPDB + VirusTotal + Shodan (opt-in, keyless) lookups, cached,
                               graceful no-key/disabled/error handling
  pipeline.py                  enrich_iocs() — classify then look up, capped per incident
  mitre_attack.py               Curated offline ATT&CK technique dataset; flags hallucinated technique IDs
ingestion/
  schemas.py                  NormalizedAlert — what every source normalizer produces
  normalizers.py               One function per alert source (generic, suricata, wazuh, syslog_cef) + registry
  correlation.py                Matches a new alert against open incidents: exact IOC/asset overlap,
                               then subnet/domain-family fuzzy signals if nothing matched exactly
  semantic_correlation.py       Opt-in third tier: one real LLM judgment call for a campaign match
                               with no shared IOC/subnet/domain at all — see Alert Correlation below
  pipeline.py                  ingest_alert() / ingest_normalized_alert(): rate limit -> dedup ->
                               correlate -> severity floor -> correlate -> promote gate
  polling.py                  Generic REST/JSON SIEM/EDR poller: PollerConfig, field-mapping,
                               cursor-based incremental fetch — see poll_connector.py / examples/
ingest_watch.py                Tails a JSON-lines alert log continuously and feeds it into the ingestion pipeline
syslog_listener.py             Real UDP/TCP network listener for syslog (optionally CEF) messages —
                               see Security Notes before exposing beyond a trusted network
poll_connector.py              CLI entrypoint for ingestion/polling.py — poll a SIEM/EDR's API
                               on an interval, or once for cron-style use (--once)
examples/poller_config.example.json   Annotated poller config to copy and adapt to your API
examples/wazuh_integration.py         Wazuh custom-integration script — pushes an alert to /ingest/wazuh
notifications/
  webhook.py                   Generic outbound webhook POST — no vendor hardcoded
  pipeline.py                   should_notify() / build_notification_payload() / notify_if_needed()
vault_backup.py                Commits and pushes the Obsidian vault to a git remote on an interval
utils/
  llm.py                      Provider selection + usage tracking (Groq → OpenAI → Anthropic → Google → Ollama)
  obsidian.py                 Markdown vault report generation with wikilinks, per-tenant vault root
  tenancy.py                  Tenant-id sanitization — the one place that decides what's safe as a path component
  rate_limit.py                In-process sliding-window limiter — shared by the API layer and the ingestion gate
  dedup.py                     In-process sliding-window alert deduplication
  incident_index.py            Lightweight per-tenant SQLite index of incident summaries (IOCs, assets,
                               verified ATT&CK technique) — backs the dashboard's queue and every
                               correlation tier's candidate lookup via list_open_incidents()
  audit_chain.py                Hash-chains each incident's audit_log into an append-only per-tenant
                               ledger; verify_incident_audit_log() detects tampering after the fact
  auth_monitor.py                Logs every failed API key attempt; alerts on a burst from one source
  log_rotation.py                Size-based rotation shared by the ingestion/auth-failure/audit-chain logs
static/                        The dashboard — vanilla HTML/CSS/JS, no build step, no CDN dependencies
  index.html                  Page shell: incident list/detail split view, new-incident + threat-hunt forms
  app.js                      All dashboard logic: fetch/SSE consumption, rendering, HTML-escaping
  style.css                   Dark theme, badges, layout
tests/                        pytest suite — see Testing below
requirements.txt              Floor-pinned (>=) dependencies — development installs
requirements.lock.txt         Exact-pinned dependency closure — use for production installs
```

**Pipeline flow:** every incident starts at **Triage**, which first runs `enrichment.enrich_iocs()` on the incident's IOCs (real AbuseIPDB/VirusTotal lookups, not LLM recall) and feeds the results into its own severity reasoning. Each agent's LLM call is forced through a structured output schema (`agents/schemas.py`) with a typed `decision` field — routing reads that field directly instead of pattern-matching free text. Triage escalates to **Investigator** or closes. Investigator and Threat Hunter may each cite a MITRE ATT&CK technique ID, which is validated against `enrichment/mitre_attack.py`'s local dataset and flagged if unrecognized. Investigator closes, escalates to **Threat Hunter** (broader-campaign suspicion), or straight to **Responder** (needs remediation now). Threat Hunter closes or escalates to **Responder**. **Responder always stops** — it proposes actions and sets the incident to `pending_approval`; nothing happens until a human calls `resolve_proposed_actions` (via `cli.py approve/deny` or the API), which also records who made the call (`approved_by`) and fires a webhook notification if none has already gone out for this update. Every run recalls similar past incidents from the tenant's ChromaDB collection before Triage runs, tracks token usage per agent, and writes/updates the incident's Obsidian vault note after every step, including the final approve/deny decision.

**Tenancy:** `tenant_id` is set once when an incident is created and flows through `SentinelState` to every agent node automatically (it's just another state field) — that's how tenant-scoped memory recall reaches code that only ever receives `state`, not an explicit argument. `graph.get_app(tenant_id)` lazily builds and caches one compiled graph (and one SQLite connection) per tenant; `memory.vector_store` and `utils.obsidian` do the same for their own per-tenant resources. `utils.tenancy.sanitize_tenant_id` is the single choke point that decides what a tenant_id is allowed to look like once it becomes a directory name — never trust it verbatim, since it can arrive directly from an API path segment.

### Adding a New Agent

1. Add a Pydantic schema for its structured output in `agents/schemas.py` with a `Literal` `decision` field.
2. Create `agents/<name>_agent.py` following the existing agents' shape: build a `ChatPromptTemplate`, call `get_llm().with_structured_output(YourSchema, include_raw=True)`, run it through `utils.llm.invoke_structured` to get `(parsed, usage)`, call `accumulate_usage(state, "<Name> Agent", usage)`, append a named message (`"name": "<Name> Agent"`) to `state["messages"]`, append to `state["audit_log"]`, set `state["next_agent"]` from the decision.
3. In `graph.py`, register the node and add it to the relevant `add_conditional_edges(...)` mapping (or a new one).
4. If it can propose actions, route it into `responder` rather than acting directly — never bypass the human approval gate.

### Adding an Ingestion Source

The deployment target for ingestion is intentionally kept open — four genuinely different formats (an already-shaped generic payload, Suricata's nested JSON, Wazuh's nested JSON, and flat-KV CEF) are wired in as proof the pattern is pluggable, not a bet on one vendor. To add your own:

1. Write a function in `ingestion/normalizers.py`: `def normalize_yourthing(payload: dict) -> Optional[NormalizedAlert]` — return `None` for anything that isn't alert-worthy (e.g. a non-alert event type), otherwise a `NormalizedAlert` (`ingestion/schemas.py`).
2. Register it in the `NORMALIZERS` dict at the bottom of that file, keyed by the source name you'll pass to `/ingest/{source}`.
3. That's it — `ingestion/pipeline.py`'s rate-limit/dedup/correlation/severity-prefilter/promote logic, the API routes, and `ingest_watch.py` (if your source is JSON-lines) all work automatically for any registered source, since they only ever read the generic `NormalizedAlert.iocs`/`affected_assets` fields, never anything vendor-specific.

### Syslog Listener and SIEM/EDR Polling Connectors

Two more ways in, both genuinely new mechanisms rather than variations on `ingest_watch.py`'s file-tailing:

- **`syslog_listener.py`** opens a real UDP or TCP socket and receives syslog (optionally CEF-formatted) messages directly over the network — no forwarder writing to a file first.
- **`poll_connector.py`** (backed by `ingestion/polling.py`) periodically calls a REST API and ingests whatever alerts it returns — the pull-based counterpart to `/ingest/{source}`'s push. It's deliberately generic rather than a Splunk/Sentinel/CrowdStrike-specific client, since every vendor's alert API has a different URL/auth/JSON shape. A `PollerConfig` (see `examples/poller_config.example.json`) describes *any* JSON-returning API — base URL, an auth header naming an environment variable to read the real token from (never the token itself), where in the response body the alert list lives, a field-mapping onto `NormalizedAlert`'s fields, and an optional cursor field/query-param for incremental polling.

A few design decisions worth knowing:

- **Every ingestion path shares the same gate, including rate limiting.** `syslog_listener.py`, `poll_connector.py`, `ingest_watch.py`, and `POST /ingest/{source}` all funnel through `ingest_normalized_alert()` in `ingestion/pipeline.py`, which checks a per-tenant rate limit (`SENTINELOS_INGEST_RATE_LIMIT_PER_MINUTE`, separate from the API layer's own limiter) *before* dedup/correlation — a flood of injected or noisy alerts costs at most a suppressed/rate-limited log line, not an LLM call, regardless of which door it came in through.
- **The syslog listener is genuinely new network-facing attack surface, and it's documented as such rather than downplayed.** Classic syslog (UDP or plain TCP) has no built-in authentication, encryption, or integrity protection — a UDP source IP is trivially spoofable. That's inherent to the protocol, not a gap in this implementation. It binds to `127.0.0.1` by default (the same "insecure exposure requires an explicit opt-in" default `api.py` uses for `SENTINELOS_API_KEY`), and `--allow-from <CIDR>` (repeatable) restricts accepted source IPs — see Security Notes and DEPLOYMENT.md.
- **The polling connector never writes a secret to disk.** `auth_token_env` in the config file names an environment variable; the actual token only ever lives in `.env` or the process environment, the same pattern every other provider/agent credential in this project already follows.
- **Cursor state is a small per-connector JSON file, not a database.** `SENTINELOS_DATA_DIR/{tenant}/poller_state/{name}.json` remembers the last-seen cursor value between polls (and between restarts) — deliberately as simple as `utils/incident_index.py`'s "small file, not a system" philosophy, since losing it just means the next poll re-fetches slightly more than strictly necessary (still deduped downstream), not a correctness failure.

### Wazuh Integration

A concrete, non-generic example of "Adding an Ingestion Source" above, since Wazuh is a genuinely common open-source SIEM/HIDS deployment target: `ingestion/normalizers.py:normalize_wazuh()` understands Wazuh's real alert JSON shape (`rule.level`/`rule.description`/`rule.mitre.id`, `agent.name`/`agent.id`, `data.srcip`/`data.dstip`/file hashes/URLs) directly — no generic-payload remapping needed. Two ways to feed it in:

1. **Tail the manager's alert log** — the same mechanism already used for Suricata: `python ingest_watch.py --path /var/ossec/logs/alerts/alerts.json --source wazuh`. Needs SentinelOS to have read access to that file (same host, a shared mount, or a log-shipping agent placing a copy where SentinelOS can read it).
2. **Push via a Wazuh custom integration** (`examples/wazuh_integration.py`) — Wazuh's own `<integration>` block in `ossec.conf` can call a script on every alert at/above a configured rule level; the example script forwards the alert JSON verbatim to `POST /ingest/wazuh`, since `normalize_wazuh()` already speaks that native shape. Use this if SentinelOS doesn't have (or shouldn't have) filesystem access to the Wazuh manager, or if you want Wazuh's own level-based prefiltering before anything reaches SentinelOS at all.

Wazuh's `rule.level` (a documented 0–15 scale) maps onto SentinelOS's four-tier severity the same way Suricata's own numeric scale does — a starting point Triage re-assesses from actual context, not a final answer. Live-verified: a realistic Wazuh alert (`rule.level: 10`, an ATT&CK-tagged brute-force rule, a source IP) run through the real, unmocked `ingest_alert()` correctly normalized to `severity: high` and promoted. The custom-integration script itself (`examples/wazuh_integration.py`) is verified against a real local HTTP server — its own argument-parsing, file-reading, and forwarding logic all work — but **not** against a live Wazuh manager, since this project has none to honestly test the `ossec.conf` wiring against; treat the exact integration-script contract as documentation-derived until you've confirmed it against your own Wazuh version.

### Alert Correlation

`utils/dedup.py` and `ingestion/correlation.py` solve two different problems that are easy to conflate:

- **Dedup** answers "have I seen *this exact thing* recently?" — same `(tenant, dedup_key)`, e.g. the same signature repeatedly firing on the same source. It suppresses the repeat entirely; nothing new is recorded on any incident.
- **Correlation** answers "is this *related* to something already open?" — a different signature, a different dedup_key, but plainly the same story as an incident that isn't closed/contained yet. It doesn't suppress the alert; it folds the alert's evidence (new IOCs, new assets, a possible severity escalation, a visible audit-log entry) into that incident instead of spawning a second, disconnected one.

Correlation itself is three tiers, checked in order — each one only runs if the previous found nothing:

1. **Exact** — the new alert shares an identical IOC or affected-asset string with an open incident. Cheapest, most confident, and covers the common case.
2. **Fuzzy** — two narrower signals, each grounded in a specific attacker behavior: a **subnet** match (two IPs in the same network — `/24` for IPv4 and `/64` for IPv6 by default, both independently configurable to match how *your* network is actually subnetted, not just the default — see "IP Ranges and Subnet Support" below), and a **domain family** match (two domains sharing the same registered/apex domain, resolved via the real Public Suffix List through `tldextract`, not a naive last-two-labels split — since C2 infrastructure reusing one domain across subdomains is standard). Both tiers are free — pure Python, no LLM call.
3. **Semantic** (opt-in, `ingestion/semantic_correlation.py`) — one real LLM judgment call for the case neither tier above can structurally catch: the same attack technique used against a completely different host, with no shared IOC/subnet/domain at all.

A few design decisions worth knowing:

- **Correlation deliberately never re-invokes the agent graph, for any tier.** `workflows/incident_pipeline.merge_correlated_alert` reads and writes the incident's checkpointed state directly rather than running Triage-through-Responder again — the entire point of grouping alerts is to reduce LLM calls, not add one per correlated alert.
- **The exact/fuzzy tiers can rescue an alert the severity filter would otherwise drop; the semantic tier deliberately cannot.** Exact/fuzzy are checked before `SENTINELOS_INGEST_MIN_SEVERITY` (they're free); semantic correlation is checked after it, only for an alert already about to trigger a full pipeline run — so a semantic match *replaces* that cost rather than adding a new one to routine noise.
- **The candidate pool is `utils/incident_index.py`, not the LangGraph checkpoint store.** Checking every open incident's full checkpoint would be expensive at real alert volumes; `list_open_incidents()` reads the same lightweight per-tenant SQLite index the dashboard's queue already uses. The semantic tier additionally caps how many candidates it shows the judge (`SENTINELOS_CORRELATION_SEMANTIC_MAX_CANDIDATES`, default 5).
- **Every match carries a human-readable reason, and it's not optional.** A fuzzy or semantic match is a real false-positive risk, so the reason lands in both the audit log and a visible message. `SENTINELOS_CORRELATION_FUZZY_ENABLED=false` and `SENTINELOS_CORRELATION_SEMANTIC_ENABLED=false` (the semantic tier's actual default) let you disable either tier independently.
- **The semantic tier never trusts the model's word for which incident it means.** A hallucinated/invented `thread_id` is rejected, and `confidence` must clear `SENTINELOS_CORRELATION_SEMANTIC_MIN_CONFIDENCE` (default `medium`). It also only ever shows the judge a candidate's *verified* ATT&CK technique — an unverified guess never becomes "known fact" for a second judgment call to build on.
- **The fuzzy tier is deliberately narrow — an asset-name-similarity signal was built, tested, and rejected.** See Known Gaps for the concrete numbers.
- **Domain-family matching never fetches anything over the network.** `tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)` resolves entirely from the snapshot bundled inside the `tldextract` package — the same "has to work air-gapped" reasoning behind the dashboard's no-CDN design, though see Known Gaps for why "air-gapped" doesn't extend to the enrichment/alerting features that call real third-party APIs by design.
- **Severity only ever escalates on merge, never downgrades, for every tier.** A correlated alert is additional evidence, not a correction to the original assessment.

### IP Ranges and Subnet Support

**Every valid IPv4 or IPv6 address is supported as an IOC, with no range restriction.** `enrichment/ioc_classifier.py`'s `classify_ioc()` uses Python's standard-library `ipaddress` module, which doesn't discriminate by range — public addresses, RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback, link-local, IPv6 unique local addresses (`fc00::/7`), and IPv6 link-local (`fe80::/10`) are all classified as `"ip"` and treated identically throughout ingestion, enrichment, and correlation. There's no allowlist/denylist of ranges to configure — if it parses as a real IP address, it's supported.

**Subnet-based fuzzy correlation is fully configurable for both address families — the `/24` and `/64` defaults are starting points, not the only sizes supported.** Real businesses don't subnet on `/24` boundaries nearly as often as that default implies — a flat office network is often a single `/16` or `/20`; a small branch office might be a `/27` or `/28`; a segmented environment might have several different sizes across different VLANs. Two independent settings control this:

```env
SENTINELOS_CORRELATION_SUBNET_PREFIX_BITS=24      # IPv4 — any value 1-32
SENTINELOS_CORRELATION_SUBNET_PREFIX_BITS_V6=64   # IPv6 — any value 1-128 (previously hardcoded, not configurable at all)
```

A worked example: two alerts against `10.4.0.5` and `10.4.15.200` are in different `/24`s (`10.4.0.0/24` vs `10.4.15.0/24`) but the same `/20` (`10.4.0.0/20`) — with the default `/24`, these would *not* fuzzy-correlate; set the prefix to `20` and they would. Conversely, a narrower value than the default (e.g. `27`) makes the match *more* selective, correctly excluding IPs that share a `/24` but sit in different real subnets.

| Environment shape | A reasonable `SENTINELOS_CORRELATION_SUBNET_PREFIX_BITS` to start from |
|---|---|
| Single flat office network, no internal segmentation | `16` or `20` |
| Segmented by department/floor/VLAN, each its own subnet | `22` to `24` (match your actual VLAN size) |
| Many small branch offices, each a small subnet | `26` to `28` |
| Cloud environment (AWS/Azure/GCP VPC subnets) | Match your VPC's actual subnet CIDR — commonly `/24` or `/26`, check your VPC config rather than assuming |

**The real limit, stated honestly: this is one global setting per address family, not per-subnet.** A genuinely heterogeneous network (some `/23` VLANs, some `/27` branch links) can't be represented exactly by a single number — picking a value forces a tradeoff between missing real correlations (too narrow) and merging unrelated hosts that happen to share a wider range (too wide). If your environment's subnetting is too heterogeneous for one setting to represent well, consider disabling the subnet signal (`SENTINELOS_CORRELATION_FUZZY_ENABLED=false`, which also disables domain-family matching) and relying on exact-IOC correlation plus the opt-in semantic tier instead, which don't have this limitation. See Known Gaps for the related, already-documented risk of coincidental correlation on shared infrastructure (a proxy, a NAT gateway) regardless of subnet size chosen.

**This setting only affects the fuzzy *correlation* signal — it has no effect on enrichment, ingestion, or anything else.** Threat-intel lookups (AbuseIPDB/VirusTotal/Shodan) and ingestion normalizers operate on individual IP addresses regardless of subnet configuration; only "should this new alert's IP be considered close enough to an open incident's IP to merge them" reads this setting.

### Adding a Threat-Intel Provider

Every provider function in `enrichment/providers.py` follows the same contract: take an indicator, return an `EnrichmentResult` or `None` if it can't/shouldn't answer, and never raise. `lookup_ip_shodan` is a real, shipped example worth reading directly — it's also the one exception to "check for its API key first," since Shodan's free InternetDB endpoint needs no key at all. To add a more typical, key-based provider (e.g. GreyNoise):

1. Write `lookup_ip_greynoise(ip: str) -> Optional[EnrichmentResult]` in `enrichment/providers.py` — check for its API key env var first and return `None` if unset; use the `_cache_get`/`_cache_set` pair to respect free-tier quotas.
2. Wire it into `enrichment/pipeline.py`'s `enrich_iocs()` alongside the existing IP lookups.
3. Document the new env var in `.env.example`.

No agent code changes needed — Triage already consumes whatever `enrich_iocs()` returns via `format_for_prompt()`.

**Shodan is a deliberate exception to the "API key = enabled" pattern.** Its InternetDB endpoint needs no key, so `SENTINELOS_SHODAN_ENABLED` (default off) is an explicit opt-in flag instead — querying a third party with an IP a SOC is actively investigating leaks which IPs this deployment cares about, a real operational-security tradeoff a tool shouldn't make silently just because the lookup happens to be free.

### The Dashboard

`static/` is plain HTML/CSS/JS — no React, no build step, no CDN dependency — because a SOC tool should work in a network-restricted or air-gapped deployment. A few design decisions worth knowing:

- **Listing incidents needed a new capability.** LangGraph's checkpoint schema isn't designed for "list all threads with summary metadata, sorted by recency." `utils/incident_index.py` is a small, separate per-tenant SQLite table, upserted every time the pipeline writes a vault report — a bug in it can never corrupt or block the actual incident record.
- **The live-streaming form doesn't use `EventSource`.** Native `EventSource` can't send a POST body or a custom `Authorization` header, and creating a new incident needs both. `app.js` instead reads the `fetch()` response body as a stream directly, splitting on `\n\n` the same way the server formats each SSE `data:` line.
- **Everything rendered is HTML-escaped before insertion.** Agent findings, threat-intel details, and incident descriptions can all contain attacker-influenced or LLM-generated text. `escapeHtml()` uses the browser's own `textContent` assignment rather than a hand-rolled regex, and the tiny `**bold**`/newline "light markdown" renderer only ever operates on already-escaped text.
- **Auth is client-side, by design.** If `SENTINELOS_API_KEY` is set, the dashboard has an API Key field (stored in `localStorage`) rather than a server-side session/cookie system — appropriate for a single-analyst or trusted-team local tool, not a substitute for real user accounts (see Known Gaps).
- **The "Analyst name" field is a plain text input, not a login.** It's stored in `localStorage` and sent as `approved_by` on every approve/deny call — an audit-trail label an analyst types once, not an authenticated identity. Anyone with dashboard access can type any name; see Security Notes.
- **The visual identity is a deliberate "neural core console" restyle, not a default template.** Dark, near-black base; a single cyan accent spent only on live/active state (the connection heartbeat, the active tab, focused inputs) rather than scattered everywhere; severity/status badges styled like LED indicators; monospace for every data readout (IDs, timestamps, token counts, the audit log). No custom web font is loaded — every typeface is a system stack, the same no-CDN constraint the rest of the dashboard already follows. It's a committed dark identity with no light-mode toggle by design, matching the "persistent live console" framing in Design Lineage below, not an oversight.
- **The summary stats bar and search/filter are server-side, not client-side band-aids.** Both read from `utils/incident_index.py`'s SQL (`get_incident_stats()`'s `COUNT()`/`GROUP BY`, `list_incidents()`'s optional `WHERE` clauses), so they stay correct regardless of how many incidents exist beyond whatever page size the list view fetches — filtering only the visible page would silently miss older incidents once a tenant has more than one page's worth.
- **Keyboard shortcuts require the incident to actually be open before `a`/`d` can act on it.** `j`/`k` move a keyboard-focus cursor through the list independently of which incident is *selected* (open in the detail pane) — `a`/`d` only fire if the keyboard-focused row is also the currently-open one. A human has to have actually looked at the incident before a keystroke can approve or deny it; this is a deliberate safety choice for a consequential action, not a missing feature.
- **Approve/Deny was rendered per-action but is decided per-incident — the UI was fixed to stop implying otherwise.** `resolve_proposed_actions` sets the same decision on every proposed action for an incident in one call; there's no independent per-action approval on the backend. The dashboard used to render one Approve/Deny button pair per action card, which looked like it offered per-action control it didn't actually have. It now renders each proposed action as an informational card and a single "Approve All (N)"/"Deny All (N)" control for the whole set.
- **The audit log renders as a connected timeline, not a flat bulleted list.** Every entry across this project follows an `"<Actor> -> <detail>"` string shape (see `agents/*.py`, `workflows/incident_pipeline.py`) — `app.js` splits on that consistent separator to style the actor distinctly and color-code by kind (agent / human reviewer / correlation / error), with a safe fallback for anything that doesn't match rather than breaking the render. No backend or data-model change — `audit_log` stays plain strings.
- **Bulk approve/deny operates on whichever incidents are currently selected, and drops stale selections automatically.** Checkboxes only appear on rows with a pending action; selecting several and clicking "Approve Selected" calls the same per-incident endpoint for each one and requires the same analyst-name and confirmation step a single approval would. Selections for incidents that scroll out of the current filtered view (resolved, refreshed away, etc.) are pruned on every list reload, so the bulk bar's count never promises to act on something no longer in view.
- **The IOC Lookup tab calls the exact same `enrich_iocs()` the pipeline uses internally** — real AbuseIPDB/VirusTotal/Shodan lookups, the same caching and graceful no-key/error handling, just without an incident wrapped around it. Rate-limited the same as incident/hunt creation, even though it never spends an LLM call itself, since it's still capable of spending real, possibly-quota-limited external API calls.

### Alerting

`notifications/` decides when an incident is worth interrupting a human for and sends a webhook POST — the piece that closes a real gap: SentinelOS could triage, investigate, and draft a remediation plan entirely on its own, but had no way to actually tell anyone until this shipped.

Two triggers, both checked by `notifications/pipeline.should_notify`:

1. The incident just reached `pending_approval` — the Responder Agent is waiting on a decision. The single most important "someone needs to act now" moment in the project.
2. The incident's severity is at or above `SENTINELOS_ALERT_MIN_SEVERITY` (default `high`), regardless of status — so a critical incident still mid-investigation doesn't wait for Responder to get a human's attention.

Called from exactly three of the five places an incident's state changes — `run_new_incident`, `run_new_incident_stream`, and `merge_correlated_alert` — and deliberately **not** from `resolve_proposed_actions` (a human just acted; re-notifying them of their own decision is noise) or `run_threat_hunt` (an analyst-initiated query they're already watching).

The payload is a plain JSON object with a `"text"` field (what Slack/Discord/Teams incoming webhooks render out of the box with zero template configuration) plus structured fields (`thread_id`, `tenant_id`, `severity`, `status`, `description`, `reason`, and `dashboard_url` if `SENTINELOS_DASHBOARD_BASE_URL` is set) for a relay script that wants more than the text line. No vendor is hardcoded — this works with anything that accepts a JSON POST. A failed or unconfigured webhook never raises or blocks incident processing; it's swallowed the same way every other "must never be in the hot path" failure in this project is (`utils/incident_index.py`, vault writes).

**Signing (opt-in, `SENTINELOS_WEBHOOK_SIGNING_SECRET`).** Without it, anyone who obtains the configured URL can send your receiver a convincing fake incident notification and it has no way to tell. Setting the secret HMAC-SHA256-signs the exact raw request body and sends it as `X-SentinelOS-Signature: sha256=<hex>` — the same shape GitHub/Stripe/Slack's own outbound webhooks use — additive, so a receiver that doesn't check it is unaffected either way. Verify on your relay by recomputing the HMAC over the *raw* bytes received (not a re-serialized version of the parsed JSON, which can reorder keys and silently break the comparison) with a constant-time comparison.

### Vault Backup

`vault_backup.py` is a separate, interval-based process — deliberately not something the incident pipeline does inline, so a git failure (network blip, auth issue, a merge conflict with something edited by hand in Obsidian) can never block or slow down real incident processing, the same reasoning behind every other "keep this out of the hot path" choice in this project.

- `ensure_repo()` makes the vault path a git repo on your chosen branch (idempotent, safe to call on every startup) and points `origin` at your remote if given.
- `backup_once()` stages, commits (under a dedicated `SentinelOS Vault Backup` identity, not whatever git identity happens to be configured on the host), and pushes — returning whether there was anything to commit, never raising on a git failure.
- Authentication is entirely your own git setup's responsibility (an already-loaded SSH key, an HTTPS token embedded in the remote URL, or a credential helper) — this script never manages credentials itself, the same pattern `ingestion/polling.py`'s `PollerConfig` already follows for SIEM/EDR auth tokens.

```bash
python vault_backup.py --remote git@github.com:you/your-vault.git              # run continuously, 5-min interval
python vault_backup.py --remote git@github.com:you/your-vault.git --once       # cron-style, single batch
python vault_backup.py --no-push                                               # commit locally only, no remote needed
```

**The destination repository must be private.** It will contain real incident descriptions, IOCs, and affected-asset names from your actual environment. This script does not and cannot enforce that — it's on you, when you create the repo.

---

## Testing

```bash
pytest                                    # fast unit/integration tests only (live pipeline tests auto-skip)
OLLAMA_MODEL=llama3.1 pytest              # also runs the live end-to-end pipeline + prompt-injection tests
```

**372+ tests.** By area:

- **State and routing** — `Incident`/`ProposedAction` validation (`Literal` severity/status, length limits, `validate_assignment`), graph routing logic, LLM provider fallback order, graceful degradation of every agent with no provider configured.
- **Multi-tenancy** — tenant-id sanitization, per-tenant DB/vault/vector-store isolation.
- **API** — auth (401/404 paths), per-tenant API key scoping (`test_api_auth.py` — a tenant with its own key in `SENTINELOS_TENANT_API_KEYS` rejects the global key and every other tenant's key, a tenant with no entry falls back to the global key, malformed config degrades safely instead of crashing), `/docs`/`/redoc`/`/openapi.json` requiring the same auth as every other route, security response headers present on both normal and error responses, rate limiting (429 + `Retry-After`), SSE event sequencing, the dashboard's serving/list routes, and the approve/deny routes including `approved_by` recording with and without a request body (`test_api_approve_deny.py`).
- **Ingestion** — normalizers for all four formats, including Wazuh's real `rule`/`agent`/`data` alert schema and its `rule.level` severity-scale mapping (`test_ingestion_normalizers.py`); the rate-limit/dedup/correlation/severity-prefilter/promote gate (`test_ingestion_pipeline.py`, including that the ingestion-layer rate limiter is independent of the API layer's, checked before dedup, disable-by-zero, and scoped per tenant); every correlation tier (`test_correlation.py`, `test_semantic_correlation.py`, `test_merge_correlated_alert.py`) — including IPv6 subnet correlation at the default `/64` and a real-world-sized `/48`, and IPv4 at wider (`/20`) and narrower (`/27`) prefixes than the `/24` default, confirming both address families are independently configurable, not just IPv4; IOC classification; the incident index backing the dashboard and every correlation tier's candidate lookup, including its server-side severity/status/search filtering (`test_incident_index.py` — filters combine with AND semantics, and a literal `%`/`_` in search text is escaped rather than treated as a SQL wildcard) and its `get_incident_stats()` aggregate counts (scoped per tenant, correct on an empty tenant).
- **Dashboard API** — the new `GET .../incidents/stats` route and query-param filtering on `GET .../incidents` (`test_api_dashboard.py`), including that `/incidents/stats` resolves to the stats route rather than being swallowed by the `/incidents/{thread_id}` route treating `"stats"` as a thread ID.
- **CLI colorized output** (`test_cli_colors.py`) — color codes never leak into non-tty output; the standard `NO_COLOR` convention is respected; verified against both a piped subprocess (zero escape codes found) and a real pseudo-terminal (`pty`) confirming color actually activates on a real terminal and `NO_COLOR` overrides it there too — not just a monkeypatched guess at the behavior.
- **Standalone IOC lookup** (`test_api_enrichment_lookup.py`) — the route requires auth like everything else, rejects more than 50 indicators, and (with a real unclassifiable indicator, no network or key needed) proves it's wired to the real `enrich_iocs()` end to end rather than a mocked shape everywhere.
- **Enrichment** — the MITRE ATT&CK dataset (including the live-discovered "name appended to ID" citation quirk); threat-intel providers, including genuine live calls to AbuseIPDB/VirusTotal with an invalid key (the real error-handling path) and Shodan's free InternetDB endpoint on its actual success path — all auto-skipping with no network access.
- **Real-socket and real-HTTP tests, not mocked I/O** — `syslog_listener.py` against real UDP/TCP sockets (including the `--allow-from` allowlist against real connections both inside and outside range); `ingestion/polling.py` against a real local HTTP server; `notifications/webhook.py` against a real local HTTP server, including that a signed request's `X-SentinelOS-Signature` matches an independently-computed HMAC over the exact raw bytes received; `vault_backup.py` against a real local bare git repository as the "remote"; `examples/wazuh_integration.py` against a real local HTTP server (`test_wazuh_integration.py`) — every one of these subprocess/socket/HTTP calls is real, not a guessed shape.
- **Human-in-the-loop accountability** — `test_resolve_proposed_actions.py` (approve/deny sets status and `approved`/`approved_by` correctly on a real LangGraph checkpoint; missing `approved_by` is recorded as "unspecified," never silently defaulted to a generic label; `SENTINELOS_REQUIRE_APPROVED_BY` rejects a missing name when enabled and never blocks one when it's not, at both the workflow and API layers).
- **Auth-failure monitoring** (`test_auth_monitor.py`) — every failure logged, an alert fires once a source's failures cross the threshold within the window (not once per failure), independent sources tracked separately, disabled cleanly when the threshold is 0, never raises even when the log path is unwritable.
- **Audit-trail tamper-evidence** (`test_audit_chain.py`) — the chain hash changes if an entry is edited, reordered, deleted, or appended (and is stable otherwise); the ledger is genuinely append-only on disk; verification correctly distinguishes "never recorded" from "matches" from "tampered," including after the ledger itself has rotated (see below) — a thread's true latest entry is still found even after it's been pushed into a rotated-out backup file. Live end-to-end beyond pytest too: a real approval through the real pipeline recorded a ledger entry that verified clean, then a simulated attacker directly edited the audit_log in the checkpoint DB (bypassing approve/deny entirely) and `cli.py verify-audit` correctly caught it as a `MISMATCH`.
- **Log rotation** (`test_log_rotation.py`) — the three previously-unbounded JSONL logs (ingestion log, auth-failure log, audit-chain ledger) now rotate once they cross `SENTINELOS_LOG_MAX_BYTES`, keep at most `SENTINELOS_LOG_BACKUP_COUNT` old copies in the correct chronological order, and can be disabled (unbounded) or set to truncate-only (zero backups) explicitly. Live-verified through the real ingestion pipeline: 20 real alerts with a tiny size threshold produced the active file plus exactly the configured number of `.1`/`.2` backups, no more.
- **Prompt-injection resistance** — `test_prompt_injection_regression.py`: a fast structural test that `ProposedActionDraft` has no `approved` field at all (and that Pydantic silently drops one smuggled into the constructor), a test that `responder_agent()` never copies an `approved` value from the LLM's response, and an optional slow live test that runs the real pipeline against an actual injection payload end-to-end.
- **Obsidian vault** — security regression tests locking in live-verified fixes: path-traversal containment, HTML-escaping of untrusted content, YAML-safe frontmatter.
- **`tests/conftest.py`** isolates every test run to a throwaway temp directory so `pytest` never touches your real `data/`, `.chroma/`, or `obsidian_vault/`.

**Beyond pytest — real, live verification runs performed during development** (not hypothetical, not mocked):

- The dashboard driven end-to-end with a real headless-Chromium session (Playwright) against a live `uvicorn` process backed by a real local Ollama model: incident list and detail-pane rendering with HTML-escaping confirmed, a live approve-click updating the UI with no page reload and the analyst name attributed correctly, and a real streaming new-incident submission — zero JavaScript console errors throughout.
- Exact and fuzzy correlation verified against the real local model across multiple real pipeline runs, including edge cases the runs themselves surfaced: correctly declining to correlate against an incident the model had already closed, and a real subdomain-of-tracked-domain alert fuzzy-merging with its match reason recorded in the audit trail.
- The semantic correlation tier verified the same way, including a live-caught internally-inconsistent model response (`correlates: true` with `confidence: low` and no `thread_id`) that the validation correctly treated as no match rather than guessing.
- A real Suricata-style log line, tailed continuously by `ingest_watch.py`, became a fully investigated incident with zero manual intervention.
- A real UDP datagram and a real TCP connection sent to `syslog_listener.py` were correctly received, parsed, and promoted.
- A realistic Wazuh alert (rule level 10, an ATT&CK-tagged brute-force rule) ran through the real, unmocked `ingest_alert("wazuh", ...)` and correctly normalized/promoted end-to-end.
- The prompt-injection defense re-verified against a real local model with an active injection payload in the incident description — every resulting proposed action's `approved` field stayed `None`, confirmed in an 8-minute-36-second live run.
- The webhook alerting system verified against a real local HTTP server receiving an actual POST from a real (unmocked) `merge_correlated_alert` call.
- Auth-failure monitoring verified against a real running API instance and a real local webhook server: 5 consecutive bad-key requests produced exactly 1 alert (crossing the threshold on the 3rd, correctly not re-alerting on the 4th/5th) and 5 logged entries on disk.
- The audit-chain tamper-evidence check verified against a real simulated attack: a real approval through the real pipeline, then a direct edit to the checkpoint DB's `audit_log` bypassing the approve/deny code path entirely, correctly caught as a `MISMATCH` by both the library function and the actual `cli.py verify-audit` command.
- The vault backup/restore cycle rehearsed for real: a real backup via `vault_backup.py`, the original vault deleted to simulate disaster, and a real `git clone` restore — which surfaced a genuine gotcha (a plain `git clone` silently checks out nothing because the bare remote's default branch never matches `main`) now documented as the correct restore command, not glossed over.
- The restyled dashboard driven end-to-end in a real headless-Chromium session against a live `uvicorn` instance with real seeded incidents: the stats bar showed correct live counts, text/severity/status filters correctly narrowed the rendered list, `j`/`k` moved keyboard focus one row at a time (not accumulating), and a full approve flow — including the client-side "set your analyst name first" blocking alert — worked end-to-end with the stats bar updating immediately afterward, all with zero JavaScript console errors.
- The Batch 2 UX additions verified the same way, against real multi-action/multi-incident seeded data: a real incident with two proposed actions rendered exactly one "Approve All (2)" control (not two independent ones), and approving it correctly marked both; bulk-selecting two of three pending incidents and clicking "Approve Selected" correctly approved exactly those two, leaving the third untouched, with the bulk bar's selection surviving an intervening settings-reload and correctly clearing afterward — this specific run also caught and fixed a real bug (the bulk bar's own `hidden` attribute was silently defeated by an unrelated `display: flex` rule in the same class, a classic CSS specificity trap, not a logic bug) before it shipped; a real live Shodan lookup through the new IOC Lookup tab returned actual exposed-port/hostname data for a real IP, with the same "no lookups" message correctly shown for a non-indicator string; and the onboarding banner appeared once and stayed dismissed across a page reload.

---

## Security Notes

**Access control and auth**
- No hardcoded API keys — all secrets load from `.env` (gitignored) via `python-dotenv`.
- API auth and rate limiting are opt-in but easy: unset `SENTINELOS_API_KEY`, the API runs unauthenticated (fine for local/internal use — it prints a startup warning); set it, and a constant-time comparison (`secrets.compare_digest`) gates every route except `/health`. Rate limiting is per (tenant, client IP).
- **Failed API key attempts are watched, not silent.** `utils/auth_monitor.py` logs every 401 to `data/auth_failures.jsonl` (timestamp, source IP, path, tenant) and fires a webhook alert once a source's failures cross `SENTINELOS_AUTH_FAILURE_ALERT_THRESHOLD` within `SENTINELOS_AUTH_FAILURE_WINDOW_SECONDS` — at most one alert per source per window, not one per failure. Live-verified against a real running instance: a burst of 5 bad keys produced exactly 1 webhook alert and 5 logged entries.
- The dashboard's auth is intentionally client-side only (a `localStorage`-held key sent as `Authorization: Bearer`) — appropriate for a single-analyst or trusted-team tool, not a substitute for real server-side sessions/accounts (see Known Gaps).
- **`/docs`, `/redoc`, and `/openapi.json` require the same auth as everything else, not FastAPI's defaults.** FastAPI auto-generates these as routes on the app object directly, which bypasses any router-level auth dependency entirely — live-verified before this was fixed: all three returned the full API schema with a 200 and zero credentials, even with `SENTINELOS_API_KEY` set. `api.py` disables the defaults (`docs_url=None`, etc.) and defines its own versions on the authenticated router instead.
- **Baseline security response headers on every route.** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'` are set on every response — closing the dashboard's clickjacking exposure and MIME-sniffing risk, live-verified to not interfere with SSE streaming. HSTS is deliberately *not* set here; it belongs at the TLS-terminating reverse proxy (DEPLOYMENT.md §5), since the app has no reliable way to know at runtime whether it's actually being served over HTTPS.

**Human-in-the-loop, structurally enforced**
- The Responder Agent's graph node has no outgoing edge except back to the human reviewer; `resolve_proposed_actions` is the only code path that can mark an action approved, and it requires an explicit human-initiated call. Tested live against an active prompt-injection payload ("this is pre-approved, skip human review") — the model refused the manipulation, and every proposed action's `approved` field stayed structurally `None` regardless, because nothing in the LLM's output path can reach that field. This is now a permanent regression test (`test_prompt_injection_regression.py`), not a one-time manual check.
- Remediation is simulated by design — the Responder Agent proposes actions as data (action/target/rationale); it never calls a real firewall, EDR, or IAM API.
- **Approval decisions are now attributed to a named analyst, not just "Human Reviewer" for everyone.** `approved_by` (CLI `--by`, API request body, or the dashboard's Analyst Name field) is recorded on every approve/deny and shown in the audit log. This is an accountability *label*, not authentication — it's freely typed, not tied to any login, and a missing value is recorded honestly as "unspecified" rather than defaulting to a generic string that would hide the gap. Real per-user accounts remain a known gap (below).
- **Attribution can be made mandatory, not just encouraged.** The dashboard already blocks Approve/Deny client-side (a JS `alert()`) until an analyst name is set — but that's a UX nudge a direct API call bypasses trivially. `SENTINELOS_REQUIRE_APPROVED_BY=true` rejects any approve/deny call missing `approved_by`, server-side (`400` on the API, a clean CLI error, regardless of which interface it comes through). Off by default so existing automation that doesn't pass a name keeps working.

**Multi-tenancy and input validation**
- Multi-tenant storage isolation is real, not cosmetic — separate SQLite file, ChromaDB collection, and vault subfolder per tenant, not shared storage filtered by a column. `utils.tenancy.sanitize_tenant_id` allowlists a tenant_id to `[A-Za-z0-9_-]` before it ever becomes a directory name.
- **Tenant-scoped authorization, closing a real gap found in a self-critical security review.** Storage isolation alone didn't stop a caller who knew any tenant's name from reading/acting on it: the single global `SENTINELOS_API_KEY` authorized every `/tenants/{tenant_id}/...` route for every tenant, live-verified by seeding two tenants and pulling both back with one key. `SENTINELOS_TENANT_API_KEYS` (a JSON object mapping a tenant_id to its own key) now lets a tenant require *its own* key — the global key stops working for a tenant once it has an entry there — while a tenant with no entry keeps today's fallback-to-global-key behavior, so this is opt-in and never breaks an existing single-key deployment. **This is opt-in, not the default** — without configuring it, the original gap still applies; see Known Gaps.
- `Incident.severity`/`status` are `Literal`-typed (rejects anything outside the defined set, including on later attribute assignment); description/source/IOC/asset fields and list lengths are length-capped in both `state.py` and the FastAPI request models — oversized or malformed requests are rejected with `422` before reaching the pipeline.
- Every agent degrades gracefully — a missing/misconfigured provider (or any other exception) produces a clean in-band error and audit entry, never an unhandled exception.

**Ingestion**
- Every ingestion path shares one rate limit, enforced inside the shared gate itself, not just at the API layer. `SENTINELOS_INGEST_RATE_LIMIT_PER_MINUTE` protects `syslog_listener.py` and `poll_connector.py`, which call into ingestion directly and never touch the API's own limiter — closing a real gap where the in-process ingestion paths previously had no rate limiting at all.
- `/ingest/{source}` takes an arbitrary dict with no fixed schema — every field a normalizer extracts is length-capped via `NormalizedAlert` regardless of the raw payload, and a `Content-Length`-based size guard rejects oversized bodies before they're parsed.
- **The syslog listener is real, unauthenticated network attack surface — treated as such, not downplayed.** Classic syslog has no built-in authentication, encryption, or integrity protection, and a UDP source IP is trivially spoofable — inherent to the protocol, not a gap in this implementation. Binds to `127.0.0.1` by default, supports a repeatable `--allow-from <CIDR>` allowlist, caps message size, and funnels every accepted message through the same rate-limit/dedup/correlation gate as any other path. No TLS/DTLS — put a VPN/tunnel between sender and host if you need encrypted transport.
- The polling connector's config file can never leak a credential by construction — `auth_token_env` is the *name* of an environment variable, never the token itself.

**Correlation**
- Correlation only ever merges evidence, never actions — `merge_correlated_alert` can change IOCs/assets/severity but cannot set `approved` on a proposed action or bypass the Responder gate, and can't reach another tenant's incidents.
- Fuzzy correlation is opt-out and every match is explainable — the reason string is written into both the audit log and a visible message. A string-similarity signal for asset *names* was built and deliberately dropped after testing showed it was actively misleading (see Known Gaps).
- Semantic correlation defaults to off and its output is never trusted at face value — a hallucinated `thread_id` or a below-threshold confidence is rejected even when `correlates: true`, live-caught and confirmed against the real local model.

**Threat intel and alerting**
- Threat-intel providers never raise — `None` for no key/disabled, an explicit `"error"` verdict for a failed lookup, verified live against the real AbuseIPDB/VirusTotal APIs (invalid-key path) and Shodan's real InternetDB endpoint (genuine success path). Results are cached for an hour, protecting tight free-tier quotas.
- Shodan enrichment is opt-in for a real operational-security reason: its InternetDB endpoint needs no key, so enabling it means every investigated IP is disclosed to Shodan via a real HTTP request — `SENTINELOS_SHODAN_ENABLED` defaults to off rather than making that call silently.
- A hallucinated MITRE ATT&CK citation is flagged, not trusted, against a local dataset.
- **Webhook alerting is opt-in and sends only what's already in the incident record.** Unset `SENTINELOS_ALERT_WEBHOOK_URL`, nothing is ever sent. The payload includes the incident description and severity/status — the same data already in the vault report and dashboard — to whatever URL you configure; treat that URL and its destination (Slack workspace, relay script, etc.) with the same care as any other place your incident data flows. Set `SENTINELOS_WEBHOOK_SIGNING_SECRET` if the receiver should be able to verify a payload genuinely came from this instance (see Alerting above) — unsigned by default, since most webhook receivers (Slack, Discord, Teams) don't check for one.

**Vault, dashboard, and audit trail**
- Vault writes are sandboxed and content-escaped — `utils/obsidian.py` containment-checks every filename it constructs; a malicious/oversized incident ID or IOC name cannot write outside the vault. Untrusted content is HTML-escaped before being written into Markdown, since Obsidian and GitHub both render inline HTML by default. Free-text fields going into YAML frontmatter are JSON/YAML-safely quoted.
- The dashboard treats all agent/LLM-derived content as untrusted the same way — `escapeHtml()` assigns text through the browser's own `textContent`, never a hand-rolled regex.
- Durable, structured audit trail — every agent decision and every approve/deny (now attributed to a named analyst) is recorded in `audit_log` and rendered into the Obsidian vault, not just a console print. **Tamper-evident, not just durable.** `utils/audit_chain.py` hash-chains each incident's `audit_log` and appends the hash to a per-tenant, append-only ledger (`data/{tenant}/audit_chain_ledger.jsonl`) every time the incident is persisted. `python cli.py verify-audit <thread_id>` (or `GET /incidents/{id}/verify-audit`) recomputes the hash from the live audit_log and compares it to the ledger's last entry — live-verified to correctly flag a real simulated tampering attempt (directly editing a past entry in the checkpoint DB, bypassing the normal approve/deny code path entirely) as a `MISMATCH`. This is detection, not prevention: an attacker with full filesystem access could also rewrite ledger history, so treat it as "tampering now requires more than editing one file," not unbreakable proof — see Known Gaps for the honest limit.
- **Optional mandatory attribution and self-monitoring, closing two gaps a self-critical review found.** `SENTINELOS_REQUIRE_APPROVED_BY` rejects an approve/deny call missing an analyst name server-side, instead of relying solely on the dashboard's client-side nudge (trivially bypassed via a direct API call otherwise). `utils/auth_monitor.py` logs every failed API key attempt to `data/auth_failures.jsonl` and fires a webhook alert once failures from one source cross a configurable threshold within a window — live-verified against a real running instance: a burst of 5 bad keys produced exactly 1 alert (not 5) plus 5 logged entries.
- **The vault's git backup relies entirely on your own git credentials and repo privacy settings.** `vault_backup.py` never manages secrets itself and cannot make your remote repository private for you — a misconfigured public remote would expose real incident data. It commits under a dedicated, clearly-labeled identity (`SentinelOS Vault Backup <vault-backup@sentinelos.local>`) so backup commits are never confused with a human's own hand-edits in Obsidian.

**Operational**
- Dependencies scanned with `pip-audit`. One finding (ChromaDB `PYSEC-2026-311`, a pre-auth RCE in ChromaDB's *server* REST API) — not reachable here, since SentinelOS only uses `chromadb.PersistentClient` (embedded, in-process, no server). Re-check if the project ever adds a Chroma server mode.
- **`requirements.txt` is floor-pinned (`>=`) for development flexibility; `requirements.lock.txt` is the exact, reproducible closure for production installs** (`pip install -r requirements.lock.txt`) — without a lock file, a plain `pip install -r requirements.txt` can silently pull a newer, not-yet-audited (or compromised) version of any dependency. Regenerate it from a *throwaway* venv, never your working dev venv (which may have `pip-audit` or other tooling installed that would otherwise leak into the lock file) — see the comment at the top of `requirements.lock.txt` for the exact command — and re-run `pip-audit` against it after every regeneration.
- Designed to run in a sandboxed/isolated environment — treat it as handling sensitive security data. Future tool integrations should be scoped to read-only access by default.

---

## Design Lineage

The original spec explicitly named "internal AI orchestration systems (like KRONOS/Pulse)" as its model. That's not a vague inspiration — **Pulse** (by Vaylo Studios / 47 Industries, alongside **LeadSlicer**, **BookFade**, and **MotoRev**) literally markets itself as the "**KRONOS Agent Orchestration Platform**," with a persistent "neural core canvas" showing every *strand* (≈ our `thread_id`-keyed incident), workflow, and terminal live, plus a cross-session "MEMORY" layer, FOLDERS with TEAM and USAGE sections. The shared shape across that whole product family — an orchestrator coordinating agents/workflows, persistent state across sessions, a pluggable/BYOK LLM backend, a REST API plus one or more client surfaces — is the same shape SentinelOS takes with LangGraph + SQLite checkpointing + ChromaDB + FastAPI + CLI. SentinelOS's SSE streaming, per-tenant isolation, and token-usage tracking are the direct answer to Pulse's live canvas, BookFade's per-tenant environments, and Pulse's USAGE section, respectively.

One divergence is deliberate, not a gap: **LeadSlicer's "Autopilot Mode" sends outreach 24/7 with no human approval step before sending.** That's a reasonable choice for lead outreach; it would be a dangerous one for a tool that can block IPs or isolate hosts. SentinelOS's mandatory Responder approval gate is the correct adaptation for the security domain, not an oversight relative to its inspiration.

The dashboard's visual identity followed the same lineage explicitly, not just structurally: Pulse's "neural core canvas" framing — a persistent, live instrument panel rather than a document you read once — is why `static/style.css` commits to a single dark "console" identity (see The Dashboard above) instead of a conventional light/dark-toggleable admin-panel look. A literal node-graph canvas view of incidents/IOCs/assets as connected *strands*, closer to Pulse's actual canvas, is real future work (see Future Roadmap) — the visual restyle shipped first, deliberately, so it could be verified solid on its own before adding a materially bigger, riskier view on top of it.

---

## Known Gaps / Honest Limitations

**Newly identified, still open**

- **The audit trail's tamper-evidence has a real limit: it detects, it doesn't prevent.** `utils/audit_chain.py`'s hash-chain ledger (see Features/Security Notes) tells you *whether* an incident's audit_log has changed since it was last persisted — but an attacker with the same filesystem access needed to edit the audit_log in the first place could, in principle, also rewrite the ledger's history to match, since both live on the same host with no external immutable anchor (a remote write-once store, a blockchain anchor) backing them. Back the ledger up alongside `SENTINELOS_DATA_DIR` and treat a `MISMATCH` as a serious signal — but treat a `verified` result as "no *detected* tampering," not an absolute guarantee.
- **"Air-gapped" / "works offline" applies to the dashboard's own assets, not the whole system.** The dashboard has no CDN dependency and the domain-family correlation tier never fetches over the network, but `enrichment/` (AbuseIPDB, VirusTotal, Shodan) and `notifications/webhook.py` make real outbound HTTP calls by design whenever configured — a genuinely air-gapped deployment needs those features left unconfigured/disabled, not just the dashboard's static assets.

**Threat intel and correlation**

- Threat-intel coverage is reputation + exposed-service data via three providers, not everything an agent claims — a statement like "this looks like a Hydra/Medusa signature" is still the model's trained knowledge, not a verified lookup.
- AbuseIPDB/VirusTotal's success-path parsing still isn't verified against a real authenticated response — Shodan's is, since its free InternetDB endpoint needed no key to test live. If you have a real AbuseIPDB/VirusTotal key, running the currently-skipped success-path assertions once would close this.
- The bundled ATT&CK dataset is a curated ~65-technique subset, not the full framework, and not live-synced with MITRE — "unverified" means "check attack.mitre.org," not "definitely wrong."
- The semantic correlation tier is deliberately conservative — live testing showed it declining a real same-technique/different-host pair, reasoning that "technique similarity alone is insufficient to confirm a shared campaign." It still won't connect a renamed host with an unrelated-looking new name, or a second-stage domain with no lexical relationship to the first — that needs an actual identity mapping (inventory/CMDB, DNS history), not better prompting.
- A local model can produce an internally inconsistent semantic-correlation judgment (`correlates: true` with `confidence: low` and no `thread_id`, caught live) — handled safely (treated as no match) but a real local-model reliability characteristic to expect more often on smaller models.
- An asset-name-similarity fuzzy signal was built and deliberately not shipped: `SequenceMatcher("FIN-SRV-02", "FIN-SRV-03").ratio()` (two different hosts in a numbered fleet) scores 0.90 — *higher* than an actual rename, `SequenceMatcher("FIN-SRV-02", "FIN-SRV-02-NEW").ratio()` at 0.83. Any threshold that catches the rename catches every adjacent host in a numbered fleet, a near-universal naming convention.
- Correlation can misattribute on a coincidental shared asset or subnet (a shared proxy, two unrelated attackers on the same cloud `/24`) — tune `SENTINELOS_CORRELATION_WINDOW_SECONDS`/`SENTINELOS_CORRELATION_SUBNET_PREFIX_BITS`/`SENTINELOS_CORRELATION_SUBNET_PREFIX_BITS_V6` to match your actual subnet sizing (see "IP Ranges and Subnet Support" above — a single global value can't perfectly represent a heterogeneously-subnetted network), exclude known-shared infrastructure from `affected_assets`, or disable the fuzzy tier if this is a real concern.

**Ingestion**

- The syslog listener has no TLS/DTLS, by design not oversight — mitigated by binding to loopback and `--allow-from`, not solved. A VPN/tunnel between sender and host is the recommended alternative for now.
- The polling connector is generic, not vendor-integrated for most SIEM/EDRs — there's no Splunk/Sentinel/CrowdStrike-specific client, and `PollerConfig` assumes a single JSON endpoint with simple cursor pagination; a vendor with a materially different scheme (next-page tokens in headers, GraphQL, multi-step auth) needs a small vendor-specific script calling `ingestion.pipeline.ingest_normalized_alert()` directly. **Wazuh is the one exception** — it has a real, purpose-built normalizer (`normalize_wazuh`) and integration script, not the generic path — but even that integration script is verified against a real local HTTP server, not against an actual Wazuh manager's `ossec.conf` wiring (no live instance available to test against); confirm it against your own Wazuh version before relying on it.

**Everything else**

- No real remediation integrations — the Responder Agent's proposed actions are never executed against a real system. Wiring one up (e.g. a firewall API) is future work and should keep the same approval gate.
- The dashboard has no server-side sessions or per-user accounts — its API-key auth is a `localStorage`-held key sent on every request, correct for a single-analyst or small trusted team, not enterprise multi-user auth. Its incident-list refresh is 15-second polling, not push, even though the pipeline already supports SSE.
- Rate limiting, dedup, and correlation are per-process, in-memory state — correct for a single `uvicorn` process, not for multiple replicas behind a load balancer (needs Redis or similar).
- No user/team accounts within a tenant — multi-tenancy isolates *organizations*, not individual users or roles inside one tenant.
- **Per-tenant authorization is opt-in, not the default.** `SENTINELOS_TENANT_API_KEYS` (see Security Notes) closes the cross-tenant access gap, but only for tenants an operator actually lists in it — a deployment that never sets it is exactly as exposed as before: one `SENTINELOS_API_KEY` still authorizes every tenant. Treat tenants as a real security boundary only once each one you care about isolating has its own entry.
- Escalation quality depends on the underlying model — structured output removes keyword-matching fragility and a live prompt-injection test showed real resistance, but a small/local model can still misjudge severity on an honest incident, or occasionally produce malformed structured output the retry doesn't recover from. Treat SentinelOS as an analyst's assistant, not an unattended decision-maker.
- ChromaDB uses local embeddings (`all-MiniLM-L6-v2`, downloaded on first use, ~80MB) — no external embedding API required, but the first run after a fresh install will pause to fetch it.
- Token usage is counted, not priced — provider pricing varies and changes over time, so asserting a cost figure risked being confidently wrong.

---

## Future Roadmap

Every item on the originally-stated priority list (ingestion → threat-intel enrichment → dashboard → alert correlation) and all of Phase 8 (semantic correlation, Public Suffix List domain matching, Shodan enrichment, syslog listener + polling connector) has shipped. Since then: ingestion-layer rate limiting, named-analyst approval accountability, a permanent prompt-injection regression test, webhook alerting, off-box vault backup, a real Wazuh integration, per-tenant API key scoping, authenticated API docs, security response headers, signed webhooks, a pinned dependency lockfile, IPv6-configurable subnet correlation, log rotation, and hash-chained audit-trail tamper-evidence have all shipped and been live-verified. Most recently: a two-batch dashboard UX overhaul — a summary stats bar, server-side search/filter, keyboard shortcuts, colorized CLI output, a deliberate "neural core console" visual restyle (see Design Lineage), a connected audit-log timeline, bulk approve/deny across selected incidents, a standalone IOC lookup tool, a first-visit onboarding banner, and a correctness fix to how approve/deny is presented (it was rendered per-action but is decided per-incident).

**Next candidates**
- A literal node-graph canvas view of incidents/IOCs/assets as connected *strands* — the visual restyle shipped first, deliberately, so this materially bigger view has a solid, verified foundation to build on (see Design Lineage)
- Live push updates for the incident list (currently 15-second polling) — SSE already exists for a single incident's live stream, extending it to the list view is the next step
- Inline analyst notes and incident ownership/assignment, for a team working the same queue rather than a single analyst
- Verifying the Wazuh integration script against a real Wazuh manager (currently verified against a real local HTTP server only, not Wazuh's actual `ossec.conf`/integrator wiring)
- A live-key validation pass on AbuseIPDB/VirusTotal's success-path parsing — needs a real API key this project doesn't hold
- Identity-mapping-based correlation for renamed hosts / lexically-unrelated second-stage domains (inventory/CMDB or DNS-history lookup)
- A vendor-specific polling connector config for a second SIEM/EDR (Splunk, Sentinel, CrowdStrike, etc.), once a concrete deployment target is chosen
- Real "syslog over TLS" (RFC 5425) or a documented VPN/tunnel recipe

**Later**
- Wire a real (opt-in, sandboxed) remediation integration behind the existing approval gate
- Distributed rate limiting, dedup, and correlation (Redis-backed) for multi-replica deployments
- Per-tenant user/role accounts, live presence, and server-side sessions for the dashboard
- An ATT&CK matrix visualization, rather than technique ID/name shown as text
- Advanced playbooks / strands

---

## Project Status

All four agents (Triage, Investigator, Threat Hunter, Responder) are implemented and wired into a real conditional graph with structured-output routing. Durable per-tenant SQLite checkpointing, ChromaDB long-term memory, Obsidian vault reporting, token-usage tracking, API auth, two independent rate limiters (API layer and ingestion gate), SSE streaming, continuous alert ingestion (severity prefilter, dedup, three-tier correlation), real threat-intel enrichment, a full analyst-facing web dashboard, named-analyst approval accountability, webhook alerting, and off-box vault backup are all live and tested.

Every priority item on the originally-stated roadmap and all of Phase 8 (except the AbuseIPDB/VirusTotal live-key sub-item, honestly still open pending a real key) has shipped. This phase additionally closed two structural gaps found during a self-critical security review — ingestion paths bypassing rate limiting, and approval decisions carrying no reviewer identity — added a permanent automated regression test for prompt-injection resistance (previously only manually verified once), and shipped the alerting and vault-backup features needed to make this genuinely useful day-to-day rather than something an analyst has to remember to go check.

A follow-up 53-category pentest-style self-audit found and closed a Critical cross-tenant authorization gap, all 4 Medium findings, and 4 of 8 Low findings — mandatory-attribution and auth-failure-monitoring options, a hash-chained tamper-evidence ledger for the audit trail, and an actually-rehearsed backup/restore runbook (which caught a real gotcha: a naive `git clone` of the vault backup silently checks out nothing unless `--branch main` is given explicitly). The remaining 4 Low findings are documented tradeoffs, not oversights: data at rest is intentionally left to disk/filesystem-level encryption rather than bespoke application crypto; there's still no privilege-tier concept to gate (nothing exists yet that would need one); the "works offline" claim doesn't extend to the enrichment/alerting features that call real third-party APIs by design; and no independent second-party review has happened yet.

A second follow-up closed two more real gaps surfaced from real-world deployment thinking, not a formal review: fuzzy subnet correlation's IPv6 grouping was hardcoded to `/64` with no way to change it (IPv4 was already configurable) — now both address families are independently configurable, with real-world subnet-sizing guidance documented since most businesses don't subnet on `/24` boundaries the way the default implies. Separately, the three append-only JSONL logs this project writes (`ingestion_log.jsonl`, `auth_failures.jsonl`, `audit_chain_ledger.jsonl`) had no rotation and would have grown forever on a long-lived deployment — `utils/log_rotation.py` now caps and rotates all three, live-verified through the real ingestion pipeline, with the audit-chain ledger's tamper-evidence lookup specifically verified to still find an incident's true latest entry even after it's been rotated into a backup file.

A real Wazuh integration (a purpose-built normalizer plus both a tail path and a push-based custom-integration script) shipped alongside the above — the first vendor-specific SIEM/EDR connector this project has, live-verified end-to-end against the real ingestion pipeline with a realistic Wazuh alert, though the integration script's actual `ossec.conf` wiring remains unverified against a live Wazuh manager (none available), and is documented as such rather than assumed correct.

A self-critical pentest-style review across 53 security categories was also run this phase, and every finding it raised was fixed the same day: per-tenant API key scoping (closing a Critical cross-tenant access gap — a single shared key previously authorized every tenant), authenticated `/docs`/`/redoc`/`/openapi.json`, baseline security response headers, HMAC-signed outbound webhooks, and a pinned `requirements.lock.txt` for reproducible production installs. Nothing here was left as a documented-but-unfixed gap.

Seven interfaces (`main.py`, `cli.py`, `api.py` + the `static/` dashboard it serves, `ingest_watch.py`, `syslog_listener.py`, `poll_connector.py`, `vault_backup.py`) share one tenant-aware orchestration module and pass 372+ tests, including real socket/HTTP/git I/O, not mocks. Requires one of `GROQ_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, or a locally-running `OLLAMA_MODEL` to run.
