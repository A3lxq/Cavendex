# Cavendex — Session Handoff

A snapshot for resuming work in a fresh chat. State as of commit `900951e`.

## Project summary

**Cavendex** (local folder name `SentinelOS`) is an open-source, multi-agent AI SOC analyst: Triage → Investigator → optional Threat Hunter → Responder (LangGraph), with a human approval gate before anything executes.

- **Repo:** `git@github.com:A3lxq/Cavendex.git` (public, Apache 2.0), branch `main`
- **Stack:** FastAPI + vanilla HTML/CSS/JS dashboard (`static/`), SQLite checkpoints, ChromaDB memory, Obsidian vault reports. Python 3.14 venv at `./venv`. Local LLM via Ollama (`qwen3.6:latest`, set `OLLAMA_MODEL`). No `.env` file exists.
- **Built and pushed:**
  - A 9-phase SOC-gap plan, all complete and verified against the code: fast-path LLM, audit-export anchor, EDR process IOC types, SOC KPIs, OIDC SSO, Elastic connector, CrowdStrike RTR example, Jira sync, live threat-intel verification.
  - QRadar and Microsoft Sentinel connectors.
  - 20 threat-intel providers, 9 ingestion formats, 922 tests.
  - A beautified `README.md` (badges, hero screenshot, TOC, gallery) with real dashboard captures in `docs/screenshots/`.

## Recent history

- `b6c12b2` Beautify README: badges, TOC, real dashboard screenshots
- `aaffcb2` / `f019c96` Added temporary Instagram reel assets (`marketing/`)
- `900951e` Removed the reel assets (still in git history if ever needed)

## Known open items

1. Wazuh integration has not been verified against a real Wazuh manager.
2. AbuseIPDB and VirusTotal have no live-key validation.
3. UI nit: the `PENDING_APPROVAL` badge overlaps the description text in the incident list row (`static/style.css` / `static/app.js`).
4. The gitignored `data/default/` tenant holds leftover test incidents.

## Prompt for the next chat

```
I'm continuing work on Cavendex (folder: ~/Claude_conversations/Sentinal_OS/SentinelOS), an open-source multi-agent AI SOC analyst (FastAPI + LangGraph + vanilla JS dashboard). Repo: git@github.com:A3lxq/Cavendex.git, branch main. Read HANDOFF.md first.

Context: all 9 planned SOC-gap phases are done and pushed, plus QRadar/Sentinel connectors, a beautified README with real screenshots (docs/screenshots/), 20 threat-intel providers, and 922 tests. There is no .env; for live agent runs use OLLAMA_MODEL=qwen3.6:latest. Python venv is at ./venv. Do not commit or push without asking me first.

Known open items are listed in HANDOFF.md.

Start by reading README.md and HANDOFF.md, then run `git log --oneline -10` and `pytest -q` to confirm the baseline, and tell me what you recommend tackling first. Today I want to: <describe your goal here>
```
