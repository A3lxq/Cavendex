# Getting Started with Cavendex

This is the friendly, no-assumptions walkthrough. If you've never used an
AI agent tool before, or you're a SOC analyst who just wants to see this
thing work without reading an architecture doc first, start here.

Already comfortable with the codebase? **[README.md](README.md)** has the
full feature list and architecture. Deploying this as a real, always-on
service? That's **[DEPLOYMENT.md](DEPLOYMENT.md)**. Don't recognize a
term? Check the **[GLOSSARY.md](GLOSSARY.md)**.

---

## What is this, actually?

Cavendex reads a security alert (a suspicious login, a malware hit, a
weird outbound connection) and does the first hour of an analyst's work
for you:

1. **Decides how serious it is**, using real threat-intel lookups where
   it can, not just guessing.
2. **Investigates** — pulls in what it knows about similar past
   incidents, checks IOCs against reputation databases, validates any
   MITRE ATT&CK technique it cites.
3. **Drafts a response plan** — "block this IP," "isolate this host" —
   but never carries it out.
4. **Waits for you.** Nothing happens to a real system until a human
   clicks Approve or Deny.

Everything it does is written down in a searchable, linkable set of
Markdown files (an "Obsidian vault") so you have a permanent record of
what happened and why — not just something that scrolled off a terminal.

---

## Step 1: Get it running (5–10 minutes)

You need Python 3.10+ and one of: a free [Groq](https://console.groq.com)
API key, a free [Google AI Studio](https://aistudio.google.com/apikey)
key, or [Ollama](https://ollama.com) running locally (no key at all, but
slower on a laptop).

**Recommended — install it as a real command:**

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install .
cp .env.example .env
```

**Alternative — from source**, if you want to read or modify the code
as you go:

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Either way, open `.env` in any text editor and paste your key into one
line, e.g.:

```env
GROQ_API_KEY=gsk_your_actual_key_here
```

Leave everything else in `.env` alone for now — the defaults are fine to
start.

Run the built-in demo:

```bash
cavendex demo      # if you installed with `pip install .`
python main.py     # if you're running from source
```

If you see agent output scroll by ending in a proposed action, it
worked. If you see a Python error instead, jump to
[Troubleshooting](#troubleshooting) below.

Rather skip local Python setup entirely? `docker compose up -d` after
the same `cp .env.example .env` step gets you the dashboard at
`http://localhost:8000/` with nothing installed on your machine but
Docker — see README's **[Installation](README.md#installation)** section.

---

## Step 2: Open the dashboard

This is the part most analysts will actually use day to day.

```bash
cavendex serve --reload   # if you installed with `pip install .`
uvicorn api:api --reload  # if you're running from source
```

Open **http://localhost:8000/** in a browser. You should see:

- An **incident queue** on the left (empty until you create one).
- A **New Incident** tab — a form to describe an alert in plain English.
- A **Threat Hunt** tab — ask a free-text question like "any signs of a
  broader credential-stuffing campaign?"

At the top of the page there's an **Analyst name** field. Type your name
or initials in it now — it gets recorded every time you approve or deny
something, so the audit trail shows *who* made each call instead of just
"someone did."

Try the demo incident from **[Step 1](#step-1-get-it-running-510-minutes)**, or fill out **New Incident** with
something like:

> Multiple failed logins from 1.2.3.4 targeting DC-01

Watch it stream through Triage → Investigator → (maybe) Threat Hunter →
Responder in real time.

---

## Step 3: Approve or deny your first action

If an incident reaches the Responder stage, it proposes an action (e.g.
"block 1.2.3.4 at the firewall") and stops. You'll see **Approve** /
**Deny** buttons in the incident's detail pane.

**Nothing happens to a real system either way** — Cavendex never has
firewall/EDR/IAM access. Approving just records the decision; wiring a
real system action to it is future work, and always will require this
same approval step.

Click one. The button becomes an "Approved by `<your name>`" or "Denied
by `<your name>`" badge — no page reload needed.

---

## Step 4: Find your incident report

Every incident writes a Markdown file with the full story — description,
findings, threat intel, the decision, who approved it — into
`obsidian_vault/default/`.

You don't need [Obsidian](https://obsidian.md) to read these; they're
plain Markdown, openable in any text editor. But if you install the free
Obsidian app and point it at that folder, you get a clickable graph
showing how incidents, IOCs, and affected assets connect to each other —
useful once you have more than a handful of incidents.

---

## Step 5 (optional): Get notified instead of checking the dashboard

By default, Cavendex doesn't tell anyone anything — you have to go
look. If you want a Slack/Discord/Teams message (or your own webhook
relay) whenever an incident needs your approval or hits high/critical
severity, set one line in `.env`:

```env
CAVENDEX_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
```

That's it. No code changes, no vendor-specific setup — it POSTs a plain
JSON payload that Slack, Discord, and Microsoft Teams incoming webhooks
all render natively.

---

## Step 6 (optional): Back up your incident vault to GitHub

Your incident vault is the durable record of everything Cavendex has
ever seen — worth having a copy somewhere other than this one machine.
`vault_backup.py` commits and pushes it to a git remote of your choice on
an interval:

```bash
cavendex backup --remote git@github.com:you/your-private-vault-repo.git   # pip install .
python vault_backup.py --remote git@github.com:you/your-private-vault-repo.git   # from source
```

**Use a private repository.** Your vault contains real incident
descriptions, IOCs, and asset names from your environment. `vault_backup.py`
does not and cannot make the repo private for you — that's on you, when
you create it on GitHub (or wherever you host it).

Want to try it without pushing anywhere yet? Add `--no-push` to either
command above to commit locally only.

---

## Troubleshooting

**`ModuleNotFoundError` when running `python main.py`, or `cavendex: command not found`**
Your virtual environment isn't active, or the install step didn't
finish. Run `source venv/bin/activate` again and re-run `pip install .`
(or `pip install -r requirements.txt` if you're running from source).

**The demo just prints an error about no provider being configured**
`.env` doesn't have a real key in it yet, or you're editing a different
`.env` than the one in this folder. Double-check `cat .env` shows your
key.

**The dashboard loads but says "disconnected" or incidents never appear**
Make sure `cavendex serve`/`uvicorn api:api --reload` is still running in
a terminal — the dashboard is just a webpage that talks to that process.
Check that terminal for a Python traceback.

**Every dashboard action returns a 401 error**
You set `CAVENDEX_API_KEY` in `.env` but haven't entered the same key
in the dashboard's own **API Key** field (top bar) — it's a separate,
browser-side value.

**A local Ollama run seems to hang**
It's probably not hanging — a full incident run on a local model can
genuinely take several minutes on modest hardware. Check `top`/`htop` for
CPU activity from the Ollama process before assuming it's stuck.

**Still stuck?** Re-read this guide's **[Step 1](#step-1-get-it-running-510-minutes)**–**[Step 2](#step-2-open-the-dashboard)** first — most issues are a
missing/misplaced `.env` value. For anything about *why* Cavendex
behaves a certain way (not just how to run it), README.md's
**[Known Gaps](README.md#known-gaps--honest-limitations)** and
**[Security Notes](README.md#security-notes)** sections are the honest source of truth.

---

## Where to go next

- **[README.md](README.md)** — full feature list, architecture, and the honest list
  of what this tool does *not* do yet.
- **[DEPLOYMENT.md](DEPLOYMENT.md)** — running this as an always-on service that watches
  real logs, with systemd units and a TLS reverse-proxy setup.
- **[GLOSSARY.md](GLOSSARY.md)** — every Cavendex-specific term (tenant, IOC,
  correlation, etc.) in one place.
