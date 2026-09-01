import os
import sys

from dotenv import find_dotenv, load_dotenv

# Load environment variables first
# find_dotenv(usecwd=True): search from the caller's working directory,
# not this file's location — matters once this module is installed
# into site-packages and run as `cavendex demo` from wherever a user's
# .env actually lives.
load_dotenv(find_dotenv(usecwd=True), override=True)

has_groq = bool(os.getenv("GROQ_API_KEY"))
has_openai = bool(os.getenv("OPENAI_API_KEY"))
has_anthropic = bool(os.getenv("ANTHROPIC_API_KEY"))
has_google = bool(os.getenv("GOOGLE_API_KEY"))
has_ollama = bool(os.getenv("OLLAMA_MODEL"))

print("🔑 GROQ_API_KEY loaded:", has_groq)
print("🔑 OPENAI_API_KEY loaded:", has_openai)
print("🔑 ANTHROPIC_API_KEY loaded:", has_anthropic)
print("🔑 GOOGLE_API_KEY loaded:", has_google)
print("🔑 OLLAMA_MODEL configured:", has_ollama)

if not any([has_groq, has_openai, has_anthropic, has_google, has_ollama]):
    print(
        "\n❌ No LLM provider configured. Copy .env.example to .env and add "
        "a GROQ_API_KEY (preferred, free tier), OPENAI_API_KEY, "
        "ANTHROPIC_API_KEY, GOOGLE_API_KEY, or OLLAMA_MODEL (for a local "
        "model, no key required), then rerun."
    )
    sys.exit(1)

from workflows.incident_pipeline import run_new_incident


def _msg_name_content(msg):
    if isinstance(msg, dict):
        return msg.get("name") or msg.get("role", "assistant"), msg.get("content", "")
    return getattr(msg, "name", None) or "Agent", getattr(msg, "content", "")


def run_pipeline_demo():
    print("\n🚀 Starting Cavendex incident pipeline...\n")

    try:
        # No fixed thread_id here on purpose: checkpointing is now durable
        # (SQLite), so a hardcoded thread_id would keep resuming the same
        # incident thread across every `python main.py` run instead of
        # demoing a fresh one each time.
        final_state = run_new_incident(
            description=(
                "Multiple failed login attempts from suspicious IP 185.220.101.45 "
                "targeting WEB-SRV-01 (Domain Controller). 47 attempts in 3 minutes."
            ),
            severity="high",
            affected_assets=["WEB-SRV-01", "DC-01"],
            iocs=["185.220.101.45"],
            source="SIEM",
        )
    except Exception as exc:
        print(f"\n❌ Cavendex run failed: {exc}")
        sys.exit(1)

    incident = final_state.get("incident")

    print("\n" + "=" * 70)
    print(f"✅ PIPELINE RESULT — status: {incident.status if incident else 'unknown'}")
    print("=" * 70)

    for msg in final_state.get("messages", []) or []:
        name, content = _msg_name_content(msg)
        print(f"\n[{name}]\n{content}")

    proposed = final_state.get("proposed_actions", []) or []
    if proposed:
        print("\nProposed Actions (pending human approval):")
        for a in proposed:
            print(f"  - {a.action} → {a.target} ({a.rationale})")
        print(
            f"\nRun `python cli.py approve {incident.id}` or "
            f"`python cli.py deny {incident.id}` to resolve."
        )

    usage = final_state.get("token_usage") or {}
    if usage:
        print(
            f"\nToken Usage: {usage.get('total_tokens', 0)} total "
            f"({usage.get('input_tokens', 0)} in / {usage.get('output_tokens', 0)} out)"
        )

    print("\nAudit Log:")
    for entry in final_state.get("audit_log", []):
        print(f"  • {entry}")

    print("\n📓 Obsidian vault report written — open the obsidian_vault/ folder as a vault to view it.")


if __name__ == "__main__":
    run_pipeline_demo()
