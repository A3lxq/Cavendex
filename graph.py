import os
import sqlite3
import threading

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph

from agents.investigator_agent import investigator_agent
from agents.responder_agent import responder_agent
from agents.threat_hunter_agent import threat_hunter_agent
from agents.triage_agent import triage_agent
from state import CavendexState
from utils.tenancy import DEFAULT_TENANT, sanitize_tenant_id


def route_next(state: CavendexState):
    return state.get("next_agent") or END


# Build the graph — an incident always starts at Triage; each agent's
# structured `decision` field drives `next_agent`, which the conditional
# edges below turn into an actual routing decision (this used to be a dead
# field: triage set next_agent="investigator" but the old graph had a fixed
# triage->END edge, so escalation never went anywhere). The graph's
# structure (nodes/edges) is shared across all tenants — only the
# checkpointer differs, so it's compiled once per tenant in get_app().
workflow = StateGraph(CavendexState)

workflow.add_node("triage", triage_agent)
workflow.add_node("investigator", investigator_agent)
workflow.add_node("threat_hunter", threat_hunter_agent)
workflow.add_node("responder", responder_agent)

workflow.add_edge(START, "triage")

workflow.add_conditional_edges(
    "triage",
    route_next,
    {"investigator": "investigator", END: END},
)
workflow.add_conditional_edges(
    "investigator",
    route_next,
    {"threat_hunter": "threat_hunter", "responder": "responder", END: END},
)
workflow.add_conditional_edges(
    "threat_hunter",
    route_next,
    {"responder": "responder", END: END},
)
# Responder never auto-routes further — it always stops and waits for a
# human to approve or deny its proposed actions (see
# workflows/incident_pipeline.py: resolve_proposed_actions).
workflow.add_edge("responder", END)

# Explicitly allow-list our own Pydantic model types for msgpack
# (de)serialization — without this, LangGraph logs a deprecation warning
# on every checkpoint read/write and will refuse to deserialize them at
# all in a future version. Shared across tenants; stateless.
_SERDE = JsonPlusSerializer(
    allowed_msgpack_modules=[("state", "Incident"), ("state", "ProposedAction")]
)

_apps: dict = {}
_apps_lock = threading.Lock()


def _base_data_dir() -> str:
    # Read lazily (not at import time) so CAVENDEX_DATA_DIR can be set
    # via load_dotenv() or monkeypatched in tests after this module is
    # first imported — same reasoning as utils.obsidian._vault_root().
    # Plain relative default (CWD-relative, same as CHROMA_PERSIST_DIR/
    # OBSIDIAN_VAULT_PATH's own ".chroma"/"obsidian_vault" defaults) —
    # not __file__-relative: once this module is installed into
    # site-packages, __file__'s directory isn't writable by a non-root
    # install and isn't where a user running `cavendex` from their own
    # directory would expect their data to land anyway.
    return os.getenv("CAVENDEX_DATA_DIR", "data")


def tenant_data_dir(tenant_id: str = DEFAULT_TENANT) -> str:
    """The per-tenant data directory other modules (e.g. the ingestion
    pipeline's raw-event log) can share without reaching into this
    module's private state — same base dir get_app() itself uses.
    """
    return os.path.join(_base_data_dir(), sanitize_tenant_id(tenant_id))


def get_app(tenant_id: str = DEFAULT_TENANT):
    """Return the compiled graph for a tenant, building and caching a
    dedicated SQLite checkpointer for it on first use.
    """
    tenant_id = sanitize_tenant_id(tenant_id)

    if tenant_id in _apps:
        return _apps[tenant_id]

    with _apps_lock:
        if tenant_id in _apps:  # re-check: another thread may have built it
            return _apps[tenant_id]

        tenant_dir = tenant_data_dir(tenant_id)
        os.makedirs(tenant_dir, exist_ok=True)
        db_path = os.path.join(tenant_dir, "cavendex.db")

        conn = sqlite3.connect(db_path, check_same_thread=False)
        checkpointer = SqliteSaver(conn, serde=_SERDE)
        checkpointer.setup()

        compiled = workflow.compile(checkpointer=checkpointer)
        _apps[tenant_id] = compiled
        return compiled
