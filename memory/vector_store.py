"""Long-term incident memory via ChromaDB.

Backs the `long_term_summary` context every agent sees: past incidents are
embedded and stored here, and future incidents recall similar ones so the
organization's history actually informs new decisions instead of resetting
on every run. Scoped per tenant — each tenant gets its own persistence
directory and collection, so one org's incident history never leaks into
another's recall context.
"""

import os
import threading
from typing import List

from utils.tenancy import DEFAULT_TENANT, sanitize_tenant_id

_COLLECTION_NAME = "cavendex_incidents"

_collections: dict = {}
_collections_lock = threading.Lock()


def _get_collection(tenant_id: str = DEFAULT_TENANT):
    tenant_id = sanitize_tenant_id(tenant_id)

    if tenant_id in _collections:
        return _collections[tenant_id]

    with _collections_lock:
        if tenant_id in _collections:
            return _collections[tenant_id]

        import chromadb

        # Read lazily (not at import time) so CHROMA_PERSIST_DIR can be set
        # via load_dotenv() or monkeypatched in tests after this module is
        # first imported.
        base_dir = os.getenv("CHROMA_PERSIST_DIR", ".chroma")
        persist_dir = os.path.join(base_dir, tenant_id)
        client = chromadb.PersistentClient(path=persist_dir)
        collection = client.get_or_create_collection(_COLLECTION_NAME)
        _collections[tenant_id] = collection
        return collection


def remember_incident(
    incident_id: str,
    description: str,
    summary: str,
    severity: str,
    tenant_id: str = DEFAULT_TENANT,
) -> None:
    """Persist a short summary of a handled incident for future recall."""
    collection = _get_collection(tenant_id)
    collection.upsert(
        ids=[incident_id],
        documents=[summary],
        metadatas=[{"description": description, "severity": severity}],
    )


def recall_similar_incidents(
    description: str, k: int = 3, tenant_id: str = DEFAULT_TENANT
) -> List[str]:
    """Return short summaries of the k most similar past incidents, if any."""
    collection = _get_collection(tenant_id)
    count = collection.count()
    if count == 0:
        return []
    results = collection.query(query_texts=[description], n_results=min(k, count))
    documents = results.get("documents") or [[]]
    return documents[0]
