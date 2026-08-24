"""Shared tenant-id handling.

Multi-tenancy scopes the SQLite checkpoint DB, the Obsidian vault, and the
ChromaDB collection per tenant — this is the one place that decides what a
tenant_id is allowed to look like once it becomes a filesystem path
component (a directory name) or a Chroma collection-name suffix. A
tenant_id can arrive directly from an API path segment or a CLI flag, so
it is never trusted verbatim.
"""

import re

DEFAULT_TENANT = "default"
_MAX_TENANT_ID_LENGTH = 64


def sanitize_tenant_id(tenant_id) -> str:
    """Normalize a tenant_id into a safe single path component.

    Unlike utils.obsidian._slugify (which preserves readability for
    freeform prose like an incident description), this uses a strict
    allowlist — a tenant_id is a handle, not prose, so there's no
    readability tradeoff to make: only letters, digits, underscore, and
    hyphen survive.
    """
    tenant_id = (tenant_id or DEFAULT_TENANT).strip()
    if not tenant_id:
        return DEFAULT_TENANT
    slug = re.sub(r"[^A-Za-z0-9_-]", "-", tenant_id)
    slug = slug[:_MAX_TENANT_ID_LENGTH].strip("-") or DEFAULT_TENANT
    return slug
