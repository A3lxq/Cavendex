from utils.tenancy import DEFAULT_TENANT, sanitize_tenant_id


def test_sanitize_tenant_id_passes_through_clean_ids():
    assert sanitize_tenant_id("acme-corp") == "acme-corp"
    assert sanitize_tenant_id("Acme_Corp_123") == "Acme_Corp_123"


def test_sanitize_tenant_id_defaults_for_empty_or_none():
    assert sanitize_tenant_id(None) == DEFAULT_TENANT
    assert sanitize_tenant_id("") == DEFAULT_TENANT
    assert sanitize_tenant_id("   ") == DEFAULT_TENANT


def test_sanitize_tenant_id_strips_path_traversal_characters():
    assert "/" not in sanitize_tenant_id("../../etc/passwd")
    assert "\\" not in sanitize_tenant_id("..\\..\\windows")


def test_sanitize_tenant_id_caps_length():
    huge = "a" * 500
    assert len(sanitize_tenant_id(huge)) <= 64


def test_sanitize_tenant_id_only_allows_safe_characters():
    result = sanitize_tenant_id("acme corp! <script>alert(1)</script>")
    assert all(c.isalnum() or c in "_-" for c in result)
