"""Tests ingestion/schemas.py:NormalizedAlert -- specifically the
process_name/command_line/parent_process_name -> prefixed-iocs folding
this project uses instead of trying to infer EDR-native indicators from a
bare string (see enrichment/ioc_classifier.py's own module docstring for
why that inference would be unreliable)."""

from ingestion.schemas import NormalizedAlert


def _alert(**overrides):
    defaults = dict(description="test alert", source="test", dedup_key="test:1")
    defaults.update(overrides)
    return NormalizedAlert(**defaults)


def test_process_context_folds_into_iocs_with_explicit_prefixes():
    alert = _alert(
        process_name="svchost.exe",
        command_line="powershell.exe -enc AAA",
        parent_process_name="explorer.exe",
    )
    assert "process:svchost.exe" in alert.iocs
    assert "cmdline:powershell.exe -enc AAA" in alert.iocs
    assert "parent:explorer.exe" in alert.iocs


def test_no_process_context_leaves_iocs_untouched():
    alert = _alert(iocs=["1.2.3.4"])
    assert alert.iocs == ["1.2.3.4"]


def test_process_context_is_appended_alongside_existing_iocs():
    alert = _alert(iocs=["1.2.3.4"], process_name="svchost.exe")
    assert alert.iocs == ["1.2.3.4", "process:svchost.exe"]


def test_process_context_deduplicates_against_an_already_present_entry():
    alert = _alert(iocs=["process:svchost.exe"], process_name="svchost.exe")
    assert alert.iocs.count("process:svchost.exe") == 1


def test_partial_process_context_only_folds_what_was_provided():
    alert = _alert(process_name="svchost.exe")
    assert alert.iocs == ["process:svchost.exe"]


def test_folding_respects_the_fifty_entry_cap():
    many_iocs = [f"1.2.3.{n}" for n in range(50)]
    alert = _alert(iocs=many_iocs, process_name="svchost.exe")
    assert len(alert.iocs) == 50
    assert "process:svchost.exe" not in alert.iocs  # budget was already full


def test_empty_process_fields_do_not_produce_bare_prefixes():
    alert = _alert(process_name="", command_line=None, parent_process_name=None)
    assert alert.iocs == []
