from enrichment.mitre_attack import lookup_technique, validate_technique_citation


def test_lookup_finds_known_technique():
    result = lookup_technique("T1110")
    assert result == {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}


def test_lookup_finds_known_sub_technique():
    result = lookup_technique("T1110.001")
    assert result["name"] == "Brute Force: Password Guessing"


def test_lookup_is_case_insensitive():
    assert lookup_technique("t1110") == lookup_technique("T1110")


def test_lookup_falls_back_to_parent_for_unknown_sub_technique():
    result = lookup_technique("T1110.999")
    assert result["id"] == "T1110.999"
    assert result["name"] == "Brute Force"  # parent's name/tactic


def test_lookup_returns_none_for_unknown_id():
    assert lookup_technique("T9999") is None


def test_lookup_returns_none_for_empty_input():
    assert lookup_technique(None) is None
    assert lookup_technique("") is None


def test_validate_citation_returns_none_when_nothing_cited():
    assert validate_technique_citation(None) is None
    assert validate_technique_citation("") is None
    assert validate_technique_citation("   ") is None


def test_validate_citation_marks_known_technique_verified():
    result = validate_technique_citation("T1046")
    assert result["verified"] is True
    assert result["name"] == "Network Service Discovery"


def test_validate_citation_flags_hallucinated_technique():
    result = validate_technique_citation("T1337")
    assert result["verified"] is False
    assert result["name"] is None
    assert result["id"] == "T1337"


def test_validate_citation_tolerates_name_appended_to_id():
    # Observed live: a model citing "T1110 - Brute Force" or "T1110: Brute
    # Force" instead of a clean "T1110" — this must still verify, since
    # the underlying citation is correct; only the format is noisy.
    for citation in ["T1110 - Brute Force", "T1110 - BRUTE FORCE", "T1110: Brute Force", "t1110 (brute force)"]:
        result = validate_technique_citation(citation)
        assert result["verified"] is True, f"expected verified for {citation!r}, got {result}"
        assert result["id"] == "T1110"


def test_validate_citation_extracts_clean_id_even_when_unverified():
    result = validate_technique_citation("T9999 - Made Up Technique")
    assert result["verified"] is False
    assert result["id"] == "T9999"  # extracted ID, not the whole noisy phrase
