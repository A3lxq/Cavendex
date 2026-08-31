from utils.incident_notes import add_note, list_notes, reset_for_tests


def setup_function():
    reset_for_tests()


def test_add_then_list_returns_the_note(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))

    note = add_note("t1", "inc-1", "Checked with the user, login was expected.", author="j.smith")

    assert note["author"] == "j.smith"
    assert note["text"] == "Checked with the user, login was expected."
    assert "id" in note and "created_at" in note

    notes = list_notes("t1", "inc-1")
    assert len(notes) == 1
    assert notes[0]["text"] == "Checked with the user, login was expected."


def test_notes_ordered_oldest_first(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    add_note("t1", "inc-1", "first")
    add_note("t1", "inc-1", "second")
    add_note("t1", "inc-1", "third")

    notes = list_notes("t1", "inc-1")
    assert [n["text"] for n in notes] == ["first", "second", "third"]


def test_notes_scoped_per_thread(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    add_note("t1", "inc-1", "note on inc-1")
    add_note("t1", "inc-2", "note on inc-2")

    assert [n["text"] for n in list_notes("t1", "inc-1")] == ["note on inc-1"]
    assert [n["text"] for n in list_notes("t1", "inc-2")] == ["note on inc-2"]


def test_notes_scoped_per_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    add_note("acme", "inc-1", "acme's note")
    add_note("globex", "inc-1", "globex's note")

    assert [n["text"] for n in list_notes("acme", "inc-1")] == ["acme's note"]
    assert [n["text"] for n in list_notes("globex", "inc-1")] == ["globex's note"]


def test_missing_author_recorded_as_none_not_a_placeholder(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    note = add_note("t1", "inc-1", "anonymous-ish note")
    assert note["author"] is None
    assert list_notes("t1", "inc-1")[0]["author"] is None


def test_empty_note_text_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    try:
        add_note("t1", "inc-1", "   ")
        assert False, "expected ValueError"
    except ValueError:
        pass
    assert list_notes("t1", "inc-1") == []


def test_note_text_is_truncated_to_a_sane_length(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    note = add_note("t1", "inc-1", "x" * 5000)
    assert len(note["text"]) == 2000


def test_no_notes_returns_empty_list(monkeypatch, tmp_path):
    monkeypatch.setenv("CAVENDEX_DATA_DIR", str(tmp_path))
    assert list_notes("t1", "never-noted") == []
