from utils.dedup import is_duplicate, reset_for_tests


def setup_function():
    reset_for_tests()


def test_first_sighting_is_not_a_duplicate(monkeypatch):
    monkeypatch.setenv("SENTINELOS_DEDUP_WINDOW_SECONDS", "300")
    assert is_duplicate("tenant-a", "key-1", now=1000.0) is False


def test_repeat_within_window_is_a_duplicate(monkeypatch):
    monkeypatch.setenv("SENTINELOS_DEDUP_WINDOW_SECONDS", "300")
    assert is_duplicate("tenant-a", "key-1", now=1000.0) is False
    assert is_duplicate("tenant-a", "key-1", now=1100.0) is True  # 100s later, within 300s window


def test_repeat_after_window_is_not_a_duplicate(monkeypatch):
    monkeypatch.setenv("SENTINELOS_DEDUP_WINDOW_SECONDS", "300")
    assert is_duplicate("tenant-a", "key-1", now=1000.0) is False
    assert is_duplicate("tenant-a", "key-1", now=1400.0) is False  # 400s later, past the window


def test_zero_window_disables_dedup(monkeypatch):
    monkeypatch.setenv("SENTINELOS_DEDUP_WINDOW_SECONDS", "0")
    assert is_duplicate("tenant-a", "key-1", now=1000.0) is False
    assert is_duplicate("tenant-a", "key-1", now=1000.0) is False


def test_different_tenants_have_independent_dedup_state(monkeypatch):
    monkeypatch.setenv("SENTINELOS_DEDUP_WINDOW_SECONDS", "300")
    assert is_duplicate("tenant-a", "key-1", now=1000.0) is False
    assert is_duplicate("tenant-b", "key-1", now=1000.0) is False  # same key, different tenant
