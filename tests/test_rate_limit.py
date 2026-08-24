from utils.rate_limit import check_rate_limit


def test_allows_requests_under_the_limit(monkeypatch):
    monkeypatch.setenv("SENTINELOS_RATE_LIMIT_PER_MINUTE", "3")
    key = "test-under-limit"
    for _ in range(3):
        assert check_rate_limit(key, now=1000.0) is None


def test_blocks_requests_over_the_limit(monkeypatch):
    monkeypatch.setenv("SENTINELOS_RATE_LIMIT_PER_MINUTE", "2")
    key = "test-over-limit"
    assert check_rate_limit(key, now=1000.0) is None
    assert check_rate_limit(key, now=1000.0) is None
    retry_after = check_rate_limit(key, now=1000.0)
    assert retry_after is not None
    assert retry_after > 0


def test_window_expires_after_sixty_seconds(monkeypatch):
    monkeypatch.setenv("SENTINELOS_RATE_LIMIT_PER_MINUTE", "1")
    key = "test-window-expiry"
    assert check_rate_limit(key, now=1000.0) is None
    assert check_rate_limit(key, now=1010.0) is not None  # still within the window
    assert check_rate_limit(key, now=1061.0) is None  # window has rolled past


def test_zero_limit_disables_rate_limiting(monkeypatch):
    monkeypatch.setenv("SENTINELOS_RATE_LIMIT_PER_MINUTE", "0")
    key = "test-disabled"
    for _ in range(50):
        assert check_rate_limit(key, now=1000.0) is None


def test_different_keys_are_independent(monkeypatch):
    monkeypatch.setenv("SENTINELOS_RATE_LIMIT_PER_MINUTE", "1")
    assert check_rate_limit("key-a", now=1000.0) is None
    assert check_rate_limit("key-b", now=1000.0) is None  # independent bucket
    assert check_rate_limit("key-a", now=1000.0) is not None  # key-a's bucket is full
