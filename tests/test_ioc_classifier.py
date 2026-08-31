from enrichment.ioc_classifier import classify_ioc


def test_classifies_ipv4():
    assert classify_ioc("203.0.113.5") == "ip"


def test_classifies_ipv6():
    assert classify_ioc("2001:db8::1") == "ip"


def test_classifies_domain():
    assert classify_ioc("example.com") == "domain"
    assert classify_ioc("evil.attacker.example.net") == "domain"


def test_classifies_hashes():
    assert classify_ioc("d41d8cd98f00b204e9800998ecf8427e") == "hash"  # md5
    assert classify_ioc("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"  # sha1
    assert classify_ioc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"  # sha256


def test_classifies_urls():
    assert classify_ioc("http://evil.example.com/payload.exe") == "url"
    assert classify_ioc("https://evil.example.com/path?query=1") == "url"
    assert classify_ioc("HTTPS://EVIL.EXAMPLE.COM/") == "url"  # case-insensitive scheme


def test_bare_domain_with_path_is_not_a_url_without_a_scheme():
    # No scheme -> ambiguous, deliberately not guessed as a URL.
    assert classify_ioc("evil.example.com/payload.exe") == "unknown"


def test_rejects_malformed_ip_looking_string():
    assert classify_ioc("999.999.999.999") == "unknown"


def test_rejects_descriptive_phrases():
    assert classify_ioc("Suricata rule ID and payload signature indicating banner-grabbing") == "unknown"
    assert classify_ioc("DC-01") == "unknown"
    assert classify_ioc("") == "unknown"


def test_classifies_cve():
    assert classify_ioc("CVE-2021-44228") == "cve"
    assert classify_ioc("cve-2014-0160") == "cve"  # case-insensitive
    assert classify_ioc("CVE-2023-1234567") == "cve"  # 7-digit sequence number


def test_rejects_malformed_cve_looking_strings():
    assert classify_ioc("CVE-21-1234") == "unknown"  # 2-digit year
    assert classify_ioc("NOTCVE-2021-1234") == "unknown"
    assert classify_ioc("CVE-2021-123") == "unknown"  # sequence too short
