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


def test_rejects_malformed_ip_looking_string():
    assert classify_ioc("999.999.999.999") == "unknown"


def test_rejects_descriptive_phrases():
    assert classify_ioc("Suricata rule ID and payload signature indicating banner-grabbing") == "unknown"
    assert classify_ioc("DC-01") == "unknown"
    assert classify_ioc("") == "unknown"
