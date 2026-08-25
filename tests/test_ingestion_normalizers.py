from ingestion.normalizers import (
    normalize_crowdstrike,
    normalize_generic,
    normalize_splunk,
    normalize_suricata_eve,
    normalize_syslog_cef,
    normalize_wazuh,
)


def test_normalize_generic_uses_provided_fields():
    alert = normalize_generic(
        {"description": "test alert", "severity": "high", "source": "my-script", "iocs": ["1.2.3.4"]}
    )
    assert alert.description == "test alert"
    assert alert.severity == "high"
    assert alert.source == "my-script"
    assert alert.iocs == ["1.2.3.4"]


def test_normalize_generic_falls_back_to_defaults():
    alert = normalize_generic({})
    assert alert.description == "Untitled alert"
    assert alert.severity == "medium"
    assert alert.source == "generic"


def test_normalize_generic_rejects_invalid_severity():
    alert = normalize_generic({"description": "x", "severity": "nuke-everything"})
    assert alert.severity == "medium"


def test_normalize_suricata_ignores_non_alert_events():
    assert normalize_suricata_eve({"event_type": "flow"}) is None
    assert normalize_suricata_eve({"event_type": "dns"}) is None


def test_normalize_suricata_maps_alert_fields():
    alert = normalize_suricata_eve(
        {
            "event_type": "alert",
            "src_ip": "203.0.113.5",
            "src_port": 44123,
            "dest_ip": "10.0.0.9",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "signature": "ET SCAN Potential SSH Scan",
                "signature_id": 2001219,
                "category": "Attempted Information Leak",
                "severity": 1,
            },
        }
    )
    assert alert is not None
    assert alert.severity == "high"
    assert alert.source == "suricata"
    assert "203.0.113.5" in alert.iocs
    assert "10.0.0.9" in alert.affected_assets
    assert alert.dedup_key == "suricata:2001219:203.0.113.5:10.0.0.9"


def test_normalize_cef_parses_valid_line():
    line = r"<134>CEF:0|PaloAltoNetworks|PAN-OS|10.1|100|Port Scan Detected|7|src=198.51.100.4 dst=10.0.0.5 dpt=3389"
    alert = normalize_syslog_cef({"raw": line})
    assert alert is not None
    assert alert.severity == "high"
    assert alert.source == "syslog_cef"
    assert "198.51.100.4" in alert.iocs
    assert "10.0.0.5" in alert.affected_assets


def test_normalize_cef_rejects_non_cef_line():
    assert normalize_syslog_cef({"raw": "this is not a CEF line"}) is None
    assert normalize_syslog_cef({}) is None


def test_normalize_cef_severity_scale_mapping():
    def sev(n):
        line = f"CEF:0|V|P|1.0|1|name|{n}|src=1.1.1.1 dst=2.2.2.2"
        return normalize_syslog_cef({"raw": line}).severity

    assert sev(0) == "low"
    assert sev(4) == "medium"
    assert sev(7) == "high"
    assert sev(9) == "critical"


def test_normalize_wazuh_rejects_payload_with_no_rule():
    assert normalize_wazuh({}) is None
    assert normalize_wazuh({"agent": {"name": "web-01"}}) is None


def test_normalize_wazuh_maps_alert_fields():
    alert = normalize_wazuh(
        {
            "rule": {
                "id": "5720",
                "level": 10,
                "description": "Multiple authentication failures.",
                "mitre": {"id": ["T1110"]},
            },
            "agent": {"id": "001", "name": "web-server-01"},
            "data": {"srcip": "203.0.113.7"},
        }
    )
    assert alert is not None
    assert alert.severity == "high"
    assert alert.source == "wazuh"
    assert "203.0.113.7" in alert.iocs
    assert "web-server-01" in alert.affected_assets
    assert "T1110" in alert.description
    assert alert.dedup_key == "wazuh:5720:001:203.0.113.7"


def test_normalize_wazuh_handles_missing_optional_fields():
    alert = normalize_wazuh({"rule": {"id": "100", "level": 3, "description": "Test rule"}})
    assert alert is not None
    assert alert.severity == "low"
    assert alert.iocs == []
    assert alert.affected_assets == []
    assert alert.dedup_key == "wazuh:100:0:na"


def test_normalize_wazuh_collects_file_hash_and_url_iocs():
    alert = normalize_wazuh(
        {
            "rule": {"id": "550", "level": 7, "description": "File changed"},
            "agent": {"id": "002", "name": "endpoint-02"},
            "data": {"md5": "d41d8cd98f00b204e9800998ecf8427e", "url": "http://evil.example.com/payload"},
        }
    )
    assert alert is not None
    assert "d41d8cd98f00b204e9800998ecf8427e" in alert.iocs
    assert "http://evil.example.com/payload" in alert.iocs


def test_normalize_wazuh_severity_scale_mapping():
    def sev(level):
        return normalize_wazuh({"rule": {"id": "1", "level": level, "description": "x"}}).severity

    assert sev(0) == "low"
    assert sev(4) == "medium"
    assert sev(7) == "high"
    assert sev(12) == "critical"


# ---------- Splunk ----------


def test_normalize_splunk_rejects_payload_with_no_rule_name():
    assert normalize_splunk({}) is None
    assert normalize_splunk({"urgency": "high"}) is None


def test_normalize_splunk_maps_flat_notable_event_fields():
    alert = normalize_splunk(
        {
            "rule_name": "Excessive Failed Logins",
            "urgency": "high",
            "src": "203.0.113.7",
            "dest": "WEB-01",
            "dvc": "fw-01",
            "signature": "Brute Force Attempt",
            "event_id": "abc-123",
            "mitre_technique_id": "T1110,T1078",
        }
    )
    assert alert is not None
    assert alert.severity == "high"
    assert alert.source == "splunk"
    assert "203.0.113.7" in alert.iocs
    assert "WEB-01" in alert.affected_assets
    assert "fw-01" in alert.affected_assets
    assert "T1110" in alert.description and "T1078" in alert.description
    assert alert.dedup_key == "splunk:abc-123:203.0.113.7:WEB-01"


def test_normalize_splunk_unwraps_webhook_result_key():
    """Splunk's own 'Webhook' alert action wraps the notable event's own
    fields inside a top-level 'result' key -- this must unwrap it rather
    than treating the whole webhook envelope as the record."""
    alert = normalize_splunk({"sid": "12345", "search_name": "x", "result": {"rule_name": "Wrapped Event"}})
    assert alert is not None
    assert "Wrapped Event" in alert.description


def test_normalize_splunk_accepts_mitre_technique_id_as_a_list():
    alert = normalize_splunk({"rule_name": "x", "mitre_technique_id": ["T1110", "T1078"]})
    assert "T1110" in alert.description and "T1078" in alert.description


def test_normalize_splunk_urgency_scale_mapping():
    def sev(urgency):
        return normalize_splunk({"rule_name": "x", "urgency": urgency}).severity

    assert sev("informational") == "low"
    assert sev("low") == "low"
    assert sev("medium") == "medium"
    assert sev("high") == "high"
    assert sev("critical") == "critical"
    assert sev("not-a-real-value") == "medium"


def test_normalize_splunk_handles_missing_optional_fields():
    alert = normalize_splunk({"rule_name": "Minimal Event"})
    assert alert is not None
    assert alert.severity == "medium"
    assert alert.iocs == []
    assert alert.affected_assets == []


# ---------- CrowdStrike ----------


def test_normalize_crowdstrike_rejects_payload_with_no_detection_id():
    assert normalize_crowdstrike({}) is None
    assert normalize_crowdstrike({"max_severity_displayname": "High"}) is None


def test_normalize_crowdstrike_maps_detection_summary_fields():
    alert = normalize_crowdstrike(
        {
            "detection_id": "ldt:abc:123",
            "max_severity_displayname": "High",
            "device": {"hostname": "WORKSTATION-01"},
            "behaviors": [
                {
                    "tactic": "Credential Access",
                    "technique": "OS Credential Dumping",
                    "technique_id": "T1003",
                    "ioc_type": "hash_sha256",
                    "ioc_value": "d41d8cd98f00b204e9800998ecf8427e",
                }
            ],
        }
    )
    assert alert is not None
    assert alert.severity == "high"
    assert alert.source == "crowdstrike"
    assert "WORKSTATION-01" in alert.affected_assets
    assert "WORKSTATION-01" in alert.description
    assert "d41d8cd98f00b204e9800998ecf8427e" in alert.iocs
    assert "T1003" in alert.description
    assert "OS Credential Dumping" in alert.description
    assert alert.dedup_key == "crowdstrike:ldt:abc:123"


def test_normalize_crowdstrike_handles_missing_optional_fields():
    alert = normalize_crowdstrike({"detection_id": "ldt:minimal:1"})
    assert alert is not None
    assert alert.severity == "medium"
    assert alert.affected_assets == []
    assert alert.iocs == []
    assert "unknown host" in alert.description


def test_normalize_crowdstrike_severity_scale_mapping():
    def sev(name):
        return normalize_crowdstrike({"detection_id": "x", "max_severity_displayname": name}).severity

    assert sev("Informational") == "low"
    assert sev("Low") == "low"
    assert sev("Medium") == "medium"
    assert sev("High") == "high"
    assert sev("Critical") == "critical"
    assert sev("Not A Real Value") == "medium"


def test_normalize_crowdstrike_deduplicates_repeated_technique_ids():
    alert = normalize_crowdstrike(
        {
            "detection_id": "x",
            "behaviors": [
                {"technique_id": "T1003", "technique": "OS Credential Dumping"},
                {"technique_id": "T1003", "technique": "OS Credential Dumping"},
            ],
        }
    )
    assert alert.description.count("T1003") == 1
