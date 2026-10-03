"""Parser and detector behavior on realistic Suricata events."""

import json
from datetime import datetime, timedelta, timezone

from autodefender.config import Config
from autodefender.detector import ThreatDetector
from autodefender.ip_manager import IPManager
from autodefender.parser import SuricataParser

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
parser = SuricataParser()


def event(src, port, seconds, event_type="flow", **extra):
    data = {"timestamp": (T0 + timedelta(seconds=seconds)).isoformat(), "event_type": event_type,
            "src_ip": src, "dest_ip": "10.0.0.5", "dest_port": port, "proto": "TCP"}
    data.update(extra)
    return parser.extract_event_data(data)


def alert(src, seconds, severity, signature="ET POLICY test", **alert_extra):
    return event(src, 80, seconds, "alert", alert={"signature": signature, "category": "Misc",
                                                   "severity": severity, **alert_extra})


def test_parser_reads_proto_and_utc_timestamps():
    data = parser.extract_event_data(json.loads(
        '{"timestamp":"2024-11-11T10:00:01.1+0000","proto":"UDP","src_ip":"192.0.2.4"}'))
    assert data["protocol"] == "UDP"
    assert data["timestamp"].tzinfo is not None


def test_parser_rejects_bad_input():
    assert parser.parse_event("[1, 2]") is None
    assert parser.parse_event("not json") is None
    assert parser.parse_event("x" * 1_000_001) is None


def test_port_scan_within_window():
    det = ThreatDetector(Config())
    threats = [det.detect(event("203.0.113.9", 1000 + i, i * 0.5)) for i in range(10)]
    assert [t.event_type for t in threats if t] == ["port_scan"]


def test_slow_probing_is_not_a_scan():
    det = ThreatDetector(Config())
    threats = [det.detect(event("203.0.113.10", 2000 + i, i * 30)) for i in range(15)]
    assert not any(t and t.event_type == "port_scan" for t in threats)


def test_repeat_hits_are_deduplicated_until_cooldown_ends():
    det = ThreatDetector(Config())
    hits = [det.detect(event("203.0.113.11", 22, i)) for i in range(20)]
    assert len([t for t in hits if t]) == 1
    later = det.detect(event("203.0.113.11", 22, 700))
    assert later is not None and later.event_type == "suspicious_port"


def test_suricata_severity_is_used():
    det = ThreatDetector(Config())
    assert det.detect(alert("203.0.113.12", 0, 3)).severity == "LOW"
    assert det.detect(alert("203.0.113.13", 1, 2)).severity == "MEDIUM"
    assert det.detect(alert("203.0.113.14", 2, 1)).severity == "HIGH"
    assert det.detect(alert("203.0.113.15", 3, 1, "ET EXPLOIT x", action="blocked")).severity == "LOW"


def test_alert_repeat_is_suppressed_until_cooldown_ends():
    det = ThreatDetector(Config())
    first = det.detect(alert("203.0.113.20", 0, 1, "ET SCAN ssh", signature_id=1001))
    assert first is not None and first.event_type == "alert"
    assert det.detect(alert("203.0.113.20", 5, 1, "ET SCAN ssh", signature_id=1001)) is None
    other = det.detect(alert("203.0.113.20", 6, 1, "ET EXPLOIT x", signature_id=1002))
    assert other is not None
    later = det.detect(alert("203.0.113.20", 700, 1, "ET SCAN ssh", signature_id=1001))
    assert later is not None


def test_blacklist_and_whitelist(tmp_path):
    ips = IPManager(str(tmp_path / "ips.json"))
    ips.add_blacklist("198.51.100.66")
    ips.add_whitelist("192.0.2.7")
    det = ThreatDetector(Config(), ip_manager=ips)
    first = det.detect(event("198.51.100.66", 443, 0))
    assert first.event_type == "blacklisted_ip" and first.severity == "HIGH"
    assert det.detect(event("198.51.100.66", 443, 5)) is None
    assert det.detect(event("192.0.2.7", 22, 0)) is None


def test_connection_burst_is_unusual_traffic():
    det = ThreatDetector(Config())
    threats = [det.detect(event("203.0.113.13", 80, i * 0.05)) for i in range(120)]
    assert any(t and t.event_type == "unusual_traffic" for t in threats)


def test_tracking_memory_is_bounded():
    det = ThreatDetector(Config())
    det.MAX_TRACKED_IPS = 100
    for i in range(1000):
        det.detect(event(f"10.1.{i // 250}.{i % 250}", 80, i * 120))
    assert len(det.ip_activity) <= 100


def test_invalid_ports_are_ignored():
    assert ThreatDetector(Config()).detect(event("203.0.113.14", "abc", 0)) is None


def test_ip_lists_validate_and_normalize(tmp_path):
    ips = IPManager(str(tmp_path / "ips.json"))
    try:
        ips.add_blacklist("not-an-ip")
        raise AssertionError("invalid IP accepted")
    except ValueError:
        pass
    assert ips.add_blacklist("2001:db8::1")
    assert ips.is_blacklisted("2001:0db8:0::1")


def test_whitelist_reloads_when_file_changes(tmp_path):
    path = tmp_path / "ips.json"
    writer = IPManager(str(path))
    reader = IPManager(str(path))
    assert not reader.is_whitelisted("203.0.113.8")
    writer.add_whitelist("203.0.113.8")
    assert reader.is_whitelisted("203.0.113.8")
    writer.remove_whitelist("203.0.113.8")
    assert not reader.is_whitelisted("203.0.113.8")
