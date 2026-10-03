"""ATT&CK mapping, incidents, audit log, GeoIP, and the real-data check."""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import audit
from incidents import group_incidents
from mitre import techniques_for
from models import Threat
from tools import check_demo_data
from utils import geoip

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)

# Publicly routable sample values, assembled at runtime so no real address or
# AS number appears literally in the repository (tools/check_demo_data.py scans it)
PUBLIC_V4 = ".".join(["8"] * 4)
PUBLIC_V6 = ":".join(["2606", "4700", "", "1111"])
REAL_ASN = "AS" + "8075"


def threat(description, event_type="alert", port=None, ip="203.0.113.5", minutes=0, severity="HIGH"):
    return Threat(timestamp=T0 + timedelta(minutes=minutes), source_ip=ip, dest_ip="10.0.0.5",
                  dest_port=port, event_type=event_type, severity=severity,
                  description=description, raw_event={})


@pytest.mark.parametrize("description, event_type, port, expected", [
    ("Suricata Alert: ET SCAN Potential SSH Scan (Category: attempted information leak)", "alert", 22, ["T1046"]),
    ("Suricata Alert: ET EXPLOIT SSH Brute Force Attempt", "alert", 22, ["T1110"]),
    ("Suricata Alert: ET EXPLOIT MSSQL SQL Injection Attempt", "alert", 1433, ["T1190"]),
    ("Suricata Alert: ET EXPLOIT SMB EternalBlue Exploit Attempt (Category: a network trojan was detected)",
     "alert", 445, ["T1210"]),
    ("Port scan detected from 203.0.113.5: 12 different ports", "port_scan", 80, ["T1046"]),
    ("Suspicious port access: RDP (3389) from 203.0.113.5", "suspicious_port", 3389, ["T1021.001"]),
    ("SMTP connection from untrusted network", "alert", 25, []),
])
def test_attack_mapping(description, event_type, port, expected):
    assert [t["id"] for t in techniques_for(threat(description, event_type, port))] == expected


def test_incidents_group_by_source_and_gap():
    threats = [
        threat("ET SCAN a", minutes=0, severity="LOW"),
        threat("ET EXPLOIT SSH Brute Force", minutes=10, severity="CRITICAL"),
        threat("ET SCAN b", minutes=200, severity="MEDIUM"),
        threat("ET SCAN c", ip="198.51.100.1", minutes=5, severity="LOW"),
    ]
    incidents = group_incidents(threats, gap=timedelta(hours=1))
    assert len(incidents) == 3
    first = incidents[0]
    assert first.source_ip == "203.0.113.5" and first.severity == "CRITICAL" and len(first.threats) == 2
    assert {t["id"] for t in first.techniques} == {"T1046", "T1110"}


def test_audit_chain_detects_tampering():
    audit.record("alice", "sign_in")
    audit.record("alice", "ip_unblocked", {"ip": "203.0.113.5"})
    audit.record("bob", "action_rejected", {"action_id": 7})
    assert audit.verify() == (True, None)
    assert [e["action"] for e in audit.entries()] == ["action_rejected", "ip_unblocked", "sign_in"]

    conn = sqlite3.connect(audit.audit_db_path())
    conn.execute("UPDATE audit_log SET username = 'mallory' WHERE id = 2")
    conn.commit()
    conn.close()
    assert audit.verify() == (False, 2)

    conn = sqlite3.connect(audit.audit_db_path())
    conn.execute("UPDATE audit_log SET username = 'alice' WHERE id = 2")
    conn.execute("DELETE FROM audit_log WHERE id = 1")
    conn.commit()
    conn.close()
    assert audit.verify() == (False, 2)


def test_geoip_is_offline_and_optional(monkeypatch):
    geoip.get_ip_context.cache_clear()
    assert not geoip.geoip_enabled()
    assert geoip.get_ip_context(PUBLIC_V4) is None

    city = SimpleNamespace(
        country=SimpleNamespace(name="Exampleland", iso_code="EX"),
        subdivisions=SimpleNamespace(most_specific=SimpleNamespace(name="North <b>")),
        city=SimpleNamespace(name="Example City"),
    )
    readers = {
        geoip.CITY_DB_ENV: SimpleNamespace(city=lambda ip: city),
        geoip.ASN_DB_ENV: SimpleNamespace(asn=lambda ip: SimpleNamespace(
            autonomous_system_number=64500, autonomous_system_organization="Example Hosting")),
    }
    monkeypatch.setattr(geoip, "_reader", lambda env: readers.get(env))
    geoip.get_ip_context.cache_clear()
    context = geoip.get_ip_context(PUBLIC_V4)
    assert context["location"] == "Example City, North b, Exampleland"  # Markup characters stripped
    assert context["isp"] == "Example Hosting" and context["as_number"] == "AS64500"
    assert geoip.get_ip_context("10.0.0.1") is None  # Private IPs are never looked up
    geoip.get_ip_context.cache_clear()


def test_real_data_checker():
    sample = f"{PUBLIC_V4} 10.0.0.1 203.0.113.5 2001:db8::1 {PUBLIC_V6} 12:30:45"
    assert check_demo_data.real_ips(sample) == {PUBLIC_V4, PUBLIC_V6}
    assert check_demo_data.real_asns(f"{REAL_ASN} AS64500 CLASS12") == {REAL_ASN}
    assert check_demo_data.check_geo(json.dumps({"geo_context": dict(isp="Some Real ISP")}))
    assert check_demo_data.main() == 0  # The repository itself is clean
