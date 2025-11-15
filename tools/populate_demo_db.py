#!/usr/bin/env python3
"""Populate demo/demo_config.db with sample threats and actions."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

from database import Database
from models import Threat, Action


def main() -> None:
    """Seed the demo database with sample data."""
    db = Database("demo/demo_config.db")
    now = datetime.now(timezone.utc)

    threats = [
        Threat(
            timestamp=now - timedelta(minutes=30),
            source_ip="192.168.1.101",
            dest_ip="10.0.0.5",
            dest_port=22,
            event_type="alert",
            severity="CRITICAL",
            description="Suricata Alert: SSH brute force attempts",
            raw_event={"rule": "ET EXPLOIT SSH Brute Force"},
            ai_explanation="Multiple SSH login attempts detected from 192.168.1.101.",
        ),
        Threat(
            timestamp=now - timedelta(hours=2),
            source_ip="203.0.113.5",
            dest_ip="10.0.0.5",
            dest_port=80,
            event_type="suspicious_port",
            severity="HIGH",
            description="Port scan targeting HTTP services",
            raw_event={"rule": "ET SCAN Nmap"},
            ai_explanation="HTTP port scan originated from 203.0.113.5.",
        ),
        Threat(
            timestamp=now - timedelta(hours=5),
            source_ip="10.0.0.50",
            dest_ip="10.0.0.5",
            dest_port=3389,
            event_type="port_scan",
            severity="MEDIUM",
            description="RDP brute force pattern",
            raw_event={"rule": "ET POLICY RDP Scan"},
            ai_explanation="Repeated RDP attempts detected.",
        ),
        Threat(
            timestamp=now - timedelta(days=1),
            source_ip="198.51.100.25",
            dest_ip="10.0.0.10",
            dest_port=443,
            event_type="alert",
            severity="HIGH",
            description="TLS certificate anomaly",
            raw_event={"rule": "ET POLICY TLS"},
            ai_explanation="Suspicious TLS certificate from 198.51.100.25.",
        ),
        Threat(
            timestamp=now - timedelta(days=2),
            source_ip="172.16.0.75",
            dest_ip="10.0.0.20",
            dest_port=25,
            event_type="alert",
            severity="LOW",
            description="SMTP connection from untrusted network",
            raw_event={"rule": "ET POLICY SMTP"},
            ai_explanation="Unusual SMTP access from 172.16.0.75.",
        ),
    ]

    threat_ids = [db.add_threat(threat) for threat in threats]

    actions = [
        Action(
            threat_id=threat_ids[0],
            action_type="SURICATA_DROP_RULE",
            description="Add drop rule for 192.168.1.101 SSH traffic",
            status="APPROVED",
            timestamp=now - timedelta(minutes=25),
            executed_at=now - timedelta(minutes=20),
        ),
        Action(
            threat_id=threat_ids[1],
            action_type="LOG",
            description="Logged HTTP port scan for review",
            status="EXECUTED",
            timestamp=now - timedelta(hours=1, minutes=30),
            executed_at=now - timedelta(hours=1, minutes=20),
        ),
        Action(
            threat_id=threat_ids[2],
            action_type="ALERT",
            description="Alert SOC about RDP attempts from 10.0.0.50",
            status="RECOMMENDED",
            timestamp=now - timedelta(hours=4, minutes=30),
        ),
        Action(
            threat_id=threat_ids[3],
            action_type="BLOCK_IP",
            description="Block 198.51.100.25 at firewall",
            status="EXECUTED",
            timestamp=now - timedelta(hours=20),
            executed_at=now - timedelta(hours=19, minutes=45),
        ),
    ]

    for action in actions:
        db.add_action(action)

    db.close()
    print("Demo database populated with sample threats and actions.")


if __name__ == "__main__":
    main()

