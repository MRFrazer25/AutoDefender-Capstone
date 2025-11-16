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
from ai_explainer import AIExplainer
from config import Config


def main() -> None:
    """Seed the demo database with sample data."""
    db = Database("demo/demo_config.db")
    now = datetime.now(timezone.utc)
    
    # Initialize AI explainer for generating real explanations
    print("Initializing AI explainer...")
    config = Config.get_default()
    # Ensure model is set (default to phi4-mini if not specified)
    if not config.ollama_model:
        config.ollama_model = "phi4-mini"
        print(f"Using default model: {config.ollama_model}")
    explainer = AIExplainer(config)
    
    if not explainer.client:
        print("WARNING: Ollama is not available. Threats will be created without AI explanations.")
        print("Start Ollama with 'ollama serve' and ensure the model is available.")
        use_ai = False
    else:
        print(f"Connected to Ollama. Using model: {config.ollama_model}")
        use_ai = True

    threats_data = [
        {
            "timestamp": now - timedelta(minutes=30),
            "source_ip": "203.0.113.45",
            "dest_ip": "10.0.0.5",
            "dest_port": 22,
            "event_type": "alert",
            "severity": "CRITICAL",
            "description": "Suricata Alert: ET EXPLOIT Attempted SSH brute force login from suspicious IP known for attacks",
            "raw_event": {"rule": "ET EXPLOIT SSH Brute Force", "category": "brute-force"},
            "metadata": {
                "geo_context": {
                    "country": "Russia",
                    "country_code": "RU",
                    "region": "Moscow",
                    "city": "Moscow",
                    "isp": "Example Hosting LLC",
                    "org": "Example Dedicated Servers",
                    "as_number": "AS64500",
                    "location": "Moscow, Moscow, Russia"
                }
            }
        },
        {
            "timestamp": now - timedelta(hours=2),
            "source_ip": "203.0.113.101",
            "dest_ip": "10.0.0.5",
            "dest_port": 80,
            "event_type": "suspicious_port",
            "severity": "HIGH",
            "description": "Port scan targeting multiple HTTP services - Potential reconnaissance activity from known Tor exit node",
            "raw_event": {"rule": "ET SCAN Nmap scripting engine User-Agent detected", "category": "network-scan"},
            "metadata": {
                "geo_context": {
                    "country": "Germany",
                    "country_code": "DE",
                    "region": "Hesse",
                    "city": "Frankfurt am Main",
                    "isp": "Example Relay Network",
                    "org": "Example Tor Exit Node",
                    "as_number": "AS64501",
                    "location": "Frankfurt am Main, Hesse, Germany"
                }
            }
        },
        {
            "timestamp": now - timedelta(hours=5),
            "source_ip": "10.0.0.50",
            "dest_ip": "10.0.0.5",
            "dest_port": 3389,
            "event_type": "port_scan",
            "severity": "MEDIUM",
            "description": "RDP brute force pattern from internal network - possible compromised workstation",
            "raw_event": {"rule": "ET POLICY RDP Connection Request", "category": "policy-violation"},
            "metadata": None
        },
        {
            "timestamp": now - timedelta(hours=8),
            "source_ip": "198.51.100.200",
            "dest_ip": "10.0.0.15",
            "dest_port": 443,
            "event_type": "alert",
            "severity": "HIGH",
            "description": "Data exfiltration attempt: Large outbound HTTPS transfer to cloud storage service exceeding threshold",
            "raw_event": {"rule": "ET POLICY Outbound Large File Transfer", "category": "data-loss"},
            "metadata": {
                "geo_context": {
                    "country": "United States",
                    "country_code": "US",
                    "region": "Washington",
                    "city": "Seattle",
                    "isp": "Example Cloud Provider",
                    "org": "Example Cloud Storage",
                    "as_number": "AS64502",
                    "location": "Seattle, Washington, United States"
                }
            }
        },
        {
            "timestamp": now - timedelta(days=1),
            "source_ip": "198.51.100.25",
            "dest_ip": "10.0.0.10",
            "dest_port": 443,
            "event_type": "alert",
            "severity": "HIGH",
            "description": "TLS certificate validation failure - possible man-in-the-middle attack detected",
            "raw_event": {"rule": "ET POLICY TLS possible TLS traffic on non-standard port", "category": "protocol-anomaly"},
            "metadata": None
        },
        {
            "timestamp": now - timedelta(days=2),
            "source_ip": "172.16.0.75",
            "dest_ip": "10.0.0.20",
            "dest_port": 25,
            "event_type": "alert",
            "severity": "LOW",
            "description": "SMTP connection from untrusted internal network segment - potential spam relay",
            "raw_event": {"rule": "ET POLICY SMTP connection from non-standard internal subnet", "category": "policy-violation"},
            "metadata": None
        },
    ]

    # Create Threat objects and generate AI explanations
    print("\nGenerating AI explanations for threats...")
    threats = []
    for i, threat_data in enumerate(threats_data, 1):
        print(f"Processing threat {i}/{len(threats_data)}: {threat_data['severity']} {threat_data['event_type']}...", end=" ")
        
        # Create Threat object
        threat = Threat(
            timestamp=threat_data["timestamp"],
            source_ip=threat_data["source_ip"],
            dest_ip=threat_data["dest_ip"],
            dest_port=threat_data["dest_port"],
            event_type=threat_data["event_type"],
            severity=threat_data["severity"],
            description=threat_data["description"],
            raw_event=threat_data["raw_event"],
            metadata=threat_data.get("metadata")
        )
        
        # Generate AI explanation if available
        if use_ai:
            try:
                ai_explanation = explainer.explain_threat(threat, use_ai=True)
                if ai_explanation:
                    threat.ai_explanation = ai_explanation
                    print("[OK] AI explanation generated")
                else:
                    print("[!] No AI explanation (fallback used)")
            except Exception as e:
                print(f"[!] Error generating explanation: {e}")
        else:
            print("[!] Skipped (Ollama unavailable)")
        
        threats.append(threat)
    
    print("\nAdding threats to database...")
    threat_ids = [db.add_threat(threat) for threat in threats]

    actions = [
        Action(
            threat_id=threat_ids[0],
            action_type="SURICATA_DROP_RULE",
            description="Critical SSH brute force response executed: Block 203.0.113.45 SSH traffic via Suricata drop rule",
            status="EXECUTED",
            timestamp=now - timedelta(minutes=28),
            executed_at=now - timedelta(minutes=25),
        ),
        Action(
            threat_id=threat_ids[0],
            action_type="LOG",
            description="Log SSH brute force incident for compliance audit trail",
            status="EXECUTED",
            timestamp=now - timedelta(minutes=28),
            executed_at=now - timedelta(minutes=25),
        ),
        Action(
            threat_id=threat_ids[0],
            action_type="WEBHOOK_NOTIFY",
            description="Critical SSH brute force response executed\nSource IP: 203.0.113.45 (Moscow, Russia)\nSeverity: CRITICAL\nActions: Drop rule added, incident logged",
            status="EXECUTED",
            timestamp=now - timedelta(minutes=28),
            executed_at=now - timedelta(minutes=25),
        ),
        Action(
            threat_id=threat_ids[1],
            action_type="LOG",
            description="HTTP port scan playbook: Record Tor exit node scan activity for threat intelligence",
            status="EXECUTED",
            timestamp=now - timedelta(hours=1, minutes=45),
            executed_at=now - timedelta(hours=1, minutes=40),
        ),
        Action(
            threat_id=threat_ids[1],
            action_type="WEBHOOK_NOTIFY",
            description="HTTP Port Scan Playbook executed\nSource IP: 203.0.113.101 (Frankfurt, Germany - Tor Exit Node)\nSeverity: HIGH\nActions: Scan logged for review",
            status="EXECUTED",
            timestamp=now - timedelta(hours=1, minutes=45),
            executed_at=now - timedelta(hours=1, minutes=40),
        ),
        Action(
            threat_id=threat_ids[2],
            action_type="ALERT",
            description="Internal RDP brute force: Alert SOC to investigate workstation 10.0.0.50 for compromise",
            status="RECOMMENDED",
            timestamp=now - timedelta(hours=4, minutes=50),
        ),
        Action(
            threat_id=threat_ids[3],
            action_type="SURICATA_DROP_RULE",
            description="Block data exfiltration: Add Suricata drop rule for 198.51.100.200 (Azure/OneDrive)",
            status="RECOMMENDED",
            timestamp=now - timedelta(hours=7, minutes=30),
        ),
        Action(
            threat_id=threat_ids[4],
            action_type="SURICATA_DROP_RULE",
            description="Block 198.51.100.25 to prevent man-in-the-middle attacks",
            status="EXECUTED",
            timestamp=now - timedelta(hours=22),
            executed_at=now - timedelta(hours=21, minutes=45),
        ),
        Action(
            threat_id=threat_ids[5],
            action_type="LOG",
            description="Log SMTP policy violation for internal audit",
            status="EXECUTED",
            timestamp=now - timedelta(days=1, hours=23),
            executed_at=now - timedelta(days=1, hours=22, minutes=50),
        ),
    ]

    for action in actions:
        db.add_action(action)

    db.close()
    print("\n[OK] Demo database populated with sample threats and actions.")
    if use_ai:
        print("[OK] All threats include AI-generated explanations from Ollama.")
    else:
        print("[!] Threats were created without AI explanations (Ollama was unavailable).")


if __name__ == "__main__":
    main()

