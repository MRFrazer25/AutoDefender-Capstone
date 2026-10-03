"""Map threats to MITRE ATT&CK techniques.

The mapping is intentionally conservative: a threat only gets a technique
when its type, port, or signature clearly matches. Unmatched threats get no
tag rather than a guess. Technique IDs follow ATT&CK Enterprise.
"""

import re
from typing import Dict, List

from models import Threat

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"

TECHNIQUES = {
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1021.005": ("Remote Services: VNC", "Lateral Movement"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1567.002": ("Exfiltration Over Web Service: Exfiltration to Cloud Storage", "Exfiltration"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1498": ("Network Denial of Service", "Impact"),
}

# Remote-access ports (used for suspicious_port threats)
PORT_TECHNIQUES = {
    22: "T1021.004",
    23: "T1021",
    139: "T1021.002",
    445: "T1021.002",
    3389: "T1021.001",
    5900: "T1021.005",
}

# (pattern on the lower-cased signature/description, technique)
KEYWORD_TECHNIQUES = [
    (r"\bscan\b|reconnaissance", "T1046"),
    (r"brute[ -]?force|root login|password guess|login attempt", "T1110"),
    (r"eternalblue|ms17-010", "T1210"),
    (r"sql injection|\bxss\b|cross[- ]site|command injection|web application attack|remote code execution", "T1190"),
    (r"privilege (gain|escalation)", "T1068"),
    (r"rdp connection", "T1021.001"),
    (r"exfiltration.*cloud storage|cloud storage.*exfiltration", "T1567.002"),
    (r"exfiltration", "T1048"),
    (r"man-in-the-middle|\bmitm\b|arp spoof", "T1557"),
    (r"\bc2\b|command and control|beacon|backdoor|\btrojan\b|malware", "T1071"),
    (r"denial of service|\bddos\b|\bdos\b|flood", "T1498"),
]


def _signature_text(threat: Threat) -> str:
    """Return the signature/description text, without Suricata's category suffix.

    Categories like "A Network Trojan was detected" are broad, so matching on
    them would mislabel many alerts.
    """
    return re.split(r"\s*\(Category:", threat.description or "", maxsplit=1)[0].lower()


def techniques_for(threat: Threat) -> List[Dict[str, str]]:
    """Return ATT&CK techniques for a threat as dicts with id, name, tactic, and url."""
    ids: List[str] = []
    if threat.event_type == "port_scan":
        ids.append("T1046")
    elif threat.event_type == "unusual_traffic":
        ids.append("T1498")
    elif threat.event_type == "suspicious_port" and threat.dest_port in PORT_TECHNIQUES:
        ids.append(PORT_TECHNIQUES[threat.dest_port])

    text = _signature_text(threat)
    for pattern, technique in KEYWORD_TECHNIQUES:
        if re.search(pattern, text):
            ids.append(technique)

    # Exfiltration to cloud storage already implies the more general technique
    if "T1567.002" in ids and "T1048" in ids:
        ids.remove("T1048")

    unique = list(dict.fromkeys(ids))[:3]
    return [
        {"id": tid, "name": TECHNIQUES[tid][0], "tactic": TECHNIQUES[tid][1], "url": ATTACK_URL.format(tid.replace(".", "/"))}
        for tid in unique
    ]


def technique_labels(threat: Threat) -> str:
    """Short comma-separated label, e.g. 'T1110 Brute Force'."""
    return ", ".join(f"{t['id']} {t['name']}" for t in techniques_for(threat))
