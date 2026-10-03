"""Group related threats into incidents.

Threats from the same source IP belong to one incident until that source
goes quiet for longer than the gap (default one hour). This turns a long
list of alerts into a short list of "what is this attacker doing" stories.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List

from mitre import techniques_for
from models import Threat
from parser import to_utc

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Incident:
    """Threats from one source within one burst of activity."""
    source_ip: str
    threats: List[Threat] = field(default_factory=list)

    @property
    def start(self) -> datetime:
        return to_utc(self.threats[0].timestamp)

    @property
    def end(self) -> datetime:
        return to_utc(self.threats[-1].timestamp)

    @property
    def severity(self) -> str:
        return max((t.severity for t in self.threats), key=lambda s: SEVERITY_RANK.get(s, 0))

    @property
    def event_types(self) -> List[str]:
        return sorted({t.event_type for t in self.threats})

    @property
    def techniques(self) -> List[Dict[str, str]]:
        seen: Dict[str, Dict[str, str]] = {}
        for threat in self.threats:
            for technique in techniques_for(threat):
                seen.setdefault(technique["id"], technique)
        return list(seen.values())

    @property
    def tactics(self) -> List[str]:
        return list(dict.fromkeys(t["tactic"] for t in self.techniques))

    @property
    def key(self) -> str:
        return f"{self.source_ip}@{self.start.isoformat()}"


def group_incidents(threats: List[Threat], gap: timedelta = timedelta(hours=1)) -> List[Incident]:
    """Group threats into incidents, most severe and most recent first."""
    by_source: Dict[str, List[Threat]] = {}
    for threat in threats:
        if threat.timestamp is None:
            continue
        by_source.setdefault(threat.source_ip or "unknown", []).append(threat)

    incidents: List[Incident] = []
    for source_ip, source_threats in by_source.items():
        source_threats.sort(key=lambda t: to_utc(t.timestamp))
        current = Incident(source_ip)
        for threat in source_threats:
            if current.threats and to_utc(threat.timestamp) - current.end > gap:
                incidents.append(current)
                current = Incident(source_ip)
            current.threats.append(threat)
        incidents.append(current)

    incidents.sort(key=lambda i: (SEVERITY_RANK.get(i.severity, 0), i.end), reverse=True)
    return incidents
