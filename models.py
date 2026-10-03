"""Data models for threats, actions, and stats.

Threat: detected security event
Action: recommended or executed response
DetectionStats: aggregated threat statistics
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, List


@dataclass
class Threat:
    """Represents a detected security threat."""
    timestamp: datetime
    source_ip: Optional[str]
    dest_ip: Optional[str]
    dest_port: Optional[int]
    event_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    raw_event: Dict
    ai_explanation: Optional[str] = None
    metadata: Optional[Dict] = None
    id: Optional[int] = None


@dataclass
class Action:
    """Represents a recommended or executed security action."""
    threat_id: int
    action_type: str  # LOG, ALERT, BLOCK_IP, RATE_LIMIT, TERMINATE, SURICATA_DROP_RULE, WEBHOOK_NOTIFY
    description: str
    status: str  # RECOMMENDED, EXECUTED, REJECTED, FAILED
    timestamp: datetime
    id: Optional[int] = None
    executed_at: Optional[datetime] = None


@dataclass
class DetectionStats:
    """Statistics about threat detections."""
    total_threats: int
    by_severity: Dict[str, int]
    by_type: Dict[str, int]
    top_sources: List[tuple]  # List of (ip, count) tuples
