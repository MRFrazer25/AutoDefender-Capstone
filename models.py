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
    
    def to_dict(self) -> Dict:
        """Convert threat to dictionary for database storage."""
        data = {
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'dest_port': self.dest_port,
            'event_type': self.event_type,
            'severity': self.severity,
            'description': self.description,
            'raw_event': str(self.raw_event),
            'ai_explanation': self.ai_explanation
        }
        # Store metadata as JSON string if present
        if self.metadata:
            import json
            data['metadata'] = json.dumps(self.metadata)
        return data


@dataclass
class Action:
    """Represents a recommended or executed security action."""
    threat_id: int
    action_type: str  # LOG, ALERT, BLOCK_IP, RATE_LIMIT, TERMINATE
    description: str
    status: str  # RECOMMENDED, APPROVED, EXECUTED, REJECTED
    timestamp: datetime
    id: Optional[int] = None
    executed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict:
        """Convert action to dictionary for database storage."""
        return {
            'threat_id': self.threat_id,
            'action_type': self.action_type,
            'description': self.description,
            'status': self.status,
            'timestamp': self.timestamp.isoformat(),
            'executed_at': self.executed_at.isoformat() if self.executed_at else None
        }


@dataclass
class DetectionStats:
    """Statistics about threat detections."""
    total_threats: int
    by_severity: Dict[str, int]
    by_type: Dict[str, int]
    top_sources: List[tuple]  # List of (ip, count) tuples
    date: Optional[datetime] = None
    
    def to_dict(self) -> Dict:
        """Convert stats to dictionary."""
        return {
            'total_threats': self.total_threats,
            'by_severity': self.by_severity,
            'by_type': self.by_type,
            'top_sources': self.top_sources,
            'date': self.date.isoformat() if self.date else None
        }

