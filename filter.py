"""Threat filtering and search.

Case-insensitive filtering with partial matching support.
"""

import logging
from datetime import datetime
from typing import List, Optional
from models import Threat

logger = logging.getLogger(__name__)


class ThreatFilter:
    """Filter and search threats."""
    
    def __init__(self):
        """Initialize the filter."""
        pass
    
    def filter_threats(self, threats: List[Threat], 
                      severity: Optional[str] = None,
                      event_type: Optional[str] = None,
                      source_ip: Optional[str] = None,
                      dest_ip: Optional[str] = None,
                      start_time: Optional[datetime] = None,
                      end_time: Optional[datetime] = None,
                      has_ai_explanation: Optional[bool] = None) -> List[Threat]:
        """
        Filter threats based on criteria.
        
        Args:
            threats: List of threats to filter
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
            event_type: Filter by event type
            source_ip: Filter by source IP (partial match)
            dest_ip: Filter by destination IP (partial match)
            start_time: Filter threats after this time
            end_time: Filter threats before this time
            has_ai_explanation: Filter by whether AI explanation exists
            
        Returns:
            Filtered list of threats
        """
        filtered = threats
        
        if severity:
            filtered = [t for t in filtered if t.severity == severity.upper()]
        
        if event_type:
            filtered = [t for t in filtered if t.event_type == event_type]
        
        if source_ip:
            filtered = [t for t in filtered if t.source_ip and source_ip in t.source_ip]
        
        if dest_ip:
            filtered = [t for t in filtered if t.dest_ip and dest_ip in t.dest_ip]
        
        if start_time:
            filtered = [t for t in filtered if t.timestamp and t.timestamp >= start_time]
        
        if end_time:
            filtered = [t for t in filtered if t.timestamp and t.timestamp <= end_time]
        
        if has_ai_explanation is not None:
            if has_ai_explanation:
                filtered = [t for t in filtered if t.ai_explanation]
            else:
                filtered = [t for t in filtered if not t.ai_explanation]
        
        return filtered
    
    def search_threats(self, threats: List[Threat], query: str) -> List[Threat]:
        """
        Search threats by description or AI explanation.
        
        Args:
            threats: List of threats to search
            query: Search query string
            
        Returns:
            List of matching threats
        """
        query_lower = query.lower()
        results = []
        
        for threat in threats:
            # Search in description
            if query_lower in threat.description.lower():
                results.append(threat)
                continue
            
            # Search in AI explanation
            if threat.ai_explanation and query_lower in threat.ai_explanation.lower():
                results.append(threat)
                continue
            
            # Search in source IP
            if threat.source_ip and query_lower in threat.source_ip.lower():
                results.append(threat)
                continue
            
            # Search in event type
            if query_lower in threat.event_type.lower():
                results.append(threat)
                continue
        
        return results
    
    def filter_by_severity_list(self, threats: List[Threat], severities: List[str]) -> List[Threat]:
        """
        Filter threats by multiple severity levels.
        
        Args:
            threats: List of threats to filter
            severities: List of severity levels to include (e.g., ['HIGH', 'CRITICAL'])
            
        Returns:
            Filtered list of threats
        """
        severities_upper = [s.upper() for s in severities]
        return [t for t in threats if t.severity in severities_upper]

