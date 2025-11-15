"""Rule-based threat detection.

Detection patterns:
- Port scans
- Suspicious ports
- Unusual traffic
- Suricata alerts
"""

import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional
from models import Threat
from config import Config

logger = logging.getLogger(__name__)


class ThreatDetector:
    """Detects security threats from Suricata events."""
    
    # Known suspicious ports
    SUSPICIOUS_PORTS = {
        22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443
    }
    
    # Known attack signatures
    ATTACK_SIGNATURES = [
        'sql injection',
        'xss',
        'command injection',
        'buffer overflow',
        'privilege escalation',
        'malware',
        'trojan',
        'backdoor',
        'exploit'
    ]
    
    def __init__(self, config: Optional[Config] = None, ip_manager=None):
        """
        Initialize the threat detector.
        
        Args:
            config: Configuration object
            ip_manager: Optional IPManager instance for whitelist/blacklist checking
        """
        self.config = config or Config.get_default()
        self.ip_manager = ip_manager  # For whitelist/blacklist support
        # Track IP activity for port scan detection
        self.ip_activity = defaultdict(lambda: {
            'ports': set(),
            'connections': 0,
            'first_seen': None,
            'last_seen': None
        })
        self.detected_threats: List[Threat] = []
    
    def detect(self, event: Dict) -> Optional[Threat]:
        """
        Detect threats from a Suricata event.
        
        Args:
            event: Parsed Suricata event dictionary
            
        Returns:
            Threat object if threat detected, None otherwise
        """
        event_type = event.get('event_type', '')
        src_ip = event.get('src_ip')
        dest_ip = event.get('dest_ip')
        dest_port = event.get('dest_port')
        alert = event.get('alert', {})
        
        # Check whitelist - ignore threats from whitelisted IPs
        if self.ip_manager and src_ip:
            if self.ip_manager.should_ignore(src_ip):
                logger.debug(f"Ignoring event from whitelisted IP: {src_ip}")
                return None
        
        # Check for alert events (Suricata already detected something)
        if event_type == 'alert':
            return self._detect_alert_threat(event, alert)
        
        # Check for port scans
        if src_ip and dest_port:
            threat = self._detect_port_scan(event, src_ip, dest_port)
            if threat:
                return threat
        
        # Check for suspicious port access
        if dest_port and dest_port in self.SUSPICIOUS_PORTS:
            threat = self._detect_suspicious_port(event, src_ip, dest_ip, dest_port)
            if threat:
                return threat
        
        # Check for unusual traffic patterns
        threat = self._detect_unusual_traffic(event)
        if threat:
            return threat
        
        return None
    
    def _detect_alert_threat(self, event: Dict, alert: Dict) -> Optional[Threat]:
        """Detect threat from Suricata alert."""
        signature = alert.get('signature', '').lower()
        category = alert.get('category', '').lower()
        action = alert.get('action', '')
        
        # Determine severity based on alert
        severity = 'MEDIUM'
        if any(sig in signature for sig in self.ATTACK_SIGNATURES):
            severity = 'HIGH'
        if 'critical' in category or 'critical' in signature:
            severity = 'CRITICAL'
        if action == 'blocked':
            severity = 'LOW'  # Already blocked
        
        description = f"Suricata Alert: {alert.get('signature', 'Unknown signature')}"
        if category:
            description += f" (Category: {category})"
        
        return Threat(
            timestamp=event.get('timestamp') or datetime.now(),
            source_ip=event.get('src_ip'),
            dest_ip=event.get('dest_ip'),
            dest_port=event.get('dest_port'),
            event_type='alert',
            severity=severity,
            description=description,
            raw_event=event.get('raw_event', event)
        )
    
    def _detect_port_scan(self, event: Dict, src_ip: str, dest_port: int) -> Optional[Threat]:
        """Detect port scanning activity."""
        now = datetime.now()
        activity = self.ip_activity[src_ip]
        
        # Initialize tracking
        if activity['first_seen'] is None:
            activity['first_seen'] = now
        activity['last_seen'] = now
        activity['ports'].add(dest_port)
        activity['connections'] += 1
        
        # Check if port scan threshold exceeded
        time_window = now - activity['first_seen']
        if time_window.total_seconds() > 0:
            # Detect if scanning many ports quickly
            if len(activity['ports']) >= self.config.PORT_SCAN_THRESHOLD:
                severity = 'HIGH' if len(activity['ports']) >= 50 else 'MEDIUM'
                
                description = (
                    f"Port scan detected from {src_ip}: "
                    f"{len(activity['ports'])} different ports accessed "
                    f"in {time_window.total_seconds():.1f} seconds"
                )
                
                # Reset tracking after detection
                self.ip_activity[src_ip] = {
                    'ports': set(),
                    'connections': 0,
                    'first_seen': None,
                    'last_seen': None
                }
                
                return Threat(
                    timestamp=event.get('timestamp') or now,
                    source_ip=src_ip,
                    dest_ip=event.get('dest_ip'),
                    dest_port=dest_port,
                    event_type='port_scan',
                    severity=severity,
                    description=description,
                    raw_event=event.get('raw_event', event)
                )
        
        return None
    
    def _detect_suspicious_port(self, event: Dict, src_ip: Optional[str], 
                               dest_ip: Optional[str], dest_port: int) -> Optional[Threat]:
        """Detect access to suspicious ports."""
        if not src_ip:
            return None
        
        # Check if port is in suspicious list
        if dest_port in self.SUSPICIOUS_PORTS:
            port_names = {
                22: 'SSH', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS',
                445: 'SMB', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',
                5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
            }
            
            port_name = port_names.get(dest_port, f'Port {dest_port}')
            description = f"Suspicious port access: {port_name} ({dest_port}) from {src_ip}"
            
            # Higher severity for admin ports
            if dest_port in [22, 3389, 5900]:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            
            return Threat(
                timestamp=event.get('timestamp') or datetime.now(),
                source_ip=src_ip,
                dest_ip=dest_ip,
                dest_port=dest_port,
                event_type='suspicious_port',
                severity=severity,
                description=description,
                raw_event=event.get('raw_event', event)
            )
        
        return None
    
    def _detect_unusual_traffic(self, event: Dict) -> Optional[Threat]:
        """Detect unusual traffic patterns."""
        src_ip = event.get('src_ip')
        dest_port = event.get('dest_port')
        protocol = (event.get('protocol') or '').upper()
        
        # Check for unusual protocol combinations
        if protocol == 'TCP' and dest_port and dest_port > 65535:
            return Threat(
                timestamp=event.get('timestamp') or datetime.now(),
                source_ip=src_ip,
                dest_ip=event.get('dest_ip'),
                dest_port=dest_port,
                event_type='unusual_traffic',
                severity='LOW',
                description=f"Unusual traffic pattern detected: {protocol} to port {dest_port}",
                raw_event=event.get('raw_event', event)
            )
        
        # Check for high connection rate from single IP
        if src_ip:
            activity = self.ip_activity[src_ip]
            if activity['connections'] > 100:
                time_window = datetime.now() - (activity['first_seen'] or datetime.now())
                if time_window.total_seconds() > 0:
                    rate = activity['connections'] / time_window.total_seconds()
                    if rate > 10:  # More than 10 connections per second
                        return Threat(
                            timestamp=event.get('timestamp') or datetime.now(),
                            source_ip=src_ip,
                            dest_ip=event.get('dest_ip'),
                            dest_port=dest_port,
                            event_type='unusual_traffic',
                            severity='MEDIUM',
                            description=f"High connection rate from {src_ip}: {rate:.1f} connections/sec",
                            raw_event=event.get('raw_event', event)
                        )
        
        return None
    
    def get_top_threat_sources(self, limit: int = 10) -> List[tuple]:
        """Get top threat sources by count."""
        source_counts = defaultdict(int)
        for threat in self.detected_threats:
            if threat.source_ip:
                source_counts[threat.source_ip] += 1
        
        return sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def reset_activity_tracking(self):
        """Reset IP activity tracking (useful for testing or periodic cleanup)."""
        self.ip_activity.clear()

