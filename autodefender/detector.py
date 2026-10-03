"""Rule-based threat detection.

Detection patterns:
- Suricata alerts (severity taken from the alert itself)
- Traffic from blacklisted IPs
- Port scans (distinct ports from one source within a time window)
- Access to commonly attacked service ports
- Unusually high connection rates

Time windows use the event's own timestamp, so replaying old logs behaves
the same as live monitoring. Repeat detections for the same source are
suppressed for a cooldown period to avoid alert floods.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
from autodefender.config import Config
from autodefender.models import Threat
from autodefender.parser import minimal_event, to_utc

logger = logging.getLogger(__name__)


class ThreatDetector:
    """Detects security threats from Suricata events."""

    # Commonly attacked service ports and their names
    SUSPICIOUS_PORTS = {
        22: 'SSH', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS',
        445: 'SMB', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
    }
    # Remote-administration ports get a higher severity
    ADMIN_PORTS = {22, 23, 3389, 5900}

    # Signature keywords that raise a low/medium alert to HIGH
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

    # Suricata alert severity: 1 is the highest priority
    SURICATA_SEVERITY = {1: 'HIGH', 2: 'MEDIUM', 3: 'LOW', 4: 'LOW'}

    # High connection rate: this many connections within RATE_WINDOW
    RATE_THRESHOLD = 100
    RATE_WINDOW = timedelta(seconds=10)

    # Limits on per-IP tracking state
    MAX_TRACKED_IPS = 10000
    ACTIVITY_TTL = timedelta(minutes=10)

    def __init__(self, config: Optional[Config] = None, ip_manager=None):
        """
        Initialize the threat detector.

        Args:
            config: Configuration object
            ip_manager: Optional IPManager instance for whitelist/blacklist checking
        """
        self.config = config or Config.get_default()
        self.ip_manager = ip_manager  # For whitelist/blacklist support
        self.scan_window = timedelta(seconds=self.config.PORT_SCAN_WINDOW_SECONDS)
        self.cooldown = timedelta(seconds=self.config.ALERT_COOLDOWN_SECONDS)
        # Per source IP: {'ports': {port: last_seen}, 'connections': [times], 'last_seen': time}
        self.ip_activity: Dict[str, dict] = {}
        # (source IP, detection kind) -> time of the last threat raised
        self._last_alerted: Dict[tuple, datetime] = {}

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
        dest_port = self._port(event.get('dest_port'))
        alert = event.get('alert') if isinstance(event.get('alert'), dict) else {}
        now = self._event_time(event)

        # Check whitelist - ignore threats from whitelisted IPs
        if self.ip_manager and src_ip and self.ip_manager.should_ignore(src_ip):
            logger.debug(f"Ignoring event from whitelisted IP: {src_ip}")
            return None

        # Check for alert events (Suricata already detected something)
        if event_type == 'alert':
            return self._detect_alert_threat(event, alert, now)

        # Statistics and other non-traffic events carry no source
        if not src_ip:
            return None

        self._track(src_ip, dest_port, now)

        # Known-bad sources
        if self.ip_manager and self.ip_manager.should_block(src_ip):
            threat = self._detect_blacklisted(event, src_ip, dest_port, now)
            if threat:
                return threat

        # Check for port scans
        if dest_port is not None:
            threat = self._detect_port_scan(event, src_ip, dest_port, now)
            if threat:
                return threat

        # Check for suspicious port access
        if dest_port in self.SUSPICIOUS_PORTS:
            threat = self._detect_suspicious_port(event, src_ip, dest_port, now)
            if threat:
                return threat

        # Check for unusual traffic patterns
        return self._detect_unusual_traffic(event, src_ip, dest_port, now)

    @staticmethod
    def _port(value) -> Optional[int]:
        """Return a valid TCP/UDP port number, or None."""
        try:
            port = int(value)
        except (TypeError, ValueError):
            return None
        return port if 0 <= port <= 65535 else None

    @staticmethod
    def _event_time(event: Dict) -> datetime:
        """Use the event's own timestamp so replayed logs keep their timing."""
        timestamp = event.get('timestamp')
        if isinstance(timestamp, datetime):
            return to_utc(timestamp)
        return datetime.now(timezone.utc)

    def _track(self, src_ip: str, dest_port: Optional[int], now: datetime):
        """Record a connection from src_ip for scan and rate detection."""
        if src_ip not in self.ip_activity:
            self._prune_activity(now)
            self.ip_activity[src_ip] = {'ports': {}, 'connections': [], 'last_seen': now}
        activity = self.ip_activity[src_ip]
        activity['last_seen'] = max(activity['last_seen'], now)
        if dest_port is not None:
            activity['ports'][dest_port] = now
        activity['connections'].append(now)
        # Keep only connections inside the rate window
        cutoff = now - self.RATE_WINDOW
        activity['connections'] = [t for t in activity['connections'] if t >= cutoff]

    def _prune_activity(self, now: datetime):
        """Drop stale tracking entries so spoofed source IPs can't grow memory without bound."""
        if len(self.ip_activity) < self.MAX_TRACKED_IPS:
            return
        cutoff = now - self.ACTIVITY_TTL
        for ip in [ip for ip, a in self.ip_activity.items() if a['last_seen'] < cutoff]:
            del self.ip_activity[ip]
        # Still too many: forget the oldest half
        if len(self.ip_activity) >= self.MAX_TRACKED_IPS:
            oldest = sorted(self.ip_activity, key=lambda ip: self.ip_activity[ip]['last_seen'])
            for ip in oldest[: len(oldest) // 2]:
                del self.ip_activity[ip]
        self._last_alerted = {
            key: when for key, when in self._last_alerted.items() if when >= now - self.cooldown
        }

    def _in_cooldown(self, key: tuple, now: datetime) -> bool:
        """Return True if this detection fired recently; otherwise record it."""
        last = self._last_alerted.get(key)
        if last is not None and abs(now - last) < self.cooldown:
            return True
        self._last_alerted[key] = now
        return False

    def _make_threat(self, event: Dict, now: datetime, event_type: str, severity: str,
                     description: str, dest_port: Optional[int] = None) -> Threat:
        return Threat(
            timestamp=now,
            source_ip=event.get('src_ip'),
            dest_ip=event.get('dest_ip'),
            dest_port=dest_port if dest_port is not None else self._port(event.get('dest_port')),
            event_type=event_type,
            severity=severity,
            description=description,
            raw_event=minimal_event(event.get('raw_event', event))
        )

    def _detect_alert_threat(self, event: Dict, alert: Dict, now: datetime) -> Optional[Threat]:
        """Detect threat from Suricata alert."""
        signature_text = str(alert.get('signature') or 'Unknown signature')
        signature = signature_text.lower()
        category = str(alert.get('category') or '').lower()
        action = str(alert.get('action') or '')

        # Start from Suricata's own priority (1 = highest)
        severity = self.SURICATA_SEVERITY.get(alert.get('severity'), 'MEDIUM')
        if severity in ('LOW', 'MEDIUM') and any(sig in signature for sig in self.ATTACK_SIGNATURES):
            severity = 'HIGH'
        if 'critical' in category or 'critical' in signature:
            severity = 'CRITICAL'
        if self.ip_manager and self.ip_manager.should_block(event.get('src_ip')):
            severity = 'CRITICAL' if severity in ('HIGH', 'CRITICAL') else 'HIGH'
        if action == 'blocked':
            severity = 'LOW'  # Suricata already dropped it (IPS mode)

        description = f"Suricata Alert: {signature_text}"
        if category:
            description += f" (Category: {category})"

        return self._make_threat(event, now, 'alert', severity, description)

    def _detect_blacklisted(self, event: Dict, src_ip: str, dest_port: Optional[int],
                            now: datetime) -> Optional[Threat]:
        """Raise a HIGH threat for traffic from a blacklisted IP (once per cooldown)."""
        if self._in_cooldown((src_ip, 'blacklisted'), now):
            return None
        target = f" to port {dest_port}" if dest_port is not None else ""
        return self._make_threat(
            event, now, 'blacklisted_ip', 'HIGH',
            f"Traffic from blacklisted IP {src_ip}{target}", dest_port
        )

    def _detect_port_scan(self, event: Dict, src_ip: str, dest_port: int,
                          now: datetime) -> Optional[Threat]:
        """Detect many distinct destination ports from one source within the scan window."""
        activity = self.ip_activity[src_ip]
        cutoff = now - self.scan_window
        activity['ports'] = {p: t for p, t in activity['ports'].items() if t >= cutoff}
        port_count = len(activity['ports'])

        if port_count < self.config.PORT_SCAN_THRESHOLD:
            return None

        first_seen = min(activity['ports'].values())
        span = (now - first_seen).total_seconds()
        activity['ports'] = {}  # Start counting again after a detection
        if self._in_cooldown((src_ip, 'port_scan'), now):
            return None

        severity = 'HIGH' if port_count >= 50 else 'MEDIUM'
        description = (
            f"Port scan detected from {src_ip}: "
            f"{port_count} different ports accessed in {span:.1f} seconds"
        )
        return self._make_threat(event, now, 'port_scan', severity, description, dest_port)

    def _detect_suspicious_port(self, event: Dict, src_ip: str, dest_port: int,
                                now: datetime) -> Optional[Threat]:
        """Detect access to commonly attacked service ports (once per source and port per cooldown)."""
        if self._in_cooldown((src_ip, 'suspicious_port', dest_port), now):
            return None
        port_name = self.SUSPICIOUS_PORTS[dest_port]
        severity = 'MEDIUM' if dest_port in self.ADMIN_PORTS else 'LOW'
        description = f"Suspicious port access: {port_name} ({dest_port}) from {src_ip}"
        return self._make_threat(event, now, 'suspicious_port', severity, description, dest_port)

    def _detect_unusual_traffic(self, event: Dict, src_ip: str, dest_port: Optional[int],
                                now: datetime) -> Optional[Threat]:
        """Detect a burst of connections from one source."""
        connections = self.ip_activity[src_ip]['connections']
        if len(connections) < self.RATE_THRESHOLD:
            return None
        if self._in_cooldown((src_ip, 'unusual_traffic'), now):
            return None
        span = max((now - min(connections)).total_seconds(), 1.0)
        rate = len(connections) / span
        return self._make_threat(
            event, now, 'unusual_traffic', 'MEDIUM',
            f"High connection rate from {src_ip}: {len(connections)} connections in {span:.0f} seconds "
            f"({rate:.1f}/sec)",
            dest_port
        )
