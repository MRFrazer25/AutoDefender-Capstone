"""Action recommendation.

Recommends actions based on threat type and severity. Every action starts
as RECOMMENDED and needs a person to approve it (the only exception is the
opt-in AUTO_APPROVE_SURICATA setting, handled by the monitor).
"""

import logging
from datetime import datetime
from typing import List, Optional
from models import Threat, Action
from config import Config
from playbooks.manager import PlaybookManager
from suricata_manager import normalize_block_ip

logger = logging.getLogger(__name__)

# Actions that need a source IP that can safely be blocked
BLOCKING_ACTIONS = {'SURICATA_DROP_RULE', 'BLOCK_IP', 'RATE_LIMIT', 'TERMINATE'}

# Actions AutoDefender can't carry out itself; the operator applies them elsewhere
MANUAL_ACTIONS = {'BLOCK_IP', 'RATE_LIMIT', 'TERMINATE'}


class ActionEngine:
    """Generates security action recommendations."""

    # Action type mappings by threat type
    ACTION_MAPPINGS = {
        'alert': {
            'CRITICAL': ['SURICATA_DROP_RULE', 'BLOCK_IP', 'ALERT', 'LOG'],
            'HIGH': ['SURICATA_DROP_RULE', 'BLOCK_IP', 'ALERT', 'LOG'],
            'MEDIUM': ['ALERT', 'LOG'],
            'LOW': ['LOG']
        },
        'blacklisted_ip': {
            'CRITICAL': ['SURICATA_DROP_RULE', 'BLOCK_IP', 'ALERT', 'LOG'],
            'HIGH': ['SURICATA_DROP_RULE', 'BLOCK_IP', 'ALERT', 'LOG'],
            'MEDIUM': ['ALERT', 'LOG'],
            'LOW': ['LOG']
        },
        'port_scan': {
            'CRITICAL': ['SURICATA_DROP_RULE', 'BLOCK_IP', 'RATE_LIMIT', 'ALERT', 'LOG'],
            'HIGH': ['SURICATA_DROP_RULE', 'BLOCK_IP', 'RATE_LIMIT', 'ALERT', 'LOG'],
            'MEDIUM': ['RATE_LIMIT', 'ALERT', 'LOG'],
            'LOW': ['ALERT', 'LOG']
        },
        'suspicious_port': {
            'CRITICAL': ['SURICATA_DROP_RULE', 'BLOCK_IP', 'TERMINATE', 'ALERT', 'LOG'],
            'HIGH': ['SURICATA_DROP_RULE', 'BLOCK_IP', 'ALERT', 'LOG'],
            'MEDIUM': ['ALERT', 'LOG'],
            'LOW': ['LOG']
        },
        'unusual_traffic': {
            'CRITICAL': ['SURICATA_DROP_RULE', 'BLOCK_IP', 'RATE_LIMIT', 'ALERT', 'LOG'],
            'HIGH': ['SURICATA_DROP_RULE', 'RATE_LIMIT', 'ALERT', 'LOG'],
            'MEDIUM': ['RATE_LIMIT', 'ALERT', 'LOG'],
            'LOW': ['LOG']
        }
    }

    def __init__(self, config: Optional[Config] = None):
        """Initialize the action engine."""
        self.config = config or Config.get_default()
        self.playbook_manager = PlaybookManager()

    def recommend_actions(self, threat: Threat) -> List[Action]:
        """
        Generate action recommendations for a threat.

        Args:
            threat: Threat object to generate actions for

        Returns:
            List of recommended Action objects
        """
        can_block = normalize_block_ip(threat.source_ip) is not None
        actions = [
            self._create_action(threat, action_type)
            for action_type in self._get_action_types(threat)
            if can_block or action_type not in BLOCKING_ACTIONS
        ]

        playbook_actions = self.playbook_manager.generate_actions(threat)
        if playbook_actions:
            actions.extend(playbook_actions)
            logger.info(f"Matched {len(playbook_actions)} playbook action(s) for threat {threat.id}")

        logger.info(f"Generated {len(actions)} action recommendations for threat {threat.id}")
        return actions

    def _get_action_types(self, threat: Threat) -> List[str]:
        """Get recommended action types for a threat."""
        mappings = self.ACTION_MAPPINGS.get(threat.event_type, {})
        return mappings.get(threat.severity, ['LOG'])

    def _create_action(self, threat: Threat, action_type: str) -> Action:
        """Create a RECOMMENDED Action object for a threat."""
        return Action(
            threat_id=threat.id or 0,
            action_type=action_type,
            description=self._get_action_description(threat, action_type),
            status='RECOMMENDED',
            timestamp=datetime.now()
        )

    def _get_action_description(self, threat: Threat, action_type: str) -> str:
        """Generate description for an action."""
        descriptions = {
            'LOG': f"Log threat from {threat.source_ip or 'unknown source'}",
            'ALERT': f"Send alert notification for {threat.event_type} threat",
            'BLOCK_IP': f"Block IP address {threat.source_ip} at your firewall (manual step)",
            'RATE_LIMIT': f"Rate-limit {threat.source_ip} at your firewall or load balancer (manual step)",
            'TERMINATE': f"Terminate open connections from {threat.source_ip} (manual step)",
            'SURICATA_DROP_RULE': f"Add Suricata drop rule for {threat.source_ip}"
        }

        base_desc = descriptions.get(action_type, f"Execute {action_type} action")

        if threat.severity in ['HIGH', 'CRITICAL']:
            base_desc += f" (High priority - {threat.severity} severity)"

        return base_desc
