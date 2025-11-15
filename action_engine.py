"""Action recommendation and execution.

Recommends actions based on threat type and severity.
Includes manual approval workflow for safety.
"""

import logging
from datetime import datetime
from typing import List, Optional
from models import Threat, Action
from config import Config

logger = logging.getLogger(__name__)


class ActionEngine:
    """Generates and manages security action recommendations."""
    
    # Action type mappings by threat type
    ACTION_MAPPINGS = {
        'alert': {
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
            'MEDIUM': ['ALERT', 'LOG'],
            'LOW': ['LOG']
        }
    }
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize the action engine."""
        self.config = config or Config.get_default()
        self.pending_actions: List[Action] = []
    
    def recommend_actions(self, threat: Threat) -> List[Action]:
        """
        Generate action recommendations for a threat.
        
        Args:
            threat: Threat object to generate actions for
            
        Returns:
            List of recommended Action objects
        """
        actions = []
        action_types = self._get_action_types(threat)
        
        for action_type in action_types:
            action = self._create_action(threat, action_type)
            if action:
                actions.append(action)
                self.pending_actions.append(action)
        
        logger.info(f"Generated {len(actions)} action recommendations for threat {threat.id}")
        return actions
    
    def _get_action_types(self, threat: Threat) -> List[str]:
        """Get recommended action types for a threat."""
        mappings = self.ACTION_MAPPINGS.get(threat.event_type, {})
        return mappings.get(threat.severity, ['LOG'])
    
    def _create_action(self, threat: Threat, action_type: str) -> Optional[Action]:
        """Create an Action object for a threat."""
        description = self._get_action_description(threat, action_type)
        
        # Determine initial status based on config
        status = 'RECOMMENDED'
        if self._should_auto_approve(threat, action_type):
            status = 'APPROVED'
        
        return Action(
            threat_id=threat.id or 0,
            action_type=action_type,
            description=description,
            status=status,
            timestamp=datetime.now()
        )
    
    def _get_action_description(self, threat: Threat, action_type: str) -> str:
        """Generate description for an action."""
        descriptions = {
            'LOG': f"Log threat from {threat.source_ip or 'unknown source'}",
            'ALERT': f"Send alert notification for {threat.event_type} threat",
            'BLOCK_IP': f"Block IP address {threat.source_ip}",
            'RATE_LIMIT': f"Apply rate limiting to {threat.source_ip}",
            'TERMINATE': f"Terminate connection from {threat.source_ip}",
            'SURICATA_DROP_RULE': f"Add Suricata drop rule for {threat.source_ip}"
        }
        
        base_desc = descriptions.get(action_type, f"Execute {action_type} action")
        
        if threat.severity in ['HIGH', 'CRITICAL']:
            base_desc += f" (High priority - {threat.severity} severity)"
        
        return base_desc
    
    def _should_auto_approve(self, threat: Threat, action_type: str) -> bool:
        """Check if action should be auto-approved based on config."""
        # Never auto-approve destructive actions
        if action_type in ['BLOCK_IP', 'TERMINATE']:
            return False
        
        # Check Suricata-specific auto-approval setting
        if action_type == 'SURICATA_DROP_RULE':
            if hasattr(self.config, 'AUTO_APPROVE_SURICATA'):
                return self.config.AUTO_APPROVE_SURICATA
            return False
        
        # Check config for auto-approval
        if threat.severity == 'CRITICAL':
            return self.config.AUTO_APPROVE_CRITICAL_SEVERITY
        elif threat.severity == 'HIGH':
            return self.config.AUTO_APPROVE_HIGH_SEVERITY
        elif threat.severity == 'MEDIUM':
            return self.config.AUTO_APPROVE_MEDIUM_SEVERITY
        elif threat.severity == 'LOW':
            return self.config.AUTO_APPROVE_LOW_SEVERITY
        
        return False
    
    def approve_action(self, action: Action) -> bool:
        """
        Approve an action for execution.
        
        Args:
            action: Action to approve
            
        Returns:
            True if approved, False otherwise
        """
        if action.status != 'RECOMMENDED':
            logger.warning(f"Action {action.id} is not in RECOMMENDED status")
            return False
        
        action.status = 'APPROVED'
        logger.info(f"Action {action.id} approved")
        return True
    
    def reject_action(self, action: Action) -> bool:
        """
        Reject an action.
        
        Args:
            action: Action to reject
            
        Returns:
            True if rejected, False otherwise
        """
        if action.status not in ['RECOMMENDED', 'APPROVED']:
            logger.warning(f"Action {action.id} cannot be rejected in current status")
            return False
        
        action.status = 'REJECTED'
        logger.info(f"Action {action.id} rejected")
        return True
    
    def execute_action(self, action: Action, safe_mode: bool = True) -> bool:
        """
        Execute an action (or simulate in safe mode).
        
        Args:
            action: Action to execute
            safe_mode: If True, only log what would happen
            
        Returns:
            True if executed/simulated successfully
        """
        if action.status != 'APPROVED':
            logger.warning(f"Action {action.id} must be APPROVED before execution")
            return False
        
        if safe_mode:
            logger.info(f"[SAFE MODE] Would execute: {action.description}")
            logger.info(f"[SAFE MODE] Action type: {action.action_type}")
            if action.threat_id:
                logger.info(f"[SAFE MODE] For threat ID: {action.threat_id}")
            action.status = 'EXECUTED'
            action.executed_at = datetime.now()
            return True
        
        # Actual execution - integrates with firewall/network tools depending on deployment
        try:
            if action.action_type == 'LOG':
                logger.info(f"Logging threat: {action.description}")
            elif action.action_type == 'ALERT':
                logger.warning(f"ALERT: {action.description}")
            elif action.action_type == 'BLOCK_IP':
                logger.info(f"Block IP action logged: {action.description}")
            elif action.action_type == 'RATE_LIMIT':
                logger.info(f"Rate limit action logged: {action.description}")
            elif action.action_type == 'TERMINATE':
                logger.info(f"Terminate connection action logged: {action.description}")
            elif action.action_type == 'SURICATA_DROP_RULE':
                # This should be handled by SuricataManager in monitor.py
                logger.info(f"Suricata rule action: {action.description}")
                # Actual execution happens in the monitor
            
            action.status = 'EXECUTED'
            action.executed_at = datetime.now()
            logger.info(f"Action {action.id} executed")
            return True
            
        except Exception as e:
            logger.error(f"Error executing action {action.id}: {e}")
            action.status = 'FAILED'
            return False
    
    def get_pending_actions(self) -> List[Action]:
        """Get list of pending actions."""
        return [a for a in self.pending_actions if a.status in ['RECOMMENDED', 'APPROVED']]
    
    def clear_pending(self):
        """Clear pending actions list."""
        self.pending_actions.clear()

