"""Suricata rule file management.

Operations:
- Add drop rules to custom rule files
- Auto-backup before modifications
- Rule validation
- Path validation for safety
- Dry-run mode
- Health monitoring
"""

import logging
import shutil
import re
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from config import Config

logger = logging.getLogger(__name__)


class SuricataManager:
    """Manages Suricata rule files and configuration."""
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize Suricata manager.
        
        Args:
            config: Configuration object
        """
        self.config = config or Config.get_default()
        
        # Ensure Suricata is enabled
        if not hasattr(self.config, 'SURICATA_ENABLED') or not self.config.SURICATA_ENABLED:
            logger.info("Suricata integration is disabled")
            return
        
        # Set up paths
        self.rules_dir = Path(getattr(self.config, 'SURICATA_RULES_DIR', './suricata_rules'))
        self.custom_rules_file = self.rules_dir / "autodefender_custom.rules"
        self.config_path = Path(getattr(self.config, 'SURICATA_CONFIG_PATH', ''))
        
        # Create rules directory if it doesn't exist
        self._initialize_rules_directory()
        
        # Counter for rule SIDs
        self.next_sid = 9000001
        
        # Health monitoring
        self._last_health_check: Optional[datetime] = None
        self._health_status: Dict[str, Any] = {}
        self._rules_modified_since_check = False
    
    def _initialize_rules_directory(self):
        """Initialize rules directory and custom rules file."""
        try:
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            
            # Create custom rules file if it doesn't exist
            if not self.custom_rules_file.exists():
                self.custom_rules_file.touch()
                logger.info(f"Created custom rules file: {self.custom_rules_file}")
            
            # Load existing SIDs to avoid conflicts
            self._load_existing_sids()
            
        except Exception as e:
            logger.error(f"Failed to initialize rules directory: {e}")
            raise
    
    def _load_existing_sids(self):
        """Load existing rule SIDs to avoid conflicts."""
        try:
            if self.custom_rules_file.exists():
                with open(self.custom_rules_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Find all SIDs in existing rules
                    sids = re.findall(r'sid:(\d+)', content)
                    if sids:
                        max_sid = max(int(sid) for sid in sids)
                        if max_sid >= self.next_sid:
                            self.next_sid = max_sid + 1
        except Exception as e:
            logger.warning(f"Could not load existing SIDs: {e}")
    
    def is_safe_path(self, path: Path) -> bool:
        """
        Check if path is safe to modify (within app directory).
        
        Args:
            path: Path to check
            
        Returns:
            True if safe, False otherwise
        """
        try:
            # Get absolute paths
            app_dir = Path(__file__).parent.resolve()
            path_resolved = path.resolve()
            
            # Check if path is within app directory or specified rules directory
            if path_resolved.is_relative_to(app_dir):
                return True
            
            # Also allow specified Suricata rules directory
            if hasattr(self.config, 'SURICATA_RULES_DIR'):
                rules_dir = Path(self.config.SURICATA_RULES_DIR).resolve()
                if path_resolved.is_relative_to(rules_dir):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking path safety: {e}")
            return False
    
    def validate_rule(self, rule: str) -> bool:
        """
        Validate Suricata rule syntax.
        
        Args:
            rule: Rule string to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Basic validation - check for required components
        rule = rule.strip()
        
        if not rule:
            return False
        
        # Must start with action (drop, alert, pass, reject)
        valid_actions = ['drop', 'alert', 'pass', 'reject']
        if not any(rule.startswith(action) for action in valid_actions):
            logger.warning(f"Rule doesn't start with valid action: {rule[:50]}")
            return False
        
        # Must contain protocol (ip, tcp, udp, icmp, etc.)
        if not any(proto in rule.lower() for proto in ['ip', 'tcp', 'udp', 'icmp', 'http']):
            logger.warning(f"Rule doesn't contain valid protocol: {rule[:50]}")
            return False
        
        # Must contain source and destination (-> or <>)
        if '->' not in rule and '<>' not in rule:
            logger.warning(f"Rule doesn't contain direction operator: {rule[:50]}")
            return False
        
        # Must have parentheses for options
        if '(' not in rule or ')' not in rule:
            logger.warning(f"Rule doesn't contain options in parentheses: {rule[:50]}")
            return False
        
        # Must have msg and sid
        if 'msg:' not in rule.lower():
            logger.warning(f"Rule doesn't contain msg: {rule[:50]}")
            return False
        
        if 'sid:' not in rule.lower():
            logger.warning(f"Rule doesn't contain sid: {rule[:50]}")
            return False
        
        return True
    
    def backup_rules_file(self) -> Optional[Path]:
        """
        Create a timestamped backup of the rules file.
        
        Returns:
            Path to backup file or None if backup failed
        """
        if not self.custom_rules_file.exists():
            logger.debug("No rules file to backup")
            return None
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.custom_rules_file.with_suffix(f'.rules.backup.{timestamp}')
            
            shutil.copy2(self.custom_rules_file, backup_path)
            logger.info(f"Created backup: {backup_path}")
            return backup_path
            
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            return None
    
    def add_custom_rule(self, rule: str) -> bool:
        """
        Add a custom Suricata rule.
        
        Args:
            rule: Complete Suricata rule string
            
        Returns:
            True if successful, False otherwise
        """
        if not hasattr(self.config, 'SURICATA_ENABLED') or not self.config.SURICATA_ENABLED:
            logger.warning("Suricata integration is disabled")
            return False
        
        # Validate rule
        if not self.validate_rule(rule):
            logger.error(f"Invalid rule: {rule[:100]}")
            return False
        
        # Validate path safety
        if not self.is_safe_path(self.custom_rules_file):
            logger.error(f"Unsafe path: {self.custom_rules_file}")
            return False
        
        # Check dry-run mode
        if hasattr(self.config, 'SURICATA_DRY_RUN') and self.config.SURICATA_DRY_RUN:
            logger.info(f"[DRY RUN] Would add rule: {rule.strip()}")
            return True
        
        try:
            # Create backup first
            self.backup_rules_file()
            
            # Ensure rule ends with newline
            if not rule.endswith('\n'):
                rule += '\n'
            
            # Append rule to file
            with open(self.custom_rules_file, 'a', encoding='utf-8') as f:
                f.write(rule)
            
            logger.info("Added custom Suricata rule")
            self._rules_modified_since_check = True
            return True
            
        except Exception as e:
            logger.error(f"Error adding custom rule: {e}")
            return False
    
    def get_rules_file_path(self) -> Path:
        """Get path to custom rules file."""
        return self.custom_rules_file
    
    def cleanup_old_backups(self, keep_count: int = 10) -> int:
        """
        Clean up old backup files, keeping only the most recent ones.
        
        Args:
            keep_count: Number of recent backups to keep
            
        Returns:
            Number of backups deleted
        """
        try:
            # Find all backup files
            backup_pattern = f"{self.custom_rules_file.stem}.rules.backup.*"
            backups = sorted(
                self.rules_dir.glob(backup_pattern),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )
            
            # Delete old backups
            deleted = 0
            for backup in backups[keep_count:]:
                try:
                    backup.unlink()
                    deleted += 1
                    logger.debug(f"Deleted old backup: {backup}")
                except Exception as e:
                    logger.warning(f"Could not delete backup {backup}: {e}")
            
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} old backup files")
            
            return deleted
            
        except Exception as e:
            logger.error(f"Error cleaning up backups: {e}")
            return 0
    
    def check_health(self) -> Dict[str, Any]:
        """
        Perform health check on Suricata rules directory.
        
        Returns:
            Dictionary with health status information:
            - status: 'healthy', 'warning', or 'error'
            - rules_file_exists: bool
            - rules_file_writable: bool
            - rules_file_size: int (bytes)
            - total_rules: int
            - backup_count: int
            - disk_space_available: int (MB)
            - last_modified: datetime
            - issues: list of issue descriptions
        """
        self._last_health_check = datetime.now()
        issues = []
        
        health = {
            'status': 'healthy',
            'rules_file_exists': False,
            'rules_file_writable': False,
            'rules_file_size': 0,
            'total_rules': 0,
            'backup_count': 0,
            'disk_space_available': 0,
            'last_modified': None,
            'issues': issues
        }
        
        try:
            # Check if rules file exists
            if self.custom_rules_file.exists():
                health['rules_file_exists'] = True
                
                # Check file size
                health['rules_file_size'] = self.custom_rules_file.stat().st_size
                health['last_modified'] = datetime.fromtimestamp(
                    self.custom_rules_file.stat().st_mtime
                )
                
                # Count rules
                try:
                    with open(self.custom_rules_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Count lines that look like rules (not comments or empty)
                        rules = [line for line in content.split('\n') 
                                if line.strip() and not line.strip().startswith('#')]
                        health['total_rules'] = len(rules)
                except Exception as e:
                    issues.append(f"Could not read rules file: {e}")
                    health['status'] = 'warning'
                
                # Check if writable
                health['rules_file_writable'] = os.access(self.custom_rules_file, os.W_OK)
                if not health['rules_file_writable']:
                    issues.append("Rules file is not writable")
                    health['status'] = 'error'
            else:
                issues.append("Rules file does not exist")
                health['status'] = 'warning'
            
            # Count backups
            backup_pattern = f"{self.custom_rules_file.stem}.rules.backup.*"
            backups = list(self.rules_dir.glob(backup_pattern))
            health['backup_count'] = len(backups)
            
            # Check disk space
            try:
                stat = os.statvfs(self.rules_dir) if hasattr(os, 'statvfs') else None
                if stat:
                    health['disk_space_available'] = (stat.f_bavail * stat.f_frsize) // (1024 * 1024)
                    if health['disk_space_available'] < 10:  # Less than 10MB
                        issues.append(f"Low disk space: {health['disk_space_available']}MB available")
                        health['status'] = 'warning'
                else:
                    # Windows fallback
                    import shutil as sh
                    usage = sh.disk_usage(self.rules_dir)
                    health['disk_space_available'] = usage.free // (1024 * 1024)
                    if health['disk_space_available'] < 10:
                        issues.append(f"Low disk space: {health['disk_space_available']}MB available")
                        health['status'] = 'warning'
            except Exception as e:
                logger.debug(f"Could not check disk space: {e}")
            
            # Check for excessive backups
            if health['backup_count'] > 20:
                issues.append(f"Many backup files ({health['backup_count']}). Consider cleanup.")
                if health['status'] == 'healthy':
                    health['status'] = 'warning'
            
            # Check for large rules file
            if health['rules_file_size'] > 1_000_000:  # > 1MB
                issues.append(f"Large rules file ({health['rules_file_size'] // 1024}KB). Consider review.")
                if health['status'] == 'healthy':
                    health['status'] = 'warning'
            
        except Exception as e:
            logger.error(f"Error during health check: {e}")
            health['status'] = 'error'
            issues.append(f"Health check failed: {e}")
        
        self._health_status = health
        self._rules_modified_since_check = False
        return health
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get cached health status.
        
        Returns:
            Most recent health check results
        """
        return self._health_status
    
    def needs_restart(self) -> bool:
        """
        Check if Suricata needs restart for rules to take effect.
        
        Returns:
            True if rules have been modified since last check
        """
        return self._rules_modified_since_check

