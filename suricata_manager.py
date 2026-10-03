"""Suricata rule file management.

Operations:
- Add drop rules to custom rule files
- Auto-backup before modifications
- Strict single-IP drop rule validation
- Path validation for safety
- Dry-run mode
- Health monitoring
"""

import ipaddress
import json
import logging
import shutil
import re
import os
import subprocess  # nosec B404 - only runs suricatasc with fixed arguments
import threading
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple
from config import Config

logger = logging.getLogger(__name__)

# The only rule shape AutoDefender writes: drop all traffic from one source IP.
DROP_RULE_PATTERN = re.compile(
    r'^drop ip (?P<src>\S+) any -> any any '
    r'\(msg:"(?P<msg>[^"\\;\r\n]{1,200})"; sid:\d+; rev:\d+;\)$'
)

MSG_MAX_LENGTH = 150


def sanitize_rule_msg(text: str) -> str:
    """Make free text safe for a Suricata msg field (one line, no quotes or separators)."""
    cleaned = re.sub(r'[\x00-\x1f\x7f"\\;]', " ", text or "")
    cleaned = " ".join(cleaned.split())
    return cleaned[:MSG_MAX_LENGTH] or "AutoDefender block"


def normalize_block_ip(ip: Optional[str]) -> Optional[str]:
    """Return the canonical form of an IP that is safe to block, or None.

    Rejects anything that is not a single address, plus addresses whose
    blocking would cut off this host or everything (loopback, unspecified,
    multicast).
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return None
    return str(addr)


def build_drop_rule(ip: str, msg: str, sid: int = 9000001) -> str:
    """Build a single-line drop rule for one source IP."""
    safe_ip = normalize_block_ip(ip)
    if not safe_ip:
        raise ValueError(f"Refusing to build a drop rule for {ip!r}")
    return f'drop ip {safe_ip} any -> any any (msg:"{sanitize_rule_msg(msg)}"; sid:{int(sid)}; rev:1;)'


def parse_drop_rule(rule: str) -> Optional[Tuple[str, str]]:
    """Return (ip, msg) if the rule matches the exact AutoDefender drop rule shape."""
    if not rule or "\n" in rule.strip() or "\r" in rule:
        return None
    match = DROP_RULE_PATTERN.match(rule.strip())
    if not match:
        return None
    ip = normalize_block_ip(match["src"])
    if not ip:
        return None
    return ip, match["msg"]


class SuricataManager:
    """Manages Suricata rule files and configuration."""
    
    def __init__(self, config: Optional[Config] = None, ip_manager=None):
        """
        Initialize Suricata manager.

        Args:
            config: Configuration object
            ip_manager: Optional IPManager; whitelisted IPs are never blocked
        """
        self.config = config or Config.get_default()
        self.ip_manager = ip_manager
        self._write_lock = threading.Lock()

        # Ensure Suricata is enabled
        if not hasattr(self.config, 'SURICATA_ENABLED') or not self.config.SURICATA_ENABLED:
            logger.info("Suricata integration is disabled")
            return
        
        # Set up paths
        self.rules_dir = Path(getattr(self.config, 'SURICATA_RULES_DIR', './suricata_rules'))
        self.custom_rules_file = self.rules_dir / "autodefender_custom.rules"
        
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
        
        # Only accept the exact single-IP drop rule shape; anything else
        # (extra rules on new lines, "any" sources, pass rules) is refused.
        parsed = parse_drop_rule(rule)
        if not parsed:
            logger.error(f"Refusing rule that is not a single-IP drop rule: {rule[:100]!r}")
            return False
        ip, msg = parsed

        if self.ip_manager and self.ip_manager.is_whitelisted(ip):
            logger.error(f"Refusing to block whitelisted IP {ip}")
            return False

        # Validate path safety
        if not self.is_safe_path(self.custom_rules_file):
            logger.error(f"Unsafe path: {self.custom_rules_file}")
            return False

        with self._write_lock:
            # One rule per IP: approving the same block twice is a no-op
            existing = self.find_block(ip)
            if existing:
                logger.info(f"{ip} is already blocked (sid {existing['sid']})")
                return True

            # Rebuild the rule ourselves so the SID is unique and the text is canonical
            sid = self.next_sid
            final_rule = build_drop_rule(ip, msg, sid)

            # Check dry-run mode
            if hasattr(self.config, 'SURICATA_DRY_RUN') and self.config.SURICATA_DRY_RUN:
                logger.info(f"[DRY RUN] Would add rule: {final_rule}")
                return True

            try:
                # Create backup first, keeping only the most recent ones
                self.backup_rules_file()
                self.cleanup_old_backups()

                with open(self.custom_rules_file, 'a', encoding='utf-8') as f:
                    f.write(final_rule + '\n')

                self.next_sid += 1
                hours = float(getattr(self.config, 'BLOCK_DURATION_HOURS', 0) or 0)
                now = datetime.now(timezone.utc)
                blocks = self._load_blocks()
                blocks[str(sid)] = {
                    "ip": ip,
                    "created": now.isoformat(),
                    "expires": (now + timedelta(hours=hours)).isoformat() if hours > 0 else None,
                }
                self._save_blocks(blocks)
                logger.info(f"Added custom Suricata rule blocking {ip}")
                self._rules_modified_since_check = True
            except Exception as e:
                logger.error(f"Error adding custom rule: {e}")
                return False

        self._maybe_reload()
        return True

    # ---- Active blocks, unblocking, and expiry ----

    @property
    def blocks_file(self) -> Path:
        """Sidecar file recording when each AutoDefender rule was added and when it expires."""
        return self.rules_dir / "autodefender_blocks.json"

    def _load_blocks(self) -> Dict[str, dict]:
        try:
            data = json.loads(self.blocks_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_blocks(self, blocks: Dict[str, dict]):
        temp = self.blocks_file.with_suffix(".json.tmp")
        temp.write_text(json.dumps(blocks, indent=2), encoding="utf-8")
        os.replace(temp, self.blocks_file)

    def list_blocks(self) -> list:
        """Return the drop rules AutoDefender wrote, oldest first.

        Each entry has sid, ip, msg, created, and expires (None = permanent).
        Rules added before block tracking existed show created/expires as None.
        """
        if not hasattr(self, 'custom_rules_file') or not self.custom_rules_file.exists():
            return []
        blocks = self._load_blocks()
        result = []
        for line in self.custom_rules_file.read_text(encoding="utf-8").splitlines():
            parsed = parse_drop_rule(line)
            sid_match = re.search(r'sid:(\d+);', line)
            if not parsed or not sid_match:
                continue
            info = blocks.get(sid_match.group(1), {})
            result.append({
                "sid": int(sid_match.group(1)),
                "ip": parsed[0],
                "msg": parsed[1],
                "created": info.get("created"),
                "expires": info.get("expires"),
            })
        return result

    def find_block(self, ip: str) -> Optional[dict]:
        """Return the active block for an IP, if any."""
        ip = normalize_block_ip(ip)
        return next((b for b in self.list_blocks() if b["ip"] == ip), None)

    def remove_blocks(self, sids) -> int:
        """Remove AutoDefender drop rules by SID. Returns how many rules were removed."""
        sids = {int(s) for s in sids}
        if not sids or not hasattr(self, 'custom_rules_file'):
            return 0
        with self._write_lock:
            if getattr(self.config, 'SURICATA_DRY_RUN', False):
                logger.info(f"[DRY RUN] Would remove rules with SIDs {sorted(sids)}")
                return 0
            lines = self.custom_rules_file.read_text(encoding="utf-8").splitlines()
            kept, removed = [], 0
            for line in lines:
                sid_match = re.search(r'sid:(\d+);', line)
                # Only ever remove rules in AutoDefender's own canonical format
                if parse_drop_rule(line) and sid_match and int(sid_match.group(1)) in sids:
                    removed += 1
                    continue
                kept.append(line)
            if not removed:
                return 0
            self.backup_rules_file()
            self.cleanup_old_backups()
            temp = self.custom_rules_file.with_suffix(".rules.tmp")
            temp.write_text("".join(line + "\n" for line in kept), encoding="utf-8")
            os.replace(temp, self.custom_rules_file)
            blocks = self._load_blocks()
            for sid in sids:
                blocks.pop(str(sid), None)
            self._save_blocks(blocks)
            self._rules_modified_since_check = True
            logger.info(f"Removed {removed} drop rule(s)")
        self._maybe_reload()
        return removed

    def unblock_ip(self, ip: str) -> bool:
        """Remove the drop rule for an IP. Returns True if a rule was removed."""
        block = self.find_block(ip)
        return bool(block) and self.remove_blocks([block["sid"]]) > 0

    def expire_blocks(self, now: Optional[datetime] = None) -> int:
        """Remove blocks whose expiry time has passed. Returns how many were removed."""
        now = now or datetime.now(timezone.utc)
        expired = [
            b["sid"] for b in self.list_blocks()
            if b["expires"] and datetime.fromisoformat(b["expires"]) <= now
        ]
        if expired:
            logger.info(f"Expiring {len(expired)} block(s)")
        return self.remove_blocks(expired) if expired else 0

    # ---- Reloading Suricata ----

    @staticmethod
    def suricatasc_available() -> bool:
        """True if the suricatasc tool is installed on this machine."""
        return shutil.which("suricatasc") is not None

    def reload_rules(self) -> Tuple[bool, str]:
        """Ask the running Suricata to reload its rules via suricatasc (no restart needed)."""
        tool = shutil.which("suricatasc")
        if not tool:
            return False, "suricatasc is not installed or not on PATH."
        command = [tool, "-c", "reload-rules"]
        socket_path = getattr(self.config, 'SURICATA_SOCKET', '')
        if socket_path:
            command.append(socket_path)
        try:
            # Fixed argument list, no shell
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)  # nosec B603
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, f"Could not run suricatasc: {e}"
        output = (result.stdout + result.stderr).strip()
        if result.returncode == 0 and '"OK"' in output.replace("'", '"'):
            self._rules_modified_since_check = False
            return True, "Suricata reloaded its rules."
        return False, f"Suricata did not confirm the reload: {output[:300]}"

    def _maybe_reload(self):
        if getattr(self.config, 'SURICATA_AUTO_RELOAD', False):
            ok, message = self.reload_rules()
            (logger.info if ok else logger.warning)(message)

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

