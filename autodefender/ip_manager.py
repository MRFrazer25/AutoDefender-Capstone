"""IP whitelist and blacklist management."""

import ipaddress
import json
import logging
from pathlib import Path
from typing import Set, Optional

logger = logging.getLogger(__name__)


def normalize_ip(ip: Optional[str]) -> Optional[str]:
    """Return the canonical form of an IPv4/IPv6 address, or None if invalid."""
    if not ip:
        return None
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return None


class IPManager:
    """Manages IP whitelist and blacklist."""

    def __init__(self, config_path: str = "ip_lists.json"):
        """
        Initialize IP manager.

        Args:
            config_path: Path to JSON file storing whitelist/blacklist
        """
        self.config_path = Path(config_path)
        self.whitelist: Set[str] = set()
        self.blacklist: Set[str] = set()
        self._lists_mtime: Optional[float] = None
        self._load_lists()

    def _file_mtime(self) -> Optional[float]:
        try:
            return self.config_path.stat().st_mtime if self.config_path.exists() else None
        except OSError:
            return None

    def _reload_if_stale(self):
        """Reload lists when another process or page has rewritten the file."""
        mtime = self._file_mtime()
        if mtime != self._lists_mtime:
            self._load_lists()

    def _load_lists(self):
        """Load whitelist and blacklist from file."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.whitelist = self._clean_list(data.get('whitelist', []))
                    self.blacklist = self._clean_list(data.get('blacklist', []))
                logger.info(f"Loaded {len(self.whitelist)} whitelisted and {len(self.blacklist)} blacklisted IPs")
            except (json.JSONDecodeError, IOError, AttributeError) as e:
                logger.warning(f"Error loading IP lists: {e}. Starting with empty lists.")
                self.whitelist = set()
                self.blacklist = set()
        else:
            # Create empty file
            self._save_lists()
        self._lists_mtime = self._file_mtime()

    @staticmethod
    def _clean_list(values) -> Set[str]:
        """Keep only valid IPs from a loaded list, in canonical form."""
        cleaned = set()
        for value in values if isinstance(values, list) else []:
            ip = normalize_ip(value)
            if ip:
                cleaned.add(ip)
            else:
                logger.warning(f"Ignoring invalid IP in IP lists file: {value!r}")
        return cleaned

    def _save_lists(self):
        """Save whitelist and blacklist to file."""
        try:
            data = {
                'whitelist': sorted(list(self.whitelist)),
                'blacklist': sorted(list(self.blacklist))
            }
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved IP lists to {self.config_path}")
            self._lists_mtime = self._file_mtime()
        except IOError as e:
            logger.error(f"Error saving IP lists: {e}")

    def add_whitelist(self, ip: str) -> bool:
        """
        Add IP to whitelist.

        Args:
            ip: IP address to whitelist

        Returns:
            True if added, False if already exists

        Raises:
            ValueError: If ip is not a valid IP address
        """
        ip = self._require_ip(ip)
        if ip in self.whitelist:
            return False
        self.whitelist.add(ip)
        # Remove from blacklist if present
        self.blacklist.discard(ip)
        self._save_lists()
        logger.info(f"Added {ip} to whitelist")
        return True

    def add_blacklist(self, ip: str) -> bool:
        """
        Add IP to blacklist.

        Args:
            ip: IP address to blacklist

        Returns:
            True if added, False if already exists

        Raises:
            ValueError: If ip is not a valid IP address
        """
        ip = self._require_ip(ip)
        if ip in self.blacklist:
            return False
        self.blacklist.add(ip)
        # Remove from whitelist if present
        self.whitelist.discard(ip)
        self._save_lists()
        logger.info(f"Added {ip} to blacklist")
        return True

    def remove_whitelist(self, ip: str) -> bool:
        """
        Remove IP from whitelist.

        Args:
            ip: IP address to remove

        Returns:
            True if removed, False if not found
        """
        ip = normalize_ip(ip)
        if ip in self.whitelist:
            self.whitelist.remove(ip)
            self._save_lists()
            logger.info(f"Removed {ip} from whitelist")
            return True
        return False

    def remove_blacklist(self, ip: str) -> bool:
        """
        Remove IP from blacklist.

        Args:
            ip: IP address to remove

        Returns:
            True if removed, False if not found
        """
        ip = normalize_ip(ip)
        if ip in self.blacklist:
            self.blacklist.remove(ip)
            self._save_lists()
            logger.info(f"Removed {ip} from blacklist")
            return True
        return False

    @staticmethod
    def _require_ip(ip: str) -> str:
        """Return the canonical IP or raise ValueError."""
        normalized = normalize_ip(ip)
        if not normalized:
            raise ValueError(f"Invalid IP address: {ip!r}")
        return normalized

    def is_whitelisted(self, ip: Optional[str]) -> bool:
        """
        Check if IP is whitelisted.

        Args:
            ip: IP address to check

        Returns:
            True if whitelisted, False otherwise
        """
        self._reload_if_stale()
        return normalize_ip(ip) in self.whitelist

    def is_blacklisted(self, ip: Optional[str]) -> bool:
        """
        Check if IP is blacklisted.

        Args:
            ip: IP address to check

        Returns:
            True if blacklisted, False otherwise
        """
        self._reload_if_stale()
        return normalize_ip(ip) in self.blacklist

    def should_ignore(self, ip: Optional[str]) -> bool:
        """
        Check if IP should be ignored (whitelisted).

        Args:
            ip: IP address to check

        Returns:
            True if should be ignored, False otherwise
        """
        return self.is_whitelisted(ip)

    def should_block(self, ip: Optional[str]) -> bool:
        """
        Check if IP should be blocked (blacklisted).

        Args:
            ip: IP address to check

        Returns:
            True if should be blocked, False otherwise
        """
        return self.is_blacklisted(ip)

    def get_whitelist(self) -> list:
        """Get list of whitelisted IPs."""
        return sorted(list(self.whitelist))

    def get_blacklist(self) -> list:
        """Get list of blacklisted IPs."""
        return sorted(list(self.blacklist))
