"""Webhook notification helper."""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


def is_valid_webhook_url(url: str) -> bool:
    """Allow only https URLs that point at a public host.

    Webhooks go to services like Slack or Teams, so local and private
    addresses are refused (this stops the webhook from being aimed at
    services inside your network).
    """
    try:
        parsed = urlparse(url or "")
        host = (parsed.hostname or "").lower()
    except ValueError:
        return False
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        return False
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        pass  # A hostname, not an IP literal
    # A hostname can still point at a private address (e.g. a DNS name for 127.0.0.1),
    # so resolve it and require every address it maps to be public.
    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError, ValueError):
        return False
    addresses = set()
    for info in infos:
        try:
            # Drop any IPv6 zone id ("fe80::1%eth0") before parsing
            addresses.add(ipaddress.ip_address(str(info[4][0]).split("%")[0]))
        except ValueError:
            return False
    return bool(addresses) and all(address.is_global for address in addresses)


def send_webhook(payload: Dict[str, Any], url: Optional[str] = None) -> bool:
    """Send payload to the given webhook URL (default: the WEBHOOK_URL environment variable)."""
    url = url if url is not None else os.getenv("WEBHOOK_URL", "")
    if not url:
        logger.debug("Webhook URL not configured. Skipping notification.")
        return False
    if not is_valid_webhook_url(url):
        logger.error("Webhook URL must be https and point at a public host. Skipping notification.")
        return False
    try:
        response = httpx.post(url, json=payload, timeout=5.0, follow_redirects=False)
        response.raise_for_status()
        logger.info("Webhook notification sent.")
        return True
    except httpx.HTTPStatusError as exc:
        # Don't log the URL: Slack/Teams webhook URLs are secrets
        logger.error(f"Webhook notification failed with HTTP {exc.response.status_code}")
        return False
    except Exception as exc:
        logger.error(f"Webhook notification failed: {type(exc).__name__}")
        return False
