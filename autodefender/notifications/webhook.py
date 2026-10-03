"""Webhook notification helper."""

from __future__ import annotations

import ipaddress
import logging
import os
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
        return True  # A hostname, not an IP literal


def send_webhook(payload: Dict[str, Any], url: Optional[str] = None) -> bool:
    """Send payload to the given webhook URL (default: the WEBHOOK_URL environment variable)."""
    url = url if url is not None else os.getenv("WEBHOOK_URL", "")
    if not url:
        logger.debug("Webhook URL not configured. Skipping notification.")
        return False
    if not is_valid_webhook_url(url):
        logger.error("Webhook URL must start with https://. Skipping notification.")
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
