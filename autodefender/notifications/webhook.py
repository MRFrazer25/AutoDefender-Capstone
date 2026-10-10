"""Webhook notification helper."""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import ParseResult, urlparse

import httpx

logger = logging.getLogger(__name__)
# httpx logs every request URL at INFO, and webhook URLs are secrets (anyone with one can post
# to your channel), so only let its warnings and errors through.
logging.getLogger("httpx").setLevel(logging.WARNING)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def _public_target(url: str) -> Optional[Tuple[ParseResult, IPAddress]]:
    """Return the parsed URL and the public address to connect to, or None if the URL isn't allowed.

    Webhooks go to services like Slack or Teams, so local and private
    addresses are refused (this stops the webhook from being aimed at
    services inside your network).
    """
    try:
        parsed = urlparse(url or "")
        host = (parsed.hostname or "").lower()
        port = parsed.port or 443
    except ValueError:
        return None
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        return None
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        return None
    try:
        address = ipaddress.ip_address(host)
        return (parsed, address) if address.is_global else None
    except ValueError:
        pass  # A hostname, not an IP literal
    # A hostname can still point at a private address (e.g. a DNS name for 127.0.0.1),
    # so resolve it and require every address it maps to be public.
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError, ValueError):
        return None
    addresses = []
    for info in infos:
        try:
            # Drop any IPv6 zone id ("fe80::1%eth0") before parsing
            address = ipaddress.ip_address(str(info[4][0]).split("%")[0])
        except ValueError:
            return None
        if not address.is_global:
            return None
        addresses.append(address)
    return (parsed, addresses[0]) if addresses else None


def is_valid_webhook_url(url: str) -> bool:
    """Allow only https URLs that point at a public host."""
    return _public_target(url) is not None


def send_webhook(payload: Dict[str, Any], url: Optional[str] = None) -> bool:
    """Send payload to the given webhook URL (default: the WEBHOOK_URL environment variable)."""
    url = url if url is not None else os.getenv("WEBHOOK_URL", "")
    if not url:
        logger.debug("Webhook URL not configured. Skipping notification.")
        return False
    target = _public_target(url)
    if target is None:
        logger.error("Webhook URL must be https and point at a public host. Skipping notification.")
        return False
    parsed, address = target
    host = parsed.hostname
    # Connect to the exact address that was checked, so a DNS answer that changes between
    # the check and the request can't redirect it. TLS still verifies the certificate
    # against the real hostname (sni_hostname), and Host keeps the request routed correctly.
    ip_netloc = f"[{address}]" if address.version == 6 else str(address)
    if parsed.port:
        ip_netloc += f":{parsed.port}"
    pinned_url = parsed._replace(netloc=ip_netloc).geturl()
    host_header = f"{host}:{parsed.port}" if parsed.port else host
    try:
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            response = client.post(pinned_url, json=payload, headers={"Host": host_header},
                                   extensions={"sni_hostname": host})
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
