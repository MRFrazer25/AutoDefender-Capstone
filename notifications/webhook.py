"""Webhook notification helper."""

from __future__ import annotations

import logging
from typing import Any, Dict

import httpx

from config import Config

logger = logging.getLogger(__name__)


def send_webhook(payload: Dict[str, Any]) -> bool:
    """Send payload to configured webhook endpoint."""
    url = Config.WEBHOOK_URL or ""
    if not url:
        logger.debug("Webhook URL not configured. Skipping notification.")
        return False
    try:
        response = httpx.post(url, json=payload, timeout=5.0)
        response.raise_for_status()
        logger.info("Webhook notification sent.")
        return True
    except Exception as exc:
        logger.error(f"Webhook notification failed: {exc}")
        return False

