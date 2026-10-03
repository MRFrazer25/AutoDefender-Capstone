"""Per-session configuration and the shared background monitor for the web console."""

from __future__ import annotations

import logging
import threading
from typing import Optional

import streamlit as st

from autodefender import audit
from autodefender.config import Config
from autodefender.ip_manager import IPManager
from autodefender.utils.path_utils import sanitize_path

logger = logging.getLogger(__name__)


def config_from_session() -> Config:
    """Build a Config from the values saved on the Setup and Settings pages.

    Settings live in this browser session only; nothing is written to
    process-wide environment variables, so one user's settings never leak
    into another user's session.
    """
    config = Config.get_default()
    state = st.session_state
    config.db_path = sanitize_path(state.get("db_path", config.db_path))
    config.ollama_endpoint = state.get("ollama_endpoint", config.ollama_endpoint)
    config.ollama_model = state.get("ollama_model", config.ollama_model) or None
    config.SURICATA_ENABLED = state.get("suricata_enabled", config.SURICATA_ENABLED)
    config.SURICATA_RULES_DIR = sanitize_path(state.get("suricata_rules_dir", config.SURICATA_RULES_DIR))
    config.SURICATA_DRY_RUN = state.get("suricata_dry_run", config.SURICATA_DRY_RUN)
    config.AUTO_APPROVE_SURICATA = state.get("auto_approve_suricata", config.AUTO_APPROVE_SURICATA)
    config.BLOCK_DURATION_HOURS = state.get("block_duration_hours", config.BLOCK_DURATION_HOURS)
    config.SURICATA_AUTO_RELOAD = state.get("suricata_auto_reload", config.SURICATA_AUTO_RELOAD)
    config.PORT_SCAN_THRESHOLD = state.get("port_scan_threshold", config.PORT_SCAN_THRESHOLD)
    config.PORT_SCAN_WINDOW_SECONDS = state.get("port_scan_window_seconds", config.PORT_SCAN_WINDOW_SECONDS)
    config.ALERT_COOLDOWN_SECONDS = state.get("alert_cooldown_seconds", config.ALERT_COOLDOWN_SECONDS)
    return config


def record(action: str, details: Optional[dict] = None) -> None:
    """Write an audit log entry for an action taken in the web console."""
    audit.record("console", action, details)


def webhook_url_from_session() -> str:
    """Return the webhook URL saved on the Setup page (or the WEBHOOK_URL default)."""
    return st.session_state.get("webhook_url", Config.WEBHOOK_URL) or ""


@st.cache_resource
def _monitor_registry() -> dict:
    """Monitors running in this server process, shared by all browser sessions."""
    return {"lock": threading.Lock(), "monitors": [], "db_path": None}


def start_monitoring(log_paths: list[str], config: Config, read_from_start: bool = False) -> None:
    """Start one background monitor per log file, replacing any running ones."""
    # Imported here so pages that never monitor don't load watchdog/Ollama
    from autodefender.monitor import RealTimeMonitor

    registry = _monitor_registry()
    with registry["lock"]:
        _stop_locked(registry)
        ip_manager = IPManager()
        started = []
        try:
            for path in log_paths:
                monitor = RealTimeMonitor(
                    path,
                    config,
                    ip_manager=ip_manager,
                    read_from_start=read_from_start,
                    queue_suricata_approvals=False,  # The web UI approves from the database
                )
                monitor.start()
                started.append(monitor)
        except Exception:
            for monitor in started:
                monitor.stop()
            raise
        registry["monitors"] = started
        registry["db_path"] = config.db_path
        logger.info("Web console started monitoring %s log source(s)", len(started))


def _stop_locked(registry: dict) -> None:
    for monitor in registry["monitors"]:
        try:
            monitor.stop()
        except Exception:
            logger.exception("Error stopping monitor")
    registry["monitors"] = []
    registry["db_path"] = None


def stop_monitoring() -> None:
    """Stop all background monitors."""
    registry = _monitor_registry()
    with registry["lock"]:
        _stop_locked(registry)


def monitoring_status() -> Optional[dict]:
    """Return combined stats for the running monitors, or None if none are running."""
    registry = _monitor_registry()
    with registry["lock"]:
        monitors = [m for m in registry["monitors"] if m.is_running()]
        if not monitors:
            return None
        return {
            "sources": [str(m.log_path) for m in monitors],
            "db_path": registry["db_path"],
            "events_processed": sum(m.events_processed for m in monitors),
            "threats_detected": sum(m.threats_detected for m in monitors),
        }
