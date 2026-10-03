"""Settings and configuration page."""

import logging
from pathlib import Path

import streamlit as st

from autodefender.ai_explainer import AIExplainer
from autodefender.config import Config
from autodefender.database import Database
from autodefender.utils.geoip import geoip_enabled
from autodefender.utils.path_utils import sanitize_path
from streamlit_pages.session_config import config_from_session, record
from streamlit_pages.setup import is_valid_model_name, is_valid_service_url

logger = logging.getLogger(__name__)


def show() -> None:
    """Render the settings page."""
    st.markdown('<div class="main-header">Settings and Configuration</div>', unsafe_allow_html=True)
    st.caption("Settings apply to this browser session only. Use environment variables or config.ini to persist them.")

    defaults = Config.get_default()
    try:
        config = config_from_session()
    except ValueError as exc:
        st.error(f"Invalid path in current settings: {exc}")
        return

    tabs = st.tabs([
        "Detection",
        "AI and Ollama",
        "Suricata integration",
        "Database",
    ])

    with tabs[0]:
        st.subheader("Detection thresholds")
        port_scan_threshold = st.number_input(
            "Port scan threshold",
            min_value=2,
            max_value=1000,
            value=int(config.PORT_SCAN_THRESHOLD),
            help="Distinct destination ports from one source within the window that count as a scan.",
        )
        port_scan_window = st.number_input(
            "Port scan window (seconds)",
            min_value=5,
            max_value=3600,
            value=int(config.PORT_SCAN_WINDOW_SECONDS),
        )
        cooldown = st.number_input(
            "Repeat alert cooldown (seconds)",
            min_value=0,
            max_value=86400,
            value=int(config.ALERT_COOLDOWN_SECONDS),
            help="After a source triggers a detection, the same detection is suppressed for this long.",
        )

        st.markdown("#### Dashboard")
        refresh_rate = st.slider(
            "Dashboard refresh interval while monitoring (seconds)",
            min_value=1.0,
            max_value=30.0,
            value=float(st.session_state.get("refresh_rate", 2.0)),
            step=0.5,
        )
        max_displayed = st.number_input(
            "Threats loaded on the dashboard",
            min_value=50,
            max_value=10000,
            value=int(st.session_state.get("max_displayed_threats", 1000)),
            step=50,
        )

        if st.button("Save detection settings"):
            st.session_state.port_scan_threshold = int(port_scan_threshold)
            st.session_state.port_scan_window_seconds = int(port_scan_window)
            st.session_state.alert_cooldown_seconds = int(cooldown)
            st.session_state.refresh_rate = float(refresh_rate)
            st.session_state.max_displayed_threats = int(max_displayed)
            record("settings_saved", {
                "section": "detection", "port_scan_threshold": int(port_scan_threshold),
                "window": int(port_scan_window), "cooldown": int(cooldown),
            })
            st.success("Saved. Detection changes apply the next time monitoring starts.")

    with tabs[1]:
        st.subheader("AI and Ollama configuration")
        endpoint = st.text_input(
            "Ollama endpoint URL",
            value=config.ollama_endpoint or "",
            placeholder="Example: http://127.0.0.1:11434",
        )
        model = st.text_input(
            "Ollama model name",
            value=config.ollama_model or "",
            placeholder="Any model you pulled with 'ollama pull' (leave blank to skip AI)",
        )
        st.caption("Ollama runs locally, so threat data sent for explanations stays on your network.")
        if geoip_enabled():
            st.caption("GeoIP: enabled with local GeoLite2 database files (no lookups leave this machine).")
        else:
            st.caption("GeoIP: off. Set AUTODEFENDER_GEOIP_CITY_DB to a GeoLite2-City.mmdb file to add location context.")

        test_col, save_col = st.columns(2)
        with test_col:
            if st.button("Test Ollama connection"):
                if not is_valid_service_url(endpoint):
                    st.error("Ollama endpoint must be an http:// or https:// URL.")
                else:
                    temp_config = Config.get_default()
                    temp_config.ollama_endpoint = endpoint
                    temp_config.ollama_model = model or None
                    explainer = AIExplainer(temp_config)
                    if explainer.connected:
                        st.success("Ollama responded successfully.")
                        if explainer.available_models:
                            st.info("Available models: " + ", ".join(explainer.available_models))
                    else:
                        st.error("Could not reach the Ollama endpoint.")
        with save_col:
            if st.button("Save AI settings"):
                if not is_valid_service_url(endpoint):
                    st.error("Ollama endpoint must be an http:// or https:// URL.")
                elif model.strip() and not is_valid_model_name(model.strip()):
                    st.error("Ollama model name can only contain letters, digits, '.', '_', ':', '/' and '-'.")
                else:
                    st.session_state.ollama_endpoint = endpoint.strip()
                    st.session_state.ollama_model = model.strip()
                    record("settings_saved", {"section": "ai", "endpoint": endpoint.strip(), "model": model.strip()})
                    st.success("AI settings saved for this session.")

    with tabs[2]:
        st.subheader("Suricata integration")
        st.warning(
            "Only enable rule management after testing in a safe environment. "
            "Drop rules only block traffic when Suricata runs inline (IPS mode)."
        )

        enable_suricata = st.checkbox("Enable Suricata rule management", value=config.SURICATA_ENABLED)
        rules_dir = st.text_input(
            "Rules directory",
            value=st.session_state.get("suricata_rules_dir", defaults.SURICATA_RULES_DIR),
            placeholder="Example: ./suricata_rules",
            disabled=not enable_suricata,
        )
        dry_run = st.checkbox(
            "Dry-run mode (log proposed rules without writing them)",
            value=config.SURICATA_DRY_RUN,
            disabled=not enable_suricata,
        )
        block_hours = st.number_input(
            "Block duration in hours (0 = permanent until unblocked)",
            min_value=0.0,
            max_value=8760.0,
            value=float(config.BLOCK_DURATION_HOURS or 0),
            step=1.0,
            disabled=not enable_suricata,
            help="Blocked IPs are unblocked automatically after this long. IPs get reassigned, "
                 "so long-lived blocks can hit innocent users later.",
        )
        auto_reload = st.checkbox(
            "Reload Suricata rules automatically after changes (uses suricatasc)",
            value=config.SURICATA_AUTO_RELOAD,
            disabled=not enable_suricata,
            help="Needs Suricata's unix command socket enabled. Without it, restart Suricata after rule changes.",
        )
        auto_approve = st.checkbox(
            "Write AI-suggested rules without asking (not recommended)",
            value=config.AUTO_APPROVE_SURICATA,
            disabled=not enable_suricata,
            help="Rules are still limited to blocking one non-whitelisted source IP.",
        )

        if enable_suricata:
            try:
                rules_path = Path(sanitize_path(rules_dir))
            except ValueError as exc:
                rules_path = None
                st.error(f"Rules directory is invalid: {exc}")
            if rules_path and rules_path.is_dir():
                rules_file = rules_path / "autodefender_custom.rules"
                if rules_file.is_file():
                    content = rules_file.read_text(encoding="utf-8")
                    rule_count = len([
                        line for line in content.splitlines()
                        if line.strip() and not line.strip().startswith("#")
                    ])
                    st.info(f"{rule_count} custom rule(s) found in {rules_file}.")
                    with st.expander("View custom rules"):
                        st.code(content, language="text")
            elif rules_path:
                st.info("The rules directory will be created when the first rule is written.")

        if st.button("Save Suricata settings"):
            try:
                sanitized_rules_dir = sanitize_path(rules_dir or defaults.SURICATA_RULES_DIR)
            except ValueError as exc:
                st.error(f"Invalid Suricata path: {exc}")
            else:
                st.session_state.suricata_enabled = enable_suricata
                st.session_state.suricata_rules_dir = sanitized_rules_dir
                st.session_state.suricata_dry_run = dry_run
                st.session_state.auto_approve_suricata = enable_suricata and auto_approve
                st.session_state.block_duration_hours = float(block_hours)
                st.session_state.suricata_auto_reload = bool(auto_reload)
                record("settings_saved", {
                    "section": "suricata", "enabled": enable_suricata, "dry_run": dry_run,
                    "auto_approve": enable_suricata and auto_approve, "block_hours": float(block_hours),
                    "auto_reload": bool(auto_reload),
                })
                st.success("Suricata settings saved. They apply the next time monitoring starts.")

    with tabs[3]:
        show_database_tab(config.db_path)

    st.markdown("---")
    st.subheader("Persisting configuration")
    st.write(
        "To persist settings across restarts, create a config.ini file (CLI) or set environment variables."
    )
    with st.expander("Example config.ini"):
        st.code(
            """[suricata]
log_path = /var/log/suricata/eve.json
enabled = true
rules_dir = ./suricata_rules
auto_approve = false
dry_run = true
block_hours = 0
auto_reload = false

[ollama]
endpoint = http://localhost:11434
model = your-model-name

[database]
path = autodefender.db

[detection]
port_scan_threshold = 10
port_scan_window_seconds = 60
alert_cooldown_seconds = 600
""",
            language="ini",
        )
    with st.expander("Environment variable reference"):
        st.markdown(
            "- `AUTODEFENDER_UI_PASSWORD` (required for the web console)\n"
            "- `AUTODEFENDER_ALLOWED_DIRS` (extra folders paths may point to)\n"
            "- `AUTODEFENDER_RETENTION_DAYS` (default retention for the purge button)\n"
            "- `AUTODEFENDER_GEOIP_CITY_DB`, `AUTODEFENDER_GEOIP_ASN_DB` (local GeoLite2 files for offline GeoIP)\n"
            "- `AUTODEFENDER_BLOCK_HOURS` (default block duration, 0 = permanent)\n"
            "- `AUTODEFENDER_AUDIT_DB` (audit log location, default audit.db)\n"
            "- `SURICATA_AUTO_RELOAD`, `SURICATA_SOCKET` (reload rules with suricatasc)\n"
            "- `OLLAMA_ENDPOINT`, `OLLAMA_MODEL`, `WEBHOOK_URL`\n"
            "- `SURICATA_ENABLED`, `SURICATA_RULES_DIR`, `SURICATA_DRY_RUN`, `AUTO_APPROVE_SURICATA`"
        )


def show_database_tab(db_path: str) -> None:
    """Database size, backup, retention, and clearing."""
    st.subheader("Database management")
    st.text_input("Database path", value=db_path, key="settings_db_path_display", disabled=True)

    path = Path(db_path)
    if not path.exists():
        st.warning("The database file does not exist at the specified path.")
        return

    st.info(f"Current database size: {path.stat().st_size / (1024 * 1024):.2f} MB")
    db = Database(db_path)
    try:
        stats = db.get_stats()
        stat_col1, stat_col2 = st.columns(2)
        stat_col1.metric("Threat records", stats.total_threats)
        stat_col2.metric("Action records", len(db.get_actions(limit=100000)))

        st.markdown("#### Backup")
        st.caption("Downloads a copy of the database. It contains IP addresses, so store it securely.")
        if st.button("Prepare backup download"):
            record("database_backup_downloaded", {"db": db_path})
            st.download_button(
                "Download backup",
                path.read_bytes(),
                file_name=f"autodefender_backup_{path.stem}.db",
                mime="application/octet-stream",
            )

        st.markdown("#### Data retention")
        retention_days = st.number_input(
            "Delete threats older than (days)",
            min_value=1,
            max_value=3650,
            value=Config.RETENTION_DAYS or 90,
            help="Keeping only what you need limits how much IP and traffic data is stored.",
        )
        if st.button("Delete old threats"):
            deleted = db.purge_threats_older_than(int(retention_days))
            record("threats_purged", {"older_than_days": int(retention_days), "deleted": deleted})
            st.success(f"Deleted {deleted} threat(s) older than {int(retention_days)} days.")

        st.markdown("#### Clear data")
        st.warning("These operations permanently delete data. Download a backup first.")
        clear_option = st.selectbox(
            "Clear data",
            ["Select an option", "All actions", "All threats and actions"],
        )
        if clear_option != "Select an option":
            confirm_clear = st.checkbox(
                f"I understand this permanently deletes: {clear_option.lower()}",
                key="confirm_clear",
            )
            if st.button("Execute clear operation", disabled=not confirm_clear):
                db.clear(
                    threats=clear_option == "All threats and actions",
                    actions=True,
                )
                logger.info("Database cleared from Settings: %s", clear_option)
                record("database_cleared", {"what": clear_option, "db": db_path})
                st.success(f"Completed clear operation: {clear_option}.")
    finally:
        db.close()
