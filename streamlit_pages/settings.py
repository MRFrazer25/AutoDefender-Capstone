"""Settings and configuration page."""

import os
from pathlib import Path

import streamlit as st

from ai_explainer import AIExplainer
from config import Config
from database import Database
from utils.path_utils import sanitize_path, sanitize_filename


def show() -> None:
    """Render the settings page."""
    st.markdown('<div class="main-header">Settings and Configuration</div>', unsafe_allow_html=True)

    config = Config.get_default()
    try:
        db_path = sanitize_path(st.session_state.get("db_path", config.db_path))
    except ValueError:
        db_path = sanitize_path(config.db_path)
        st.session_state.db_path = db_path

    tabs = st.tabs([
        "General",
        "AI and Ollama",
        "Suricata integration",
        "Database",
    ])

    with tabs[0]:
        st.subheader("General settings")
        log_path = st.text_input(
            "Default Suricata log path",
            value=os.getenv("SURICATA_LOG_PATH", config.DEFAULT_SURICATA_LOG_PATH),
            placeholder=r"Example: C:\Program Files\Suricata\log\eve.json",
            help="Path to the Suricata eve.json log file.",
        )

        st.markdown("#### Detection thresholds")
        port_scan_threshold = st.number_input(
            "Port scan threshold",
            min_value=1,
            max_value=100,
            value=config.PORT_SCAN_THRESHOLD,
            help="Number of ports from the same source that triggers a scan alert.",
        )
        suspicious_port_threshold = st.number_input(
            "Suspicious port threshold",
            min_value=1,
            max_value=65535,
            value=config.SUSPICIOUS_PORT_THRESHOLD,
            help="Ports above this value are considered suspicious.",
        )

        st.markdown("#### Interface options")
        refresh_rate = st.slider(
            "Dashboard refresh interval (seconds)",
            min_value=1.0,
            max_value=10.0,
            value=config.REFRESH_RATE,
            step=0.5,
        )
        max_displayed = st.number_input(
            "Maximum threats displayed",
            min_value=10,
            max_value=500,
            value=config.MAX_DISPLAYED_THREATS,
        )

        if st.button("Save general settings"):
            try:
                sanitized_log = sanitize_path(log_path)
            except ValueError as exc:
                st.error(f"Invalid log path: {exc}")
            else:
                os.environ["SURICATA_LOG_PATH"] = sanitized_log
                st.session_state.log_path = sanitized_log
                st.session_state.refresh_rate = refresh_rate
                st.session_state.max_displayed_threats = max_displayed
                st.session_state.port_scan_threshold = port_scan_threshold
                st.session_state.suspicious_port_threshold = suspicious_port_threshold
                st.success("General settings recorded for this session.")
                st.info("Persist settings by adding them to your environment or config.ini file.")

    with tabs[1]:
        st.subheader("AI and Ollama configuration")
        endpoint = st.text_input(
            "Ollama endpoint URL",
            value=st.session_state.get("ollama_endpoint", config.OLLAMA_ENDPOINT),
            placeholder="Example: http://127.0.0.1:11434",
        )
        model = st.text_input(
            "Ollama model name",
            value=st.session_state.get("ollama_model", config.OLLAMA_MODEL or ""),
            placeholder="Example: phi4-mini",
        )

        if st.button("Test Ollama connection"):
            try:
                temp_config = Config.get_default()
                temp_config.ollama_endpoint = endpoint
                temp_config.ollama_model = model or None
                explainer = AIExplainer(temp_config)
                if explainer.client:
                    st.success("Ollama responded successfully.")
                    st.info("Available models: " + ", ".join(explainer.available_models))
                else:
                    st.error("Could not reach the Ollama endpoint.")
            except Exception as exc:
                st.error(f"Connection error: {exc}")

        ai_severities = st.multiselect(
            "Generate AI explanations for severities",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH"],
        )

        if st.button("Save AI settings"):
            os.environ["OLLAMA_ENDPOINT"] = endpoint
            os.environ["OLLAMA_MODEL"] = model
            st.session_state.ollama_endpoint = endpoint
            st.session_state.ollama_model = model
            st.session_state.ai_severities = ai_severities
            st.success("AI settings recorded for this session.")

    with tabs[2]:
        st.subheader("Suricata integration")
        st.warning(
            "Only enable rule management after testing in a safe environment and keeping backups."
        )

        enable_suricata = st.checkbox(
            "Enable Suricata rule management",
            value=st.session_state.get("suricata_enabled", config.SURICATA_ENABLED),
        )

        rules_dir = ""
        dry_run = st.session_state.get("suricata_dry_run", config.SURICATA_DRY_RUN)
        auto_approve = config.AUTO_APPROVE_SURICATA
        suricata_config_path = config.SURICATA_CONFIG_PATH

        if enable_suricata:
            rules_dir = st.text_input(
                "Rules directory",
                value=st.session_state.get("suricata_rules_dir", config.SURICATA_RULES_DIR),
                placeholder="Example: ./suricata_rules",
            )
            try:
                normalized_rules_path = sanitize_path(rules_dir)
            except ValueError as exc:
                normalized_rules_path = None
                st.error(f"Rules directory is invalid: {exc}")
            else:
                if os.path.exists(normalized_rules_path):
                    st.success(f"Rules directory found at {normalized_rules_path}.")
                    # Use os.path.join with normalized string and constant
                    rules_file_str = os.path.join(normalized_rules_path, "autodefender_custom.rules")
                    # Validate the final path to ensure it's still within safe directory
                    try:
                        normalized_rules_file = sanitize_path(rules_file_str)
                        # Additional check: ensure it's still within the rules directory
                        if not normalized_rules_file.startswith(normalized_rules_path + os.sep) and normalized_rules_file != normalized_rules_path:
                            raise ValueError("Rules file path is outside rules directory")
                    except ValueError:
                        # If validation fails, path is invalid
                        st.error("Invalid rules file path")
                        normalized_rules_file = None
                    
                    if normalized_rules_file and os.path.exists(normalized_rules_file):
                        with open(normalized_rules_file, "r", encoding="utf-8") as handle:
                            content = handle.read()
                            st.info(
                                f"{len([line for line in content.splitlines() if line.strip() and not line.strip().startswith('#')])} custom rule(s) found."
                            )
                            with st.expander("View custom rules"):
                                st.code(content, language="text")
                else:
                    st.warning("Rules directory does not exist yet.")
                    if st.button("Create rules directory"):
                        try:
                            os.makedirs(normalized_rules_path, exist_ok=True)
                            st.success("Directory created.")
                        except Exception as exc:
                            st.error(f"Unable to create directory: {exc}")

            dry_run = st.checkbox(
                "Dry-run mode",
                value=dry_run,
                help="Log proposed rules without writing to disk.",
            )
            auto_approve = st.checkbox(
                "Automatically approve rules (not recommended)",
                value=os.getenv("AUTO_APPROVE_SURICATA", "false").lower() == "true",
            )
            suricata_config_path = st.text_input(
                "Suricata configuration file (optional)",
                value=os.getenv("SURICATA_CONFIG_PATH", config.SURICATA_CONFIG_PATH),
                placeholder=r"Example: C:\Program Files\Suricata\suricata.yaml",
            )
        else:
            st.info("Suricata integration is currently disabled.")

        if st.button("Save Suricata settings"):
            try:
                sanitized_rules_dir = sanitize_path(rules_dir) if rules_dir else sanitize_path(config.SURICATA_RULES_DIR)
                sanitized_config_path = (
                    sanitize_path(suricata_config_path)
                    if suricata_config_path
                    else ""
                )
            except ValueError as exc:
                st.error(f"Invalid Suricata path: {exc}")
            else:
                st.session_state.suricata_enabled = enable_suricata
                st.session_state.suricata_rules_dir = sanitized_rules_dir
                st.session_state.suricata_dry_run = dry_run
                os.environ["SURICATA_ENABLED"] = "true" if enable_suricata else "false"
                os.environ["SURICATA_RULES_DIR"] = sanitized_rules_dir
                os.environ["SURICATA_DRY_RUN"] = "true" if dry_run else "false"
                os.environ["AUTO_APPROVE_SURICATA"] = "true" if auto_approve else "false"
                if sanitized_config_path:
                    os.environ["SURICATA_CONFIG_PATH"] = sanitized_config_path
                st.success("Suricata settings recorded for this session.")

    with tabs[3]:
        st.subheader("Database management")
        db_exists = Path(db_path).exists()
        st.text_input(
            "Database path",
            value=db_path,
            key="settings_db_path_display",
            disabled=True,
        )

        if db_exists:
            db_size = Path(db_path).stat().st_size / (1024 * 1024)
            st.info(f"Current database size: {db_size:.2f} MB")
            try:
                db_info = Database(db_path)
                threat_count = len(db_info.get_threats(limit=100000))
                action_count = len(db_info.get_actions(limit=100000))
                db_info.close()
                stat_col1, stat_col2 = st.columns(2)
                stat_col1.metric("Threat records", threat_count)
                stat_col2.metric("Action records", action_count)
            except Exception as exc:
                st.error(f"Error reading database: {exc}")
        else:
            st.warning("The database file does not exist at the specified path.")

        st.markdown("#### Maintenance")
        st.warning(
            "These operations can delete data permanently. Back up the database before making changes."
        )

        if st.button("Export database backup"):
            if db_exists:
                import shutil
                from datetime import datetime
                backup_dir = Path("backups")
                backup_dir.mkdir(parents=True, exist_ok=True)
                backup_name = sanitize_filename(
                    f"autodefender_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
                )
                backup_path = backup_dir / backup_name
                try:
                    shutil.copy2(db_path, backup_path)
                    st.success(f"Backup created: {backup_path}")
                    with open(backup_path, "rb") as handle:
                        st.download_button(
                            "Download backup",
                            handle.read(),
                            file_name=backup_name,
                            mime="application/octet-stream",
                        )
                except Exception as exc:
                    st.error(f"Failed to create backup: {exc}")
            else:
                st.error("Database file not found; backup skipped.")

        clear_option = st.selectbox(
            "Clear data",
            ["Select an option", "All threats", "All actions", "Everything"],
        )
        if clear_option != "Select an option":
            if st.button("Execute clear operation"):
                try:
                    db_handle = Database(db_path)
                    cursor = db_handle.conn.cursor()
                    if clear_option == "All threats":
                        cursor.execute("DELETE FROM threats")
                    elif clear_option == "All actions":
                        cursor.execute("DELETE FROM actions")
                    elif clear_option == "Everything":
                        cursor.execute("DELETE FROM threats")
                        cursor.execute("DELETE FROM actions")
                        cursor.execute("DELETE FROM stats")
                    db_handle.conn.commit()
                    db_handle.close()
                    st.success(f"Completed clear operation: {clear_option}.")
                except Exception as exc:
                    st.error(f"Clear operation failed: {exc}")

    st.markdown("---")
    st.subheader("Persisting configuration")
    st.write(
        "To persist settings across restarts, create a config.ini file or set environment variables."
    )
    with st.expander("Example config.ini"):
        st.code(
            """[suricata]
log_path = C:\\Program Files\\Suricata\\log\\eve.json
enabled = true
rules_dir = ./suricata_rules
auto_approve = false
dry_run = true

[ollama]
endpoint = http://localhost:11434
model = phi4-mini

[database]
path = autodefender.db

[detection]
port_scan_threshold = 10
suspicious_port_threshold = 1024
""",
            language="ini",
        )
    with st.expander("Environment variable reference"):
        st.write(
            "SURICATA_LOG_PATH, OLLAMA_ENDPOINT, OLLAMA_MODEL, SURICATA_ENABLED, "
            "SURICATA_RULES_DIR, SURICATA_CONFIG_PATH, AUTO_APPROVE_SURICATA, SURICATA_DRY_RUN"
        )

