"""Setup page for initial configuration."""

import os
import tempfile
from pathlib import Path

import streamlit as st

from config import Config
from utils.path_utils import sanitize_path


def show() -> None:
    """Render the setup page."""
    st.markdown('<div class="main-header">Initial Configuration</div>', unsafe_allow_html=True)
    st.write(
        "Complete this form before using the console. "
        "The values are stored for this session only."
    )

    config = Config.get_default()

    demo_clicked = st.button("Load demo configuration", type="secondary", use_container_width=True)

    if demo_clicked:
        try:
            # Use relative paths for demo - will be sanitized when used
            st.session_state.log_path = "demo/example_suricata_log.json"
            st.session_state.db_path = "demo/demo_config.db"
            st.session_state.ollama_endpoint = "http://127.0.0.1:11434"
            st.session_state.ollama_model = "phi4-mini"
            st.session_state.suricata_rules_dir = "./suricata_rules"
            st.session_state.suricata_enabled = True
            st.session_state.suricata_dry_run = True
            st.session_state.setup_complete = True

            # Ensure demo database exists
            demo_db_path = Path("demo/demo_config.db")
            demo_db_path.parent.mkdir(parents=True, exist_ok=True)
            if not demo_db_path.exists():
                from database import Database
                demo_db = Database(str(demo_db_path))
                demo_db.close()

            # Set environment variables for immediate use
            os.environ["SURICATA_LOG_PATH"] = st.session_state.log_path
            os.environ["SURICATA_ENABLED"] = "true" if st.session_state.suricata_enabled else "false"
            os.environ["SURICATA_RULES_DIR"] = st.session_state.suricata_rules_dir
            os.environ["SURICATA_DRY_RUN"] = "true" if st.session_state.suricata_dry_run else "false"
            os.environ["OLLAMA_ENDPOINT"] = st.session_state.ollama_endpoint
            os.environ["OLLAMA_MODEL"] = st.session_state.ollama_model
            os.environ["DB_PATH"] = st.session_state.db_path

            # Verify demo database has data
            try:
                from database import Database
                demo_db = Database(str(demo_db_path))
                demo_threats = demo_db.get_threats()
                threat_count = len(demo_threats)
                demo_db.close()
                if threat_count > 0:
                    st.success(f"Demo configuration loaded! Database has {threat_count} threats. Navigate to Dashboard or Threat Analysis to view them.")
                else:
                    st.warning("Demo database exists but appears empty. Run 'python tools/populate_demo_db.py' to populate it.")
            except Exception as e:
                st.warning(f"Could not verify demo database: {e}")
            
            st.rerun()
        except ValueError as exc:
            st.error(f"Unable to load demo configuration: {exc}")

    default_log_path = st.session_state.get(
        "log_path", config.DEFAULT_SURICATA_LOG_PATH
    )
    default_db_path = st.session_state.get("db_path", config.db_path)
    default_ollama_endpoint = st.session_state.get(
        "ollama_endpoint", config.OLLAMA_ENDPOINT
    )
    default_ollama_model = st.session_state.get(
        "ollama_model", config.OLLAMA_MODEL or ""
    )
    default_rules_dir = st.session_state.get(
        "suricata_rules_dir", config.SURICATA_RULES_DIR
    )

    st.subheader("Core paths")
    
    # Log path section with native file picker
    log_path_col1, log_path_col2 = st.columns([3, 1])
    with log_path_col1:
        # Get current value from session state or default
        current_log_path = st.session_state.get("log_path", default_log_path)
        log_path = st.text_area(
            "Suricata eve.json path(s)",
            value=current_log_path,
            height=80,
            placeholder="Example: C:\\Program Files\\Suricata\\log\\eve.json\nFor multiple sources, enter one path per line",
            key="log_path_input",
        )
        # Sync text area value with session state
        if log_path != current_log_path:
            st.session_state.log_path = log_path
    with log_path_col2:
        uploaded_log = st.file_uploader(
            "Browse files",
            type=["json", "log", "txt"],
            help="Opens your system's file picker to select log file(s).",
            key="upload_log",
            accept_multiple_files=True,
            label_visibility="collapsed",
        )
        if uploaded_log:
            # Save uploaded files and use their paths
            saved_paths = []
            upload_dir = Path(tempfile.gettempdir()) / "autodefender_uploads"
            upload_dir.mkdir(exist_ok=True)
            
            files_to_process = uploaded_log if isinstance(uploaded_log, list) else [uploaded_log]
            for uploaded_file in files_to_process:
                saved_path = upload_dir / uploaded_file.name
                with open(saved_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                # Use absolute path and normalize for Windows
                abs_path = saved_path.resolve()
                saved_paths.append(str(abs_path))
            
            st.session_state.log_path = "\n".join(saved_paths)
            st.success(f"File(s) saved to: {upload_dir}")
            st.rerun()
    
    # Database path section with native file picker
    db_path_col1, db_path_col2 = st.columns([3, 1])
    with db_path_col1:
        db_path = st.text_input(
            "AutoDefender database path",
            value=st.session_state.get("db_path", default_db_path),
            placeholder="Example: autodefender.db",
            key="db_path_input",
        )
        # Update session state when user types
        if "db_path_input" in st.session_state:
            st.session_state.db_path = st.session_state.db_path_input
    with db_path_col2:
        uploaded_db = st.file_uploader(
            "Browse files",
            type=["db", "sqlite", "sqlite3"],
            help="Opens your system's file picker to select database file.",
            key="upload_db",
            label_visibility="collapsed",
        )
        if uploaded_db:
            # Save uploaded file and use its path
            upload_dir = Path(tempfile.gettempdir()) / "autodefender_uploads"
            upload_dir.mkdir(exist_ok=True)
            saved_path = upload_dir / uploaded_db.name
            with open(saved_path, "wb") as f:
                f.write(uploaded_db.getbuffer())
            # Use absolute path and normalize for Windows
            abs_path = saved_path.resolve()
            st.session_state.db_path = str(abs_path)
            st.success(f"File saved to: {upload_dir}")
            st.rerun()

    with st.form("setup_form"):

        st.subheader("AI service")
        ollama_endpoint = st.text_input(
            "Ollama endpoint URL",
            value=default_ollama_endpoint,
            placeholder="Example: http://127.0.0.1:11434",
        )
        ollama_model = st.text_input(
            "Ollama model name",
            value=default_ollama_model,
            placeholder="Example: phi4-mini",
        )
        webhook_url = st.text_input(
            "Notification webhook URL (optional)",
            value=st.session_state.get("webhook_url", config.WEBHOOK_URL),
            placeholder="Example: https://hooks.slack.com/services/...",
            help="If provided, approved actions can trigger this webhook (Slack, Teams, etc.)",
        )

        st.subheader("Suricata integration")
        suricata_enabled = st.checkbox(
            "Enable Suricata rule management",
            value=st.session_state.get("suricata_enabled", config.SURICATA_ENABLED),
        )
        rules_dir = st.text_input(
            "Rules directory",
            value=default_rules_dir,
            placeholder="Example: ./suricata_rules",
        )
        dry_run = st.checkbox(
            "Run in dry-run mode (recommended for testing)",
            value=st.session_state.get("suricata_dry_run", config.SURICATA_DRY_RUN),
        )

        submitted = st.form_submit_button("Save configuration")

    if submitted:
        # Get current values from session state (updated by inputs or file browser)
        log_path = st.session_state.get("log_path", default_log_path)
        db_path = st.session_state.get("db_path", default_db_path)
        
        errors = []

        if not log_path.strip():
            errors.append("Log path is required.")
        if not db_path.strip():
            errors.append("Database path is required.")
        if not ollama_endpoint.strip():
            errors.append("Ollama endpoint is required.")
        if not ollama_model.strip():
            errors.append("Ollama model name is required.")

        if errors:
            for error in errors:
                st.error(error)
            st.session_state.setup_complete = False
            return

        try:
            # Handle multi-path log input BEFORE sanitization
            log_paths = [l.strip() for l in log_path.strip().split('\n') if l.strip()]
            sanitized_paths = [str(sanitize_path(p)) for p in log_paths]
            
            sanitized_db_path = str(sanitize_path(db_path))
            sanitized_rules_dir = str(sanitize_path(rules_dir))
        except ValueError as exc:
            st.error(f"Invalid path: {exc}")
            st.session_state.setup_complete = False
            return

        st.session_state.log_path = '\n'.join(sanitized_paths)
        st.session_state.db_path = sanitized_db_path
        st.session_state.ollama_endpoint = ollama_endpoint.strip()
        st.session_state.ollama_model = ollama_model.strip()
        st.session_state.suricata_enabled = suricata_enabled
        st.session_state.suricata_rules_dir = sanitized_rules_dir
        st.session_state.suricata_dry_run = dry_run
        st.session_state.webhook_url = webhook_url.strip()
        st.session_state.setup_complete = True

        os.environ["SURICATA_LOG_PATH"] = st.session_state.log_path
        os.environ["SURICATA_ENABLED"] = "true" if suricata_enabled else "false"
        os.environ["SURICATA_RULES_DIR"] = st.session_state.suricata_rules_dir
        os.environ["SURICATA_DRY_RUN"] = "true" if dry_run else "false"
        os.environ["OLLAMA_ENDPOINT"] = st.session_state.ollama_endpoint
        os.environ["OLLAMA_MODEL"] = st.session_state.ollama_model
        if webhook_url.strip():
            os.environ["WEBHOOK_URL"] = webhook_url.strip()

        st.success("Configuration saved. You can now use the other pages.")

    st.markdown("### Status")
    if st.session_state.setup_complete:
        st.info("Setup is complete for this session.")
    else:
        st.warning("Setup is not complete. Fill in the form above.")

    st.markdown("### Guidance")
    st.write(
        "- Verify the log file path and ensure the account running this console can read it.\n"
        "- Run Ollama locally or expose it on a secure internal network.\n"
        "- Keep this console behind a VPN or reverse proxy with authentication.\n"
        "- Set the AUTODEFENDER_UI_PASSWORD environment variable to require a password."
    )

    # Validate log paths if any are configured
    current_log_path = st.session_state.get("log_path", "")
    if current_log_path and current_log_path.strip():
        # Handle multi-path input (newline-separated)
        log_paths = [p.strip() for p in current_log_path.split('\n') if p.strip()]
        missing_paths = []
        existing_paths = []
        
        for log_path in log_paths:
            # Sanitize path before checking
            try:
                sanitized = sanitize_path(log_path)
                path_obj = Path(sanitized)
                if path_obj.exists():
                    existing_paths.append(log_path)
                else:
                    missing_paths.append(log_path)
            except (ValueError, Exception):
                # If sanitization fails, treat as missing
                missing_paths.append(log_path)
        
        if missing_paths:
            if len(missing_paths) == len(log_paths):
                st.warning(
                    "None of the specified log files exist yet. "
                    "Make sure Suricata is configured to write to these paths, "
                    "or use the file browser to upload files for analysis."
                )
            else:
                st.warning(
                    f"Some log files do not exist yet: {', '.join(missing_paths)}. "
                    "Make sure Suricata is configured to write to these paths."
                )
        elif existing_paths:
            st.success(f"Found {len(existing_paths)} log file(s). Ready for monitoring.")


