"""Setup page for initial configuration."""

import logging
import shutil
import uuid
from pathlib import Path
from urllib.parse import urlparse

import streamlit as st

from config import Config
from notifications.webhook import is_valid_webhook_url
from streamlit_pages.session_config import record
from utils.path_utils import sanitize_path

logger = logging.getLogger(__name__)

# Uploads are stored inside the project so the path checks accept them
UPLOAD_DIR = Path("uploads")

DEMO_LOG = Path("demo/example_suricata_log.json")
DEMO_DB = Path("demo/demo_config.db")
DEMO_WORKING_DB = Path("demo/generated/demo_session.db")


def _save_upload(uploaded_file, allowed_suffixes: set) -> Path:
    """Save an uploaded file under a random name and return its absolute path.

    The browser-supplied filename is never used as a path, only its extension.
    """
    suffix = Path(uploaded_file.name).suffix.lower()
    if suffix not in allowed_suffixes:
        raise ValueError(f"File type {suffix or '(none)'} is not allowed")
    UPLOAD_DIR.mkdir(exist_ok=True)
    saved_path = UPLOAD_DIR / f"{uuid.uuid4().hex}{suffix}"
    with open(saved_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return saved_path.resolve()


def is_valid_service_url(url: str) -> bool:
    """Accept only http(s) URLs with a host, e.g. the Ollama endpoint."""
    parsed = urlparse(url or "")
    return parsed.scheme in ("http", "https") and bool(parsed.hostname)


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
            if not DEMO_LOG.exists() or not DEMO_DB.exists():
                st.error("Demo files are missing from the demo/ folder.")
                st.stop()
            # Work on a copy so monitoring and approvals never modify the committed demo database
            DEMO_WORKING_DB.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(DEMO_DB, DEMO_WORKING_DB)

            st.session_state.log_path = str(DEMO_LOG)
            st.session_state.db_path = str(DEMO_WORKING_DB)
            st.session_state.ollama_endpoint = "http://127.0.0.1:11434"
            st.session_state.ollama_model = "phi4-mini"
            st.session_state.suricata_rules_dir = "./suricata_rules"
            st.session_state.suricata_enabled = True
            st.session_state.suricata_dry_run = True
            st.session_state.setup_complete = True

            # Also update widget keys so text inputs display the new values
            st.session_state.log_path_input = str(DEMO_LOG)
            st.session_state.db_path_input = str(DEMO_WORKING_DB)

            # Clear processed file tracking so demo paths work
            st.session_state.pop("processed_log_files", None)
            st.session_state.pop("processed_db_file", None)
            st.session_state.setup_notice = (
                "Demo configuration loaded (dry-run mode, working copy of the demo database). "
                "Open the Dashboard or Threat Analysis to explore it."
            )
            st.rerun()
        except OSError:
            # Full details go to the server log, not the browser
            logger.exception("Unable to load demo configuration")
            st.error("Unable to load demo configuration. Check the server log for details.")

    notice = st.session_state.pop("setup_notice", None)
    if notice:
        st.success(notice)

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
        # Initialize widget key if it doesn't exist
        if "log_path_input" not in st.session_state:
            st.session_state.log_path_input = st.session_state.get("log_path", default_log_path)
        
        log_path = st.text_area(
            "Suricata eve.json path(s)",
            height=80,
            placeholder="Example: C:\\Program Files\\Suricata\\log\\eve.json\nFor multiple sources, enter one path per line",
            key="log_path_input",
        )
        # Sync widget value with session state
        if log_path:
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
            # Track processed files to avoid infinite loop
            processed_key = "processed_log_files"
            if processed_key not in st.session_state:
                st.session_state[processed_key] = set()
            
            files_to_process = uploaded_log if isinstance(uploaded_log, list) else [uploaded_log]
            new_files = []
            
            for uploaded_file in files_to_process:
                # Check if we've already processed this file
                file_id = f"{uploaded_file.name}_{uploaded_file.size}"
                if file_id not in st.session_state[processed_key]:
                    # Save uploaded files and use their paths
                    try:
                        abs_path = _save_upload(uploaded_file, {".json", ".log", ".txt"})
                    except ValueError as exc:
                        st.error(str(exc))
                        continue
                    new_files.append(str(abs_path))
                    st.session_state[processed_key].add(file_id)
            
            if new_files:
                # Update log path with new files
                existing_paths = st.session_state.get("log_path", "").split('\n')
                existing_paths = [p.strip() for p in existing_paths if p.strip()]
                all_paths = existing_paths + new_files
                st.session_state.log_path = "\n".join(all_paths)
                st.success("File(s) saved. Path(s) updated above.")
                st.rerun()
    
    # Database path section with native file picker
    db_path_col1, db_path_col2 = st.columns([3, 1])
    with db_path_col1:
        # Initialize widget key if it doesn't exist
        if "db_path_input" not in st.session_state:
            st.session_state.db_path_input = st.session_state.get("db_path", default_db_path)
        
        db_path = st.text_input(
            "AutoDefender database path",
            placeholder="Example: autodefender.db",
            key="db_path_input",
        )
        # Sync widget value with session state
        if db_path:
            st.session_state.db_path = db_path
    with db_path_col2:
        uploaded_db = st.file_uploader(
            "Browse files",
            type=["db", "sqlite", "sqlite3"],
            help="Opens your system's file picker to select database file.",
            key="upload_db",
            label_visibility="collapsed",
        )
        if uploaded_db:
            # Track processed files to avoid infinite loop
            processed_key = "processed_db_file"
            if processed_key not in st.session_state:
                st.session_state[processed_key] = None
            
            # Check if we've already processed this file
            file_id = f"{uploaded_db.name}_{uploaded_db.size}"
            if st.session_state[processed_key] != file_id:
                # Save uploaded file and use its path
                try:
                    abs_path = _save_upload(uploaded_db, {".db", ".sqlite", ".sqlite3"})
                except ValueError as exc:
                    st.error(str(exc))
                    st.stop()
                st.session_state.db_path = str(abs_path)
                st.session_state[processed_key] = file_id
                st.success("File saved. Path updated above.")
                st.rerun()

    with st.form("setup_form"):

        st.subheader("AI service")
        ollama_endpoint = st.text_input(
            "Ollama endpoint URL",
            value=st.session_state.get("ollama_endpoint", default_ollama_endpoint),
            placeholder="Example: http://127.0.0.1:11434",
        )
        ollama_model = st.text_input(
            "Ollama model name",
            value=st.session_state.get("ollama_model", default_ollama_model),
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
            value=st.session_state.get("suricata_rules_dir", default_rules_dir),
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
        if ollama_endpoint.strip() and not is_valid_service_url(ollama_endpoint.strip()):
            errors.append("Ollama endpoint must be an http:// or https:// URL.")
        if webhook_url.strip() and not is_valid_webhook_url(webhook_url.strip()):
            errors.append("Webhook URL must be an https:// URL.")

        if errors:
            for error in errors:
                st.error(error)
            st.session_state.setup_complete = False
            return

        try:
            # Handle multi-path log input BEFORE sanitization
            log_paths = [l.strip() for l in log_path.strip().split('\n') if l.strip()]
            sanitized_paths = [sanitize_path(p, include_log_dirs=True) for p in log_paths]
            
            sanitized_db_path = sanitize_path(db_path)
            sanitized_rules_dir = sanitize_path(rules_dir)
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

        record("setup_saved", {"db": sanitized_db_path, "suricata_enabled": suricata_enabled, "dry_run": dry_run})
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
        "- The console requires the AUTODEFENDER_UI_PASSWORD environment variable (12+ characters)."
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
                sanitized = sanitize_path(log_path, include_log_dirs=True)
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


