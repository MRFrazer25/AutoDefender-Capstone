#!/usr/bin/env python3
"""AutoDefender Streamlit Web UI."""

import functools
import hashlib
import hmac
import importlib
import os
import logging
import secrets
import threading
import time
from datetime import datetime, timezone

import streamlit as st

from autodefender import audit
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


st.set_page_config(
    page_title="AutoDefender Web Console",
    page_icon="AutoDef",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "About": "AutoDefender web console for Suricata monitoring and analysis."
    },
)

st.markdown(
    """
<style>
    .main-header {
        font-size: 2rem;
        font-weight: 600;
        color: #0b3d6d;
        margin-bottom: 1rem;
    }
    .subhead {
        font-size: 1.2rem;
        font-weight: 500;
        color: #244b66;
        margin-top: 1rem;
    }
    .metric-card {
        background-color: #eef2f6;
        padding: 0.75rem;
        border-radius: 0.4rem;
        margin: 0.4rem 0;
    }
</style>
""",
    unsafe_allow_html=True,
)


PASSWORD_ENV = "AUTODEFENDER_UI_PASSWORD"
DEV_MODE_ENV = "AUTODEFENDER_DEV"
MIN_PASSWORD_LENGTH = 12
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
PBKDF2_ITERATIONS = 200_000
LOCAL_ADDRESSES = {"localhost", "127.0.0.1", "::1"}
# Sign the session out after this long without any interaction
IDLE_TIMEOUT_SECONDS = 30 * 60
# Example passwords from the docs; using one unchanged would be a known default credential
PLACEHOLDER_PASSWORDS = {
    "replace-with-a-long-random-password",
    "choose-a-long-password",
    "pick-any-long-password",
}

# Page name -> module in streamlit_pages
PAGES = {
    "Setup": "setup",
    "Dashboard": "dashboard",
    "Incidents": "incidents",
    "Threat Analysis": "threat_analysis",
    "Action Management": "action_management",
    "IP Management": "ip_management",
    "Playbook Editor": "playbook_editor",
    "Settings": "settings",
    "Audit Log": "audit_log",
    "Documentation": "documentation",
}
RESTRICTED_BEFORE_SETUP = {
    "Dashboard", "Incidents", "Threat Analysis", "Action Management", "Playbook Editor", "IP Management",
}


@st.cache_resource
def _login_guard() -> dict:
    """In-memory sign-in state shared by every browser session in this server process.

    The lock serializes sign-in checks; the failure times back up the audit
    log (which makes the lockout survive restarts) in case it can't be written.
    """
    return {"lock": threading.Lock(), "failures": []}


@st.cache_resource
def _fingerprint_key() -> bytes:
    """Random per-process key for password fingerprints (never written anywhere)."""
    return secrets.token_bytes(32)


def _password_digest(password: str) -> bytes:
    """Salted PBKDF2 digest of a password, keyed to this server process."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), _fingerprint_key(), PBKDF2_ITERATIONS)


@functools.lru_cache(maxsize=4)
def _configured_password_digest(password: str) -> bytes:
    """Digest of the configured password; cached since every rerun needs it."""
    return _password_digest(password)


def _password_fingerprint(password: str) -> str:
    """Fingerprint of the configured password, used to end sessions when it changes."""
    return _configured_password_digest(password).hex()


def _lockout_remaining(failure_times: list, now: float) -> float:
    """Seconds left in a lockout, given failed sign-in times since the last success.

    Sliding window: at most MAX_ATTEMPTS failures per LOCKOUT_SECONDS.
    """
    recent = sorted(t for t in failure_times if now - t < LOCKOUT_SECONDS)
    if len(recent) < MAX_ATTEMPTS:
        return 0.0
    return max(0.0, recent[-MAX_ATTEMPTS] + LOCKOUT_SECONDS - now)


def _persisted_failures(now: float) -> list:
    """Failed sign-in times from the audit log since the last successful sign-in."""
    since = datetime.fromtimestamp(now - LOCKOUT_SECONDS, tz=timezone.utc)
    failures = []
    try:
        for entry in audit.recent({"sign_in", "sign_in_failed"}, since):
            if entry["action"] == "sign_in":
                failures = []
            else:
                failures.append(entry["timestamp"].timestamp())
    except Exception:
        logger.exception("Could not read sign-in history from the audit log")
    return failures


def _configured_password() -> str:
    """Read the console password from the environment or Streamlit secrets."""
    password = os.getenv(PASSWORD_ENV, "")
    if not password:
        try:
            password = str(st.secrets.get(PASSWORD_ENV, ""))
        except Exception:
            # No secrets.toml present
            password = ""
    return password


def _dev_mode_allowed() -> bool:
    """Allow running without a password only in dev mode on a localhost-only server."""
    if os.getenv(DEV_MODE_ENV) != "1":
        return False
    address = (st.get_option("server.address") or "").strip().strip("[]")
    return address in LOCAL_ADDRESSES


def ensure_session_defaults() -> None:
    """Set up default session state values."""
    defaults = {
        "log_path": "",
        "setup_complete": False,
        "authenticated": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def require_password() -> bool:
    """Require the AUTODEFENDER_UI_PASSWORD before showing the console.

    Fails closed: with no password configured the console refuses to run,
    unless AUTODEFENDER_DEV=1 and the server only listens on localhost.
    """
    password_required = _configured_password()
    if not password_required:
        if _dev_mode_allowed():
            st.sidebar.warning("Dev mode: no password set. Localhost only.")
            st.session_state.authenticated = True
            return True
        st.title("AutoDefender Web Console")
        st.error(
            f"Set {PASSWORD_ENV} before starting the console. "
            "Refusing to run without a password."
        )
        st.stop()

    if len(password_required) < MIN_PASSWORD_LENGTH:
        st.title("AutoDefender Web Console")
        st.error(
            f"{PASSWORD_ENV} must be at least {MIN_PASSWORD_LENGTH} characters. "
            "Choose a longer password and restart the console."
        )
        st.stop()

    if password_required.strip().lower() in PLACEHOLDER_PASSWORDS:
        st.title("AutoDefender Web Console")
        st.error(
            f"{PASSWORD_ENV} is still set to the example value from the docs. "
            "Choose your own password and restart the console."
        )
        st.stop()

    fingerprint = _password_fingerprint(password_required)
    if st.session_state.authenticated and st.session_state.get("password_fingerprint") != fingerprint:
        # The password changed since this session signed in
        audit.record("console", "signed_out_password_changed")
        st.session_state.clear()
        st.session_state.authenticated = False
        st.info("The console password changed. Sign in again.")

    if st.session_state.authenticated:
        now = time.time()
        last_seen = st.session_state.get("last_activity", now)
        # A running dashboard refreshes itself, so it counts as activity
        if now - last_seen > IDLE_TIMEOUT_SECONDS:
            audit.record("console", "session_timeout")
            st.session_state.clear()
            st.session_state.authenticated = False
            st.info("You were signed out after 30 minutes of inactivity.")
        else:
            st.session_state.last_activity = now
            return True

    st.title("AutoDefender Web Console")
    st.warning("This console is protected. Enter the access password to continue.")
    with st.form("sign_in"):
        password_input = st.text_input(
            "Access password",
            type="password",
            placeholder="Enter the password provided by the administrator",
        )
        submitted = st.form_submit_button("Sign in")

    if submitted:
        guard = _login_guard()
        # Check the lockout and the password in one locked step, so parallel
        # attempts can't slip past the attempt limit
        with guard["lock"]:
            now = time.time()
            remaining = max(
                _lockout_remaining(guard["failures"], now),
                _lockout_remaining(_persisted_failures(now), now),
            )
            if remaining > 0:
                audit.record("console", "sign_in_blocked", {"seconds_left": int(remaining) + 1})
            else:
                # Compare fixed-length digests in constant time
                supplied = _password_digest(password_input)
                expected = _configured_password_digest(password_required)
                if hmac.compare_digest(supplied, expected):
                    guard["failures"].clear()
                    st.session_state.authenticated = True
                    st.session_state.password_fingerprint = fingerprint
                    st.session_state.last_activity = time.time()
                    logger.info("Console sign-in succeeded")
                    audit.record("console", "sign_in")
                    st.rerun()

                guard["failures"].append(now)
                guard["failures"] = [t for t in guard["failures"] if now - t < LOCKOUT_SECONDS]
                logger.warning("Console sign-in failed (%s recently)", len(guard["failures"]))
                audit.record("console", "sign_in_failed", {"recent_failures": len(guard["failures"])})
                if _lockout_remaining(guard["failures"], now) > 0:
                    logger.warning("Console sign-in locked for up to %s seconds", LOCKOUT_SECONDS)
                    audit.record("console", "sign_in_locked", {"seconds": LOCKOUT_SECONDS})
        time.sleep(1)  # Slows down guessing (outside the lock)
        if remaining > 0:
            st.error(f"Too many failed attempts. Try again in {int(remaining) + 1} seconds.")
            return False
        st.error("Password incorrect. Access denied.")

    return st.session_state.authenticated


def main() -> None:
    """Run the Streamlit application."""
    ensure_session_defaults()

    if not require_password():
        st.stop()

    st.sidebar.title("AutoDefender")
    if _configured_password() and st.sidebar.button("Sign out"):
        audit.record("console", "sign_out")
        st.session_state.clear()
        st.rerun()
    st.sidebar.markdown("---")

    pages = list(PAGES)
    force_setup_warning = False

    if st.session_state.get("navigation") not in pages:
        st.session_state.navigation = "Setup"

    if (
        not st.session_state.setup_complete
        and st.session_state.navigation in RESTRICTED_BEFORE_SETUP
    ):
        force_setup_warning = True
        st.session_state.navigation = "Setup"

    selected_page = st.sidebar.radio(
        "Navigation",
        pages,
        index=pages.index(st.session_state.navigation),
        key="navigation",
    )

    if (
        not st.session_state.setup_complete
        and selected_page in RESTRICTED_BEFORE_SETUP
    ):
        force_setup_warning = True
        selected_page = "Setup"

    if force_setup_warning:
        st.sidebar.warning("Complete the setup page before using the console.")

    importlib.import_module(f"streamlit_pages.{PAGES[selected_page]}").show()

    st.sidebar.markdown("---")
    st.sidebar.caption("AutoDefender Web Console")
    st.sidebar.caption("Suricata monitoring and analysis")


if __name__ == "__main__":
    main()
