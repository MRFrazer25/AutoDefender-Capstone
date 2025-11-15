#!/usr/bin/env python3
"""AutoDefender Streamlit Web UI."""

import os
import logging
import streamlit as st


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


def ensure_session_defaults() -> None:
    """Set up default session state values."""
    defaults = {
        "monitoring": False,
        "monitor_thread": None,
        "log_path": "",
        "setup_complete": False,
        "authenticated": False,
        "checked_password": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def require_password() -> bool:
    """Prompt for password when AUTODEFENDER_UI_PASSWORD is set."""
    password_required = os.getenv(PASSWORD_ENV)
    if not password_required:
        st.session_state.authenticated = True
        return True

    if not st.session_state.checked_password:
        st.session_state.checked_password = True

    if st.session_state.authenticated:
        return True

    st.title("AutoDefender Web Console")
    st.warning("This console is protected. Enter the access password to continue.")
    password_input = st.text_input(
        "Access password",
        type="password",
        placeholder="Enter the password provided by the administrator",
    )
    if st.button("Sign in"):
        if password_input == password_required:
            st.session_state.authenticated = True
            st.success("Access granted.")
        else:
            st.error("Password incorrect. Access denied.")

    return st.session_state.authenticated


def main() -> None:
    """Run the Streamlit application."""
    ensure_session_defaults()

    if not require_password():
        st.stop()

    st.sidebar.title("AutoDefender")
    st.sidebar.markdown("---")

    pages = [
        "Setup",
        "Dashboard",
        "Threat Analysis",
        "Action Management",
        "IP Management",
        "Settings",
        "Documentation",
    ]

    restricted_before_setup = {
        "Dashboard",
        "Threat Analysis",
        "Action Management",
        "IP Management",
    }
    force_setup_warning = False

    if "navigation" not in st.session_state:
        st.session_state.navigation = "Setup"

    if (
        not st.session_state.setup_complete
        and st.session_state.navigation in restricted_before_setup
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
        and selected_page in restricted_before_setup
    ):
        force_setup_warning = True
        selected_page = "Setup"

    if force_setup_warning:
        st.sidebar.warning("Complete the setup page before using the console.")

    if selected_page == "Setup":
        from streamlit_pages import setup

        setup.show()
    elif selected_page == "Dashboard":
        from streamlit_pages import dashboard

        dashboard.show()
    elif selected_page == "Threat Analysis":
        from streamlit_pages import threat_analysis

        threat_analysis.show()
    elif selected_page == "Action Management":
        from streamlit_pages import action_management

        action_management.show()
    elif selected_page == "IP Management":
        from streamlit_pages import ip_management

        ip_management.show()
    elif selected_page == "Settings":
        from streamlit_pages import settings

        settings.show()
    elif selected_page == "Documentation":
        from streamlit_pages import documentation

        documentation.show()

    st.sidebar.markdown("---")
    st.sidebar.caption("AutoDefender Web Console")
    st.sidebar.caption("Suricata monitoring and analysis")


if __name__ == "__main__":
    main()

