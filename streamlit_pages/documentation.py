"""Documentation page with help and guides."""

import streamlit as st


def show() -> None:
    """Display the documentation page."""
    st.markdown('<div class="main-header">Documentation</div>', unsafe_allow_html=True)

    doc_section = st.selectbox(
        "Select a topic",
        [
            "Quick start",
            "Dashboard guide",
            "Threat analysis",
            "Action management",
            "IP management",
            "Configuration",
            "AI features",
            "Suricata integration",
            "Security best practices",
        ],
    )

    st.markdown("---")

    if doc_section == "Quick start":
        st.markdown(
            """
            ### Quick start guide

            1. **Install prerequisites**: Suricata, Ollama, and Python dependencies.
            2. **Launch the web console**: `streamlit run streamlit_app.py`
            3. **Complete the Setup page**: Provide log path, database path, and Ollama details.
            4. **Start monitoring**: Use the Dashboard page once setup is complete.
            5. **Explore other pages**: Analyze threats, manage actions, and maintain IP lists.
            """
        )

    elif doc_section == "Dashboard guide":
        st.markdown(
            """
            ### Dashboard overview

            - **Metrics** show total threats and severity distribution.
            - **Charts** include severity distribution, timeline, and top source IPs.
            - **Recent threats** lists the most recent events with filtering and search.
            - Use the log path input to start and stop real-time monitoring.
            - Enable auto-refresh to update the view every few seconds.
            """
        )

    elif doc_section == "Threat analysis":
        st.markdown(
            """
            ### Threat analysis features

            - Filter by severity, date range, source or destination IP, and AI explanation status.
            - Use the search box for free-text queries (description and explanation fields).
            - View results in table, chart, or IP analysis tabs.
            - Export filtered results to CSV or JSON with the export controls.
            """
        )

    elif doc_section == "Action management":
        st.markdown(
            """
            ### Action management

            - Review AI-recommended actions for each threat.
            - Approve or reject individual Suricata drop rules.
            - Use batch operations to approve or reject multiple actions at once.
            - Review the action history table to see previous decisions.
            - Suricata integration must be enabled to apply rules directly.
            """
        )

    elif doc_section == "IP management":
        st.markdown(
            """
            ### IP management

            - **Whitelist** trusted IPs to ignore their activity.
            - **Blacklist** known malicious IPs to flag them with higher priority.
            - Import or export IP lists in bulk using the text-based tools.
            - Review IP statistics to identify frequent sources and destinations.
            - Quick actions allow moving IPs between lists directly from the analysis table.
            """
        )

    elif doc_section == "Configuration":
        st.markdown(
            """
            ### Configuration guidance

            - Use the Settings page to adjust log paths, thresholds, and UI options.
            - Configure Ollama endpoint and model names, then test connectivity.
            - Enable Suricata integration only after verifying backups and rule paths.
            - Database tools allow exporting backups and clearing data when needed.
            - Persist settings through environment variables or a config.ini file.
            """
        )

    elif doc_section == "AI features":
        st.markdown(
            """
            ### AI features overview

            - Ollama provides local language models for explanations and rule suggestions.
            - Smaller models such as phi4-mini work well for interactive use.
            - Configure which severity levels should receive AI explanations.
            - Keep Ollama on a trusted network segment and monitor resource usage.
            - No threat data is sent to external services when using local models.
            """
        )

    elif doc_section == "Suricata integration":
        st.markdown(
            """
            ### Suricata integration details

            - AutoDefender can write custom Suricata rules after manual approval.
            - Enable integration in Settings and provide a writable rules directory.
            - Use dry-run mode while testing to avoid changing production rules.
            - Always back up existing rule files before approving new rules.
            - Reload Suricata after applying new rules to activate changes.
            """
        )

    elif doc_section == "Security best practices":
        st.markdown(
            """
            ### Security best practices

            - Run the web console behind authentication (VPN, reverse proxy, or password).
            - Set the AUTODEFENDER_UI_PASSWORD environment variable for built-in access control.
            - Keep database and rule directories backed up and access controlled.
            - Review whitelists and blacklists regularly to avoid stale entries.
            - Use dry-run mode and manual approvals for Suricata rule changes in production.
            - Monitor application logs and audit who approves or rejects actions.
            """
        )

    st.markdown("---")
    st.info(
        "Additional documentation is available in the README.md, STREAMLIT_UI_GUIDE.md, "
        "and TESTING_WITH_SURICATA.md files within the project directory."
    )

