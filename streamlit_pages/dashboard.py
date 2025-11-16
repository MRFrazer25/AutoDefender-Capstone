"""Dashboard page with real-time monitoring and statistics."""

import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from config import Config
from database import Database
from utils.path_utils import sanitize_path


def show() -> None:
    """Display the dashboard."""
    st.markdown(
        '<div class="main-header">Real-Time Security Dashboard</div>',
        unsafe_allow_html=True,
    )

    config = Config.get_default()
    try:
        db_path_value = st.session_state.get("db_path", config.db_path)
        db_path = str(sanitize_path(db_path_value))
    except ValueError as exc:
        st.error(f"Invalid database path: {exc}")
        return
    db = Database(db_path)

    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        log_path = st.text_input(
            "Suricata log path",
            value=st.session_state.get("log_path", config.DEFAULT_SURICATA_LOG_PATH),
            help="Path to the Suricata eve.json log file.",
            placeholder="Example: C:\\Program Files\\Suricata\\log\\eve.json",
        )
        try:
            sanitized_log_path = str(sanitize_path(log_path))
        except ValueError as exc:
            st.error(f"Invalid log path: {exc}")
            sanitized_log_path = log_path
        st.session_state.log_path = sanitized_log_path

    with col2:
        monitoring = st.session_state.get("monitoring", False)
        if not monitoring:
            if st.button("Start monitoring", type="primary", use_container_width=True):
                # Support multiple log paths (newline-separated)
                # Split and sanitize each path individually
                raw_paths = [p.strip() for p in sanitized_log_path.split('\n') if p.strip()]
                sanitized_paths = []
                missing_paths = []
                
                for raw_path in raw_paths:
                    try:
                        sanitized = sanitize_path(raw_path)
                        sanitized_paths.append(str(sanitized))
                        if not sanitized.exists():
                            missing_paths.append(str(sanitized))
                    except ValueError:
                        missing_paths.append(raw_path)
                
                if missing_paths:
                    st.error(f"Log file(s) not found: {', '.join(missing_paths)}")
                else:
                    st.session_state.monitoring = True
                    st.success(f"Monitoring started for {len(sanitized_paths)} source(s).")
                    st.rerun()
        else:
            if st.button("Stop monitoring", type="secondary", use_container_width=True):
                st.session_state.monitoring = False
                st.info("Monitoring stopped.")
                st.rerun()

    with col3:
        auto_refresh = st.checkbox(
            "Auto-refresh",
            value=True,
            help="Refresh the dashboard every two seconds while monitoring.",
        )

    st.markdown("---")

    st.subheader("Current metrics")
    threats = db.get_threats(limit=1000)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for threat in threats:
        if threat.severity in severity_counts:
            severity_counts[threat.severity] += 1

    metric_cols = st.columns(5)
    metric_cols[0].metric("Total threats", len(threats))
    metric_cols[1].metric("Critical", severity_counts["CRITICAL"])
    metric_cols[2].metric("High", severity_counts["HIGH"])
    metric_cols[3].metric("Medium", severity_counts["MEDIUM"])
    metric_cols[4].metric("Low", severity_counts["LOW"])

    st.markdown("---")
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("Severity distribution")
        if threats:
            severity_df = pd.DataFrame(
                {
                    "Severity": list(severity_counts.keys()),
                    "Count": list(severity_counts.values()),
                }
            )
            fig = px.pie(
                severity_df,
                values="Count",
                names="Severity",
                color="Severity",
                color_discrete_map={
                    "CRITICAL": "#d92e2e",
                    "HIGH": "#ff8c3a",
                    "MEDIUM": "#ffd84d",
                    "LOW": "#3a8c3f",
                },
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threats detected yet.")

    with chart_col2:
        st.subheader("Threat timeline")
        if threats:
            threat_times = []
            for threat in threats:
                if threat.timestamp:
                    try:
                        if isinstance(threat.timestamp, str):
                            dt_value = datetime.fromisoformat(
                                threat.timestamp.replace("Z", "+00:00")
                            )
                        else:
                            dt_value = threat.timestamp
                        threat_times.append(dt_value)
                    except ValueError:
                        continue

            if threat_times:
                time_df = pd.DataFrame({"timestamp": threat_times})
                # Ensure timestamp column is datetime type
                if not pd.api.types.is_datetime64_any_dtype(time_df["timestamp"]):
                    time_df["timestamp"] = pd.to_datetime(time_df["timestamp"], errors='coerce')
                # Drop any rows where time conversion failed
                time_df = time_df.dropna(subset=["timestamp"])
                
                if not time_df.empty:
                    time_df["hour"] = time_df["timestamp"].dt.floor("h")
                    time_counts = (
                        time_df.groupby("hour")
                        .size()
                        .reset_index(name="count")
                        .sort_values("hour")
                    )
                    fig = px.line(
                        time_counts,
                        x="hour",
                        y="count",
                        labels={"hour": "Time", "count": "Threats"},
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No valid timestamp data available for timeline.")
            else:
                st.info("Timestamp data is not available.")
        else:
            st.info("No threats detected yet.")

    st.markdown("---")
    st.subheader("Recent threats")

    filter_col1, filter_col2, filter_col3 = st.columns(3)

    with filter_col1:
        severity_filter = st.multiselect(
            "Severity filter",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH"],
        )

    with filter_col2:
        limit = st.selectbox("Rows to display", [10, 25, 50, 100], index=1)

    with filter_col3:
        search_query = st.text_input(
            "Search text",
            placeholder="Example: 192.168.1.10 or SSH scan",
        )

    filtered_threats = threats[:limit]

    if severity_filter:
        filtered_threats = [
            threat for threat in filtered_threats if threat.severity in severity_filter
        ]

    if search_query:
        query = search_query.lower()
        filtered_threats = [
            threat
            for threat in filtered_threats
            if query in threat.description.lower()
            or (threat.source_ip and query in threat.source_ip.lower())
        ]

    if filtered_threats:
        threat_rows = []
        for threat in filtered_threats:
            timestamp_str = ""
            if threat.timestamp:
                try:
                    if isinstance(threat.timestamp, str):
                        display_dt = datetime.fromisoformat(
                            threat.timestamp.replace("Z", "+00:00")
                        )
                    else:
                        display_dt = threat.timestamp
                    timestamp_str = display_dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    timestamp_str = str(threat.timestamp)

            threat_rows.append(
                {
                    "ID": threat.id,
                    "Time": timestamp_str,
                    "Severity": threat.severity,
                    "Source IP": threat.source_ip or "N/A",
                    "Destination IP": threat.dest_ip or "N/A",
                    "Description": (
                        threat.description[:80] + "..."
                        if len(threat.description) > 80
                        else threat.description
                    ),
                    "AI Explanation": (
                        "Ready" if threat.ai_explanation else "Pending"
                    ),
                }
            )

        table_df = pd.DataFrame(threat_rows)
        st.dataframe(table_df, use_container_width=True, height=400)

        st.markdown("### Threat details")
        selected_id = st.selectbox(
            "Threat identifier",
            [row["ID"] for row in threat_rows],
            format_func=lambda value: f"Threat {value}",
        )

        if selected_id:
            threat = db.get_threat(selected_id)
            if threat:
                with st.expander("Threat information", expanded=True):
                    detail_col1, detail_col2 = st.columns(2)

                    with detail_col1:
                        st.markdown(f"**Severity:** `{threat.severity}`")
                        st.markdown(f"**Event type:** `{threat.event_type}`")
                        st.markdown(f"**Source IP:** `{threat.source_ip or 'N/A'}`")
                        st.markdown(f"**Destination IP:** `{threat.dest_ip or 'N/A'}`")
                        if threat.dest_port:
                            st.markdown(f"**Destination port:** `{threat.dest_port}`")

                    with detail_col2:
                        st.markdown(f"**Timestamp:** `{threat.timestamp}`")
                        st.markdown("**Description:**")
                        st.info(threat.description)

                    if threat.ai_explanation:
                        st.markdown("**AI analysis:**")
                        st.success(threat.ai_explanation)
                    else:
                        st.warning("AI explanation is not available yet.")

                    actions = db.get_actions(threat_id=threat.id)
                    if actions:
                        st.markdown("**Recommended actions:**")
                        for action in actions:
                            st.markdown(
                                f"- {action.action_type}: {action.description} "
                                f"(status: {action.status})"
                            )
    else:
        st.info("No threats match the current filters.")

    st.markdown("---")
    st.subheader("Top source IP addresses")

    if threats:
        ip_counts = {}
        for threat in threats:
            if threat.source_ip:
                ip_counts[threat.source_ip] = ip_counts.get(threat.source_ip, 0) + 1

        if ip_counts:
            top_ips = sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[
                :10
            ]
            ip_df = pd.DataFrame(top_ips, columns=["IP Address", "Threat Count"])
            fig = px.bar(
                ip_df,
                x="IP Address",
                y="Threat Count",
                color="Threat Count",
                color_continuous_scale="Reds",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Source IP data is not available.")

    if auto_refresh and st.session_state.get("monitoring", False):
        time.sleep(2)
        st.rerun()

    db.close()

