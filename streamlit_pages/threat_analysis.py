"""Threat analysis page with filtering and export."""

import os
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from config import Config
from database import Database
from exporter import Exporter
from filter import ThreatFilter
from utils.path_utils import sanitize_path, sanitize_filename


def show() -> None:
    """Display the threat analysis view."""
    st.markdown('<div class="main-header">Threat Analysis</div>', unsafe_allow_html=True)

    config = Config.get_default()
    try:
        db_path_value = st.session_state.get("db_path", config.db_path)
        db_path = sanitize_path(db_path_value)
    except ValueError as exc:
        st.error(f"Invalid database path: {exc}")
        return
    db = Database(db_path)
    threat_filter = ThreatFilter()

    st.subheader("Filter options")
    filter_col1, filter_col2, filter_col3 = st.columns(3)

    with filter_col1:
        severities = st.multiselect(
            "Severity levels",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        )

    with filter_col2:
        ai_choice = st.selectbox(
            "AI explanation",
            ["All", "Only with explanation", "Only without explanation"],
        )

    with filter_col3:
        limit = st.number_input(
            "Maximum rows",
            min_value=10,
            max_value=10000,
            value=500,
            step=50,
        )

    date_col1, date_col2 = st.columns(2)
    use_date_filter = False
    start_datetime = None
    end_datetime = None

    with date_col1:
        use_date_filter = st.checkbox("Use date range filter")
        if use_date_filter:
            start_date = st.date_input(
                "Start date",
                value=datetime.now() - timedelta(days=7),
            )
            start_time = st.time_input("Start time", value=datetime.min.time())
            start_datetime = datetime.combine(start_date, start_time)

    with date_col2:
        if use_date_filter:
            end_date = st.date_input("End date", value=datetime.now())
            end_time = st.time_input("End time", value=datetime.max.time())
            end_datetime = datetime.combine(end_date, end_time)

    ip_col1, ip_col2 = st.columns(2)

    with ip_col1:
        source_ip_filter = st.text_input(
            "Source IP contains",
            placeholder="Example: 192.168",
        )

    with ip_col2:
        dest_ip_filter = st.text_input(
            "Destination IP contains",
            placeholder="Example: 10.0.0.5",
        )

    search_query = st.text_input(
        "Search in description or explanation",
        placeholder="Example: brute force or 203.0.113",
    )

    st.markdown("---")

    threats = db.get_threats(limit=int(limit))

    if severities:
        threats = threat_filter.filter_by_severity_list(threats, severities)

    if ai_choice == "Only with explanation":
        threats = threat_filter.filter_threats(threats, has_ai_explanation=True)
    elif ai_choice == "Only without explanation":
        threats = threat_filter.filter_threats(threats, has_ai_explanation=False)

    if use_date_filter and start_datetime and end_datetime:
        threats = threat_filter.filter_threats(
            threats,
            start_time=start_datetime,
            end_time=end_datetime,
        )

    if source_ip_filter:
        threats = threat_filter.filter_threats(
            threats,
            source_ip=source_ip_filter,
        )

    if dest_ip_filter:
        threats = threat_filter.filter_threats(
            threats,
            dest_ip=dest_ip_filter,
        )

    if search_query:
        threats = threat_filter.search_threats(threats, search_query)

    st.subheader(f"Analysis results ({len(threats)} threats)")

    if threats:
        stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for threat in threats:
            if threat.severity in severity_counts:
                severity_counts[threat.severity] += 1

        stat_col1.metric("Critical", severity_counts["CRITICAL"])
        stat_col2.metric("High", severity_counts["HIGH"])
        stat_col3.metric("Medium", severity_counts["MEDIUM"])
        stat_col4.metric("Low", severity_counts["LOW"])

        tab1, tab2, tab3 = st.tabs(["Table view", "Charts", "IP analysis"])

        with tab1:
            table_rows = []
            for threat in threats:
                timestamp_str = ""
                if threat.timestamp:
                    try:
                        if isinstance(threat.timestamp, str):
                            dt_value = datetime.fromisoformat(
                                threat.timestamp.replace("Z", "+00:00")
                            )
                        else:
                            dt_value = threat.timestamp
                        timestamp_str = dt_value.strftime("%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        timestamp_str = str(threat.timestamp)

                table_rows.append(
                    {
                        "ID": threat.id,
                        "Timestamp": timestamp_str,
                        "Severity": threat.severity,
                        "Event type": threat.event_type,
                        "Source IP": threat.source_ip or "N/A",
                        "Destination IP": threat.dest_ip or "N/A",
                        "Port": threat.dest_port if threat.dest_port else "N/A",
                        "Description": threat.description,
                        "AI explanation": "Available"
                        if threat.ai_explanation
                        else "Missing",
                    }
                )

            display_df = pd.DataFrame(table_rows)
            st.dataframe(display_df, use_container_width=True, height=500)

            st.markdown("### Export data")
            export_col1, export_col2 = st.columns(2)

            with export_col1:
                export_format = st.selectbox("Format", ["JSON", "CSV"])

            with export_col2:
                export_filename = st.text_input(
                    "File name",
                    value=f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    placeholder="Example: threats_export",
                )

            if st.button("Export"):
                exporter = Exporter(db)
                safe_name = sanitize_filename(export_filename) or sanitize_filename(
                    f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                )
                filename = f"{safe_name}.{export_format.lower()}"
                try:
                    if export_format == "CSV":
                        success = exporter.export_threats_csv(threats, filename)
                    else:
                        success = exporter.export_threats_json(threats, filename)

                    if success:
                        # Get the actual path from exporter for download
                        from exporter import EXPORTS_DIR
                        safe_export_path = os.path.join(EXPORTS_DIR, filename)
                        # Validate path is within exports directory
                        exports_dir_normalized = os.path.abspath(os.path.normpath(EXPORTS_DIR))
                        safe_export_path_normalized = os.path.abspath(os.path.normpath(safe_export_path))
                        if not safe_export_path_normalized.startswith(exports_dir_normalized + os.sep):
                            st.error("Export path validation failed")
                            return
                        st.success(
                            f"Exported {len(threats)} threats to {filename}."
                        )
                        with open(safe_export_path_normalized, "r", encoding="utf-8") as handle:
                            st.download_button(
                                label=f"Download {export_format}",
                                data=handle.read(),
                                file_name=os.path.basename(safe_export_path),
                                mime=(
                                    "application/json"
                                    if export_format == "JSON"
                                    else "text/csv"
                                ),
                            )
                    else:
                        st.error("Export failed.")
                except Exception as exc:
                    st.error(f"Export error: {exc}")

        with tab2:
            chart_col1, chart_col2 = st.columns(2)

            with chart_col1:
                st.markdown("#### Threats by type")
                type_counts = {}
                for threat in threats:
                    type_counts[threat.event_type] = type_counts.get(threat.event_type, 0) + 1
                type_df = pd.DataFrame(
                    list(type_counts.items()),
                    columns=["Type", "Count"],
                )
                fig = px.bar(type_df, x="Type", y="Count", color="Count")
                st.plotly_chart(fig, use_container_width=True)

            with chart_col2:
                st.markdown("#### Threats by severity")
                severity_df = pd.DataFrame(
                    list(severity_counts.items()),
                    columns=["Severity", "Count"],
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

            st.markdown("#### Timeline")
            timeline_rows = []
            for threat in threats:
                if threat.timestamp:
                    try:
                        if isinstance(threat.timestamp, str):
                            dt_value = datetime.fromisoformat(
                                threat.timestamp.replace("Z", "+00:00")
                            )
                        else:
                            dt_value = threat.timestamp
                        timeline_rows.append(
                            {"time": dt_value, "severity": threat.severity}
                        )
                    except ValueError:
                        continue

            if timeline_rows:
                timeline_df = pd.DataFrame(timeline_rows)
                # Ensure time column is datetime type
                if not pd.api.types.is_datetime64_any_dtype(timeline_df["time"]):
                    timeline_df["time"] = pd.to_datetime(timeline_df["time"], errors='coerce')
                # Drop any rows where time conversion failed
                timeline_df = timeline_df.dropna(subset=["time"])
                
                if not timeline_df.empty:
                    timeline_df["hour"] = timeline_df["time"].dt.floor("h")
                    timeline_counts = (
                        timeline_df.groupby(["hour", "severity"])
                        .size()
                        .reset_index(name="count")
                    )
                else:
                    timeline_counts = pd.DataFrame(columns=["hour", "severity", "count"])
                
                if not timeline_counts.empty:
                    fig = px.bar(
                        timeline_counts,
                        x="hour",
                        y="count",
                        color="severity",
                        labels={"hour": "Time", "count": "Threats"},
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No timeline data available for the selected threats.")
            else:
                st.info("Timeline data is not available.")

        with tab3:
            st.markdown("#### Top source IP addresses")
            source_stats = {}
            for threat in threats:
                if threat.source_ip:
                    if threat.source_ip not in source_stats:
                        source_stats[threat.source_ip] = {
                            "count": 0,
                            "severities": {},
                        }
                    source_stats[threat.source_ip]["count"] += 1
                    severity = threat.severity
                    bucket = source_stats[threat.source_ip]["severities"]
                    bucket[severity] = bucket.get(severity, 0) + 1

            if source_stats:
                top_sources = sorted(
                    source_stats.items(),
                    key=lambda item: item[1]["count"],
                    reverse=True,
                )[:20]
                source_rows = []
                for ip_value, data in top_sources:
                    source_rows.append(
                        {
                            "IP Address": ip_value,
                            "Total": data["count"],
                            "Critical": data["severities"].get("CRITICAL", 0),
                            "High": data["severities"].get("HIGH", 0),
                            "Medium": data["severities"].get("MEDIUM", 0),
                            "Low": data["severities"].get("LOW", 0),
                        }
                    )
                source_df = pd.DataFrame(source_rows)
                st.dataframe(source_df, use_container_width=True)

                fig = px.bar(
                    source_df,
                    x="IP Address",
                    y="Total",
                    color="Total",
                    color_continuous_scale="Reds",
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Source IP data is not available.")

            st.markdown("#### Top destination IP addresses")
            dest_counts = {}
            for threat in threats:
                if threat.dest_ip:
                    dest_counts[threat.dest_ip] = dest_counts.get(threat.dest_ip, 0) + 1

            if dest_counts:
                top_dest = sorted(
                    dest_counts.items(),
                    key=lambda item: item[1],
                    reverse=True,
                )[:20]
                dest_df = pd.DataFrame(top_dest, columns=["IP Address", "Threat Count"])
                st.dataframe(dest_df, use_container_width=True)
            else:
                st.info("Destination IP data is not available.")
    else:
        st.info("No threats match the current filters.")

    db.close()

