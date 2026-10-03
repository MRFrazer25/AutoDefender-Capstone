"""Incidents page: related threats grouped by source and time."""

from datetime import timedelta

import pandas as pd
import plotly.express as px
import streamlit as st

from database import Database
from incidents import group_incidents
from mitre import technique_labels
from streamlit_pages.session_config import config_from_session
from utils.display import md_escape

SEVERITY_COLORS = {"CRITICAL": "#d92e2e", "HIGH": "#ff8c3a", "MEDIUM": "#ffd84d", "LOW": "#3a8c3f"}


def show() -> None:
    """Render the incidents page."""
    st.markdown('<div class="main-header">Incidents</div>', unsafe_allow_html=True)
    st.caption(
        "Threats from the same source are grouped into one incident until that source "
        "is quiet for longer than the gap below."
    )

    try:
        db = Database(config_from_session().db_path)
    except ValueError as exc:
        st.error(f"Invalid path in current settings: {exc}")
        return

    col1, col2, col3 = st.columns(3)
    with col1:
        gap_minutes = st.number_input("Gap between incidents (minutes)", min_value=5, max_value=1440, value=60)
    with col2:
        min_severity = st.selectbox("Minimum severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], index=1)
    with col3:
        limit = st.number_input("Threats to load", min_value=100, max_value=20000, value=2000, step=100)

    threats = db.get_threats(limit=int(limit))
    db.close()

    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    incidents = [
        i for i in group_incidents(threats, gap=timedelta(minutes=int(gap_minutes)))
        if order.index(i.severity) >= order.index(min_severity)
    ]

    if not incidents:
        st.info("No incidents match the current filters.")
        return

    metric_cols = st.columns(3)
    metric_cols[0].metric("Incidents", len(incidents))
    metric_cols[1].metric("Critical or high", sum(i.severity in ("CRITICAL", "HIGH") for i in incidents))
    metric_cols[2].metric("Distinct sources", len({i.source_ip for i in incidents}))

    summary = pd.DataFrame([
        {
            "Source IP": i.source_ip,
            "Severity": i.severity,
            "Threats": len(i.threats),
            "Start (UTC)": i.start.strftime("%Y-%m-%d %H:%M:%S"),
            "Duration": str(i.end - i.start).split(".")[0],
            "Tactics": ", ".join(i.tactics) or "-",
        }
        for i in incidents
    ])
    st.dataframe(summary, use_container_width=True, height=300)

    st.markdown("### Incident details")
    for incident in incidents[:50]:
        label = (
            f"{incident.severity} | {md_escape(incident.source_ip)} | "
            f"{len(incident.threats)} threat(s) | {incident.start.strftime('%Y-%m-%d %H:%M')} UTC"
        )
        with st.expander(label):
            if incident.techniques:
                st.markdown("**MITRE ATT&CK:** " + ", ".join(
                    f"[{t['id']}]({t['url']}) {md_escape(t['name'])}" for t in incident.techniques
                ))
            st.markdown("**Event types:** " + md_escape(", ".join(incident.event_types)))

            timeline = pd.DataFrame([
                {
                    "Time (UTC)": t.timestamp,
                    "Severity": t.severity,
                    "Type": t.event_type,
                    "Description": t.description,
                    "ATT&CK": technique_labels(t),
                }
                for t in incident.threats
            ])
            if len(incident.threats) > 1:
                fig = px.scatter(
                    timeline, x="Time (UTC)", y="Type", color="Severity",
                    color_discrete_map=SEVERITY_COLORS, hover_data=["Description"], height=250,
                )
                st.plotly_chart(fig, use_container_width=True, key=f"incident_{incident.key}")
            st.dataframe(timeline, use_container_width=True)

    if len(incidents) > 50:
        st.caption(f"Showing details for the first 50 of {len(incidents)} incidents.")
