"""Action management page for approving or rejecting security actions."""

import pandas as pd
import streamlit as st
from datetime import datetime

from config import Config
from database import Database
from suricata_manager import SuricataManager
from utils.path_utils import sanitize_path


def show() -> None:
    """Display the action management page."""
    st.markdown('<div class="main-header">Action Management</div>', unsafe_allow_html=True)

    config = Config.get_default()
    try:
        db_path_value = st.session_state.get("db_path", config.db_path)
        db_path = str(sanitize_path(db_path_value))
    except ValueError as exc:
        st.error(f"Invalid database path: {exc}")
        return
    db = Database(db_path)

    suricata_enabled = st.session_state.get("suricata_enabled", config.SURICATA_ENABLED)
    config.SURICATA_ENABLED = suricata_enabled
    try:
        config.SURICATA_RULES_DIR = str(
            sanitize_path(st.session_state.get("suricata_rules_dir", config.SURICATA_RULES_DIR))
        )
    except ValueError:
        st.error("Invalid Suricata rules directory configured.")
        config.SURICATA_RULES_DIR = str(sanitize_path(config.SURICATA_RULES_DIR))
    config.SURICATA_DRY_RUN = st.session_state.get(
        "suricata_dry_run", config.SURICATA_DRY_RUN
    )

    if not suricata_enabled:
        st.warning(
            "Suricata integration is disabled. Enable it in Settings or the Setup page to approve rules."
        )

    st.subheader("Filter actions")
    status_filter = st.multiselect(
        "Status values",
        ["RECOMMENDED", "EXECUTED", "REJECTED", "FAILED"],
        default=["RECOMMENDED"],
    )

    actions = db.get_actions(limit=500)
    if status_filter:
        actions = [action for action in actions if action.status in status_filter]

    st.subheader("Summary")
    summary_counts = {
        "RECOMMENDED": 0,
        "EXECUTED": 0,
        "REJECTED": 0,
        "FAILED": 0,
    }
    for action in db.get_actions(limit=5000):
        if action.status in summary_counts:
            summary_counts[action.status] += 1

    metric_cols = st.columns(4)
    metric_cols[0].metric("Recommended", summary_counts["RECOMMENDED"])
    metric_cols[1].metric("Executed", summary_counts["EXECUTED"])
    metric_cols[2].metric("Rejected", summary_counts["REJECTED"])
    metric_cols[3].metric("Failed", summary_counts["FAILED"])

    st.markdown("---")

    if actions:
        st.subheader(f"Pending and recent actions ({len(actions)} records)")
        grouped = {}
        for action in actions:
            if action.threat_id:
                grouped.setdefault(action.threat_id, []).append(action)

        for threat_id, threat_actions in grouped.items():
            threat = db.get_threat(threat_id)
            if not threat:
                continue

            header_text = f"Threat {threat_id}: {threat.description[:120]}"
            with st.expander(header_text, expanded=threat_actions[0].status == "RECOMMENDED"):
                detail_col1, detail_col2 = st.columns(2)
                with detail_col1:
                    st.markdown(f"**Severity:** `{threat.severity}`")
                    st.markdown(f"**Source IP:** `{threat.source_ip or 'N/A'}`")
                    st.markdown(f"**Event type:** `{threat.event_type}`")
                with detail_col2:
                    st.markdown(f"**Timestamp:** `{threat.timestamp}`")
                    st.markdown(f"**Destination:** `{threat.dest_ip or 'N/A'}`")
                    if threat.dest_port:
                        st.markdown(f"**Port:** `{threat.dest_port}`")

                st.markdown("**Description:**")
                st.info(threat.description)

                if threat.ai_explanation:
                    st.markdown("**AI analysis:**")
                    st.success(threat.ai_explanation)

                st.markdown("### Actions for this threat")
                for index, action in enumerate(threat_actions):
                    action_cols = st.columns([3, 1, 1])
                    with action_cols[0]:
                        st.markdown(f"**{action.action_type}** (status: {action.status})")
                        st.text(action.description)
                        if action.executed_at:
                            st.caption(f"Executed at {action.executed_at}")

                    if action.status == "RECOMMENDED" and suricata_enabled and action.action_type == "SURICATA_DROP_RULE":
                        with action_cols[1]:
                            if st.button(
                                "Approve",
                                key=f"approve_{action.id}_{index}",
                            ):
                                try:
                                    manager = SuricataManager(config)
                                    if manager.add_custom_rule(action.description):
                                        db.update_action_status(
                                            action.id,
                                            "EXECUTED",
                                            datetime.now(),
                                        )
                                        st.success("Action approved and executed.")
                                        st.rerun()
                                    else:
                                        db.update_action_status(action.id, "FAILED")
                                        st.error("Failed to apply the Suricata rule.")
                                except Exception as exc:
                                    st.error(f"Rule approval failed: {exc}")
                    else:
                        action_cols[1].write(" ")

                    if action.status == "RECOMMENDED":
                        with action_cols[2]:
                            if st.button(
                                "Reject",
                                key=f"reject_{action.id}_{index}",
                            ):
                                db.update_action_status(action.id, "REJECTED")
                                st.info("Action rejected.")
                                st.rerun()
                    elif action_cols[2]:
                        action_cols[2].write(" ")

                    if index < len(threat_actions) - 1:
                        st.markdown("---")

        recommended_actions = [a for a in actions if a.status == "RECOMMENDED"]
        if recommended_actions:
            st.markdown("---")
            st.subheader("Batch operations")
            batch_col1, batch_col2 = st.columns(2)

            with batch_col1:
                if st.button(
                    "Approve all Suricata rules",
                    disabled=not suricata_enabled,
                ):
                    suricata_candidates = [
                        a
                        for a in recommended_actions
                        if a.action_type == "SURICATA_DROP_RULE"
                    ]
                    if suricata_candidates:
                        try:
                            manager = SuricataManager(config)
                            approved = 0
                            for action in suricata_candidates:
                                if manager.add_custom_rule(action.description):
                                    db.update_action_status(
                                        action.id,
                                        "EXECUTED",
                                        datetime.now(),
                                    )
                                    approved += 1
                                else:
                                    db.update_action_status(action.id, "FAILED")
                            st.success(
                                f"Approved {approved} of {len(suricata_candidates)} Suricata actions."
                            )
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Batch approval failed: {exc}")
                    else:
                        st.info("No Suricata rules are awaiting approval.")

            with batch_col2:
                if st.button("Reject all recommended actions"):
                    for action in recommended_actions:
                        db.update_action_status(action.id, "REJECTED")
                    st.info(f"Rejected {len(recommended_actions)} actions.")
                    st.rerun()
    else:
        st.info("No actions match the selected filters.")

    st.markdown("---")
    st.subheader("Action history (latest 100)")

    history = db.get_actions(limit=100)
    if history:
        history_rows = []
        for action in history:
            timestamp_str = ""
            if action.timestamp:
                try:
                    if isinstance(action.timestamp, str):
                        dt_value = datetime.fromisoformat(action.timestamp.replace("Z", "+00:00"))
                    else:
                        dt_value = action.timestamp
                    timestamp_str = dt_value.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    timestamp_str = str(action.timestamp)

            history_rows.append(
                {
                    "ID": action.id,
                    "Threat ID": action.threat_id or "N/A",
                    "Type": action.action_type,
                    "Status": action.status,
                    "Timestamp": timestamp_str,
                    "Executed": action.executed_at or "N/A",
                    "Description": (action.description[:60] + "...")
                    if len(action.description) > 60
                    else action.description,
                }
            )

        history_df = pd.DataFrame(history_rows)
        st.dataframe(history_df, use_container_width=True, height=400)
    else:
        st.info("No action history is available.")

    db.close()

