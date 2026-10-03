"""Action management page for approving or rejecting security actions."""

import logging
from datetime import datetime
from typing import Optional

import pandas as pd
import streamlit as st

from autodefender.action_engine import MANUAL_ACTIONS
from autodefender.database import Database
from autodefender.ip_manager import IPManager
from autodefender.notifications.webhook import send_webhook
from streamlit_pages.session_config import (
    config_from_session,
    record,
    webhook_url_from_session,
)
from autodefender.mitre import techniques_for
from autodefender.suricata_manager import SuricataManager, build_drop_rule, normalize_block_ip, parse_drop_rule
from autodefender.utils.display import md_escape

logger = logging.getLogger(__name__)

ALREADY_HANDLED = "This action was already handled (maybe in another tab). Refreshing."


def _rule_for_action(action, threat):
    """Return the drop rule to apply for an action, or None if there is no safe rule.

    AI/fallback actions already hold a full rule. Playbook steps hold a plain
    description, so build the rule from the threat's source IP instead.
    """
    if parse_drop_rule(action.description):
        return action.description
    if threat and normalize_block_ip(threat.source_ip):
        return build_drop_rule(threat.source_ip, f"AutoDefender: {threat.description}")
    return None


def _apply_drop_rule(manager, action, threat, db) -> Optional[bool]:
    """Write the action's drop rule and record the result.

    Returns True/False for success/failure, or None if the action was no
    longer pending (already handled elsewhere).
    """
    if not db.transition_action(action.id, "RECOMMENDED", "PROCESSING"):
        return None
    rule = _rule_for_action(action, threat)
    try:
        applied = bool(rule) and manager.add_custom_rule(rule)
    except Exception:
        logger.exception("Error applying drop rule for action %s", action.id)
        applied = False
    if applied:
        db.update_action_status(action.id, "EXECUTED", datetime.now())
    else:
        db.update_action_status(action.id, "FAILED")
    return applied


def _execute_additional_action(action, threat, db):
    """Execute non-Suricata actions such as logging or webhook."""
    now = datetime.now()
    success = False
    message = ""
    if not db.transition_action(action.id, "RECOMMENDED", "PROCESSING"):
        return None, ALREADY_HANDLED

    if action.action_type == "WEBHOOK_NOTIFY":
        payload = {
            "text": action.description,
            "threat": {
                "id": threat.id,
                "severity": threat.severity,
                "source_ip": threat.source_ip,
                "event_type": threat.event_type,
                "description": threat.description,
            },
        }
        
        # Add geographic context if available
        if threat.metadata and "geo_context" in threat.metadata:
            geo = threat.metadata["geo_context"]
            payload["threat"]["location"] = geo.get("location", "Unknown")
            payload["threat"]["isp"] = geo.get("isp", "Unknown")
        webhook_url = webhook_url_from_session()
        if not webhook_url:
            # Put it back so it can be sent once a URL is configured
            db.update_action_status(action.id, "RECOMMENDED")
            return False, "No webhook URL is configured. Add one on the Setup page."
        success = send_webhook(payload, webhook_url)
        message = "Webhook notification sent." if success else "Webhook notification failed. Check the server log."
    elif action.action_type == "LOG":
        success = True
        message = "Log action recorded."
    elif action.action_type in MANUAL_ACTIONS:
        # AutoDefender can't do these itself; record that the operator did
        success = True
        message = "Marked as done. Remember to apply this change in your firewall."
    else:
        success = True
        message = "Action marked as completed."

    db.update_action_status(
        action.id,
        "EXECUTED" if success else "FAILED",
        now if success else None,
    )
    return success, message


def show_active_blocks(config) -> None:
    """List the drop rules AutoDefender wrote, with unblock and reload controls."""
    try:
        manager = SuricataManager(config, ip_manager=IPManager())
        expired = manager.expire_blocks()
        blocks = manager.list_blocks()
    except Exception:
        logger.exception("Could not read the Suricata rules directory")
        st.error("Could not read the Suricata rules directory. Check the server log for details.")
        return
    if expired:
        record("blocks_expired", {"count": expired})

    duration = "permanent" if not config.BLOCK_DURATION_HOURS else f"{config.BLOCK_DURATION_HOURS:g} hours"
    with st.expander(f"Active blocks ({len(blocks)}), new blocks last: {duration}", expanded=False):
        if not blocks:
            st.caption("No drop rules are active.")
        else:
            st.dataframe(pd.DataFrame([
                {
                    "IP": b["ip"],
                    "SID": b["sid"],
                    "Reason": b["msg"],
                    "Blocked at (UTC)": (b["created"] or "unknown")[:19],
                    "Expires (UTC)": (b["expires"] or "never")[:19],
                }
                for b in blocks
            ]), use_container_width=True)
            unblock_col, button_col = st.columns([3, 1])
            with unblock_col:
                ip_to_unblock = st.selectbox("Unblock an IP", [b["ip"] for b in blocks], key="unblock_ip")
            with button_col:
                st.write("")
                if st.button("Unblock", key="unblock_button"):
                    if manager.unblock_ip(ip_to_unblock):
                        record("ip_unblocked", {"ip": ip_to_unblock})
                        st.session_state.rules_changed = True
                        st.success(f"Removed the drop rule for {ip_to_unblock}.")
                        st.rerun()
                    else:
                        st.error("Could not remove the rule (dry-run mode leaves rules unchanged).")

        if manager.needs_restart() or st.session_state.get("rules_changed"):
            st.warning("Rules changed. Suricata needs to reload them before they take effect.")
        if SuricataManager.suricatasc_available():
            if st.button("Reload Suricata rules now", key="reload_rules"):
                ok, message = manager.reload_rules()
                record("rules_reloaded" if ok else "rules_reload_failed", {"message": message})
                if ok:
                    st.session_state.rules_changed = False
                (st.success if ok else st.error)(message)
        else:
            st.caption("Install suricatasc (part of Suricata) to reload rules from here; "
                       "otherwise restart Suricata after rule changes.")


def show() -> None:
    """Display the action management page."""
    st.markdown('<div class="main-header">Action Management</div>', unsafe_allow_html=True)

    try:
        config = config_from_session()
    except ValueError as exc:
        st.error(f"Invalid path in current settings: {exc}")
        return
    db = Database(config.db_path)

    suricata_enabled = config.SURICATA_ENABLED
    if not suricata_enabled:
        st.warning(
            "Suricata integration is disabled. Enable it in Settings or the Setup page to approve rules."
        )
    elif config.SURICATA_DRY_RUN:
        st.info("Dry-run mode is on: approved rules are logged but not written to the rules file.")
    st.caption(
        "BLOCK_IP, RATE_LIMIT, and TERMINATE are manual steps: AutoDefender records them, "
        "you apply them in your firewall."
    )
    if suricata_enabled:
        show_active_blocks(config)

    st.subheader("Filter actions")
    status_filter = st.multiselect(
        "Status values",
        ["RECOMMENDED", "PROCESSING", "EXECUTED", "REJECTED", "FAILED"],
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

            header_text = f"Threat {threat_id}: {md_escape(threat.description[:120])}"
            with st.expander(header_text, expanded=threat_actions[0].status == "RECOMMENDED"):
                detail_col1, detail_col2 = st.columns(2)
                with detail_col1:
                    st.markdown(f"**Severity:** {md_escape(threat.severity)}")
                    st.markdown(f"**Source IP:** {md_escape(threat.source_ip or 'N/A')}")
                    st.markdown(f"**Event type:** {md_escape(threat.event_type)}")
                with detail_col2:
                    st.markdown(f"**Timestamp:** {md_escape(threat.timestamp)}")
                    st.markdown(f"**Destination:** {md_escape(threat.dest_ip or 'N/A')}")
                    if threat.dest_port:
                        st.markdown(f"**Port:** {md_escape(threat.dest_port)}")

                st.markdown("**Description:**")
                st.info(md_escape(threat.description))
                techniques = techniques_for(threat)
                if techniques:
                    st.markdown("**MITRE ATT&CK:** " + ", ".join(
                        f"[{t['id']}]({t['url']}) {md_escape(t['name'])} ({md_escape(t['tactic'])})" for t in techniques
                    ))

                if threat.ai_explanation:
                    st.markdown("**AI analysis:**")
                    st.success(md_escape(threat.ai_explanation))

                st.markdown("### Actions for this threat")
                for index, action in enumerate(threat_actions):
                    action_cols = st.columns([3, 1, 1])
                    with action_cols[0]:
                        st.markdown(f"**{md_escape(action.action_type)}** (status: {md_escape(action.status)})")
                        st.text(action.description)
                        if action.executed_at:
                            st.caption(f"Executed at {action.executed_at}")

                    if action.status == "RECOMMENDED":
                        with action_cols[1]:
                            if action.action_type == "SURICATA_DROP_RULE":
                                if suricata_enabled and st.button(
                                    "Approve",
                                    key=f"approve_{action.id}_{index}",
                                ):
                                    manager = SuricataManager(config, ip_manager=IPManager())
                                    applied = _apply_drop_rule(manager, action, threat, db)
                                    if applied is None:
                                        st.info(ALREADY_HANDLED)
                                        st.rerun()
                                    record("action_approved" if applied else "action_failed", {
                                        "action_id": action.id, "type": action.action_type,
                                        "source_ip": threat.source_ip, "dry_run": config.SURICATA_DRY_RUN,
                                    })
                                    if applied:
                                        st.session_state.rules_changed = not config.SURICATA_DRY_RUN
                                        st.success("Action approved and executed.")
                                        st.rerun()
                                    else:
                                        st.error(
                                            "Failed to apply the Suricata rule. Only single-IP drop rules "
                                            "for non-whitelisted IPs are accepted."
                                        )
                            else:
                                if st.button(
                                    "Mark done" if action.action_type in MANUAL_ACTIONS else "Execute",
                                    key=f"execute_{action.id}_{index}",
                                ):
                                    success, message = _execute_additional_action(action, threat, db)
                                    if success is None:
                                        st.info(message)
                                        st.rerun()
                                    record("action_executed" if success else "action_failed", {
                                        "action_id": action.id, "type": action.action_type,
                                    })
                                    if success:
                                        st.success(message)
                                        st.rerun()
                                    else:
                                        st.error(message or "Action execution failed.")
                    else:
                        action_cols[1].write(" ")

                    if action.status == "RECOMMENDED":
                        with action_cols[2]:
                            if st.button(
                                "Reject",
                                key=f"reject_{action.id}_{index}",
                            ):
                                if db.transition_action(action.id, "RECOMMENDED", "REJECTED"):
                                    record("action_rejected", {"action_id": action.id, "type": action.action_type})
                                    st.info("Action rejected.")
                                else:
                                    st.info(ALREADY_HANDLED)
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
                        manager = SuricataManager(config, ip_manager=IPManager())
                        approved = 0
                        for action in suricata_candidates:
                            if _apply_drop_rule(manager, action, db.get_threat(action.threat_id), db):
                                approved += 1
                        if approved and not config.SURICATA_DRY_RUN:
                            st.session_state.rules_changed = True
                        record("actions_batch_approved", {
                            "approved": approved, "requested": len(suricata_candidates),
                        })
                        st.success(
                            f"Approved {approved} of {len(suricata_candidates)} Suricata actions."
                        )
                        st.rerun()
                    else:
                        st.info("No Suricata rules are awaiting approval.")

            with batch_col2:
                if st.button("Reject all recommended actions"):
                    rejected = sum(
                        db.transition_action(action.id, "RECOMMENDED", "REJECTED") for action in recommended_actions
                    )
                    record("actions_batch_rejected", {"count": rejected})
                    st.info(f"Rejected {rejected} actions.")
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

