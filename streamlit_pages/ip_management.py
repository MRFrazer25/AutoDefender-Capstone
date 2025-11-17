"""IP whitelist and blacklist management page."""

import pandas as pd
import streamlit as st
import re

from config import Config
from database import Database
from ip_manager import IPManager
from utils.path_utils import sanitize_path


def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(part) <= 255 for part in parts)


def show() -> None:
    """Render the IP management page."""
    st.markdown('<div class="main-header">IP Address Management</div>', unsafe_allow_html=True)
    st.write(
        "Manage trusted and blocked IP addresses. Whitelisted IPs are ignored by the "
        "detector. Blacklisted IPs generate high-priority alerts."
    )

    ip_manager = IPManager()
    config = Config.get_default()
    try:
        db_path_value = st.session_state.get("db_path", config.db_path)
        db_path = sanitize_path(db_path_value)
    except ValueError as exc:
        st.error(f"Invalid database path: {exc}")
        return
    db = Database(db_path)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Whitelist")
        st.caption("IPs that should be ignored during threat detection.")

        with st.form("add_whitelist"):
            new_ip = st.text_input(
                "Add an IP to the whitelist",
                placeholder="Example: 192.168.1.100",
            )
            submitted = st.form_submit_button("Add to whitelist")
            if submitted:
                if not new_ip:
                    st.error("Enter an IP address before submitting.")
                elif not is_valid_ip(new_ip):
                    st.error("The IP address format is invalid.")
                elif ip_manager.add_whitelist(new_ip):
                    st.success(f"Added {new_ip} to the whitelist.")
                    st.rerun()
                else:
                    st.warning(f"{new_ip} is already whitelisted.")

        whitelist = ip_manager.get_whitelist()
        if whitelist:
            st.markdown(f"Whitelisted IPs ({len(whitelist)} total):")
            for ip_value in whitelist:
                row_col1, row_col2 = st.columns([3, 1])
                with row_col1:
                    threat_count = len(db.get_threats(limit=10000, source_ip=ip_value))
                    st.text(f"{ip_value} (would ignore {threat_count} threats)")
                with row_col2:
                    if st.button("Remove", key=f"remove_whitelist_{ip_value}"):
                        ip_manager.remove_whitelist(ip_value)
                        st.success(f"Removed {ip_value} from the whitelist.")
                        st.rerun()
        else:
            st.info("No IP addresses are whitelisted.")

    with col2:
        st.subheader("Blacklist")
        st.caption("IPs that should trigger high-priority alerts.")

        with st.form("add_blacklist"):
            new_ip = st.text_input(
                "Add an IP to the blacklist",
                placeholder="Example: 203.0.113.50",
            )
            submitted = st.form_submit_button("Add to blacklist")
            if submitted:
                if not new_ip:
                    st.error("Enter an IP address before submitting.")
                elif not is_valid_ip(new_ip):
                    st.error("The IP address format is invalid.")
                elif ip_manager.add_blacklist(new_ip):
                    st.success(f"Added {new_ip} to the blacklist.")
                    st.rerun()
                else:
                    st.warning(f"{new_ip} is already blacklisted.")

        blacklist = ip_manager.get_blacklist()
        if blacklist:
            st.markdown(f"Blacklisted IPs ({len(blacklist)} total):")
            for ip_value in blacklist:
                row_col1, row_col2 = st.columns([3, 1])
                with row_col1:
                    threat_count = len(db.get_threats(limit=10000, source_ip=ip_value))
                    st.text(f"{ip_value} (generated {threat_count} threats)")
                with row_col2:
                    if st.button("Remove ", key=f"remove_blacklist_{ip_value}"):
                        ip_manager.remove_blacklist(ip_value)
                        st.success(f"Removed {ip_value} from the blacklist.")
                        st.rerun()
        else:
            st.info("No IP addresses are blacklisted.")

    st.markdown("---")
    st.subheader("Bulk operations")
    bulk_col1, bulk_col2 = st.columns(2)

    with bulk_col1:
        st.markdown("#### Import from text")
        destination = st.selectbox("Import to", ["Whitelist", "Blacklist"])
        ip_text = st.text_area(
            "Enter IP addresses (one per line)",
            placeholder="192.168.1.100\n192.168.1.101\n192.168.1.102",
            height=150,
        )
        if st.button("Import addresses"):
            if not ip_text:
                st.error("Enter at least one IP address.")
            else:
                ip_list = [value.strip() for value in ip_text.splitlines() if value.strip()]
                valid = [ip for ip in ip_list if is_valid_ip(ip)]
                invalid = [ip for ip in ip_list if not is_valid_ip(ip)]

                if invalid:
                    st.warning(
                        "Skipped the following invalid IPs: " + ", ".join(invalid)
                    )

                added = 0
                for ip in valid:
                    if destination == "Whitelist":
                        if ip_manager.add_whitelist(ip):
                            added += 1
                    else:
                        if ip_manager.add_blacklist(ip):
                            added += 1

                st.success(f"Imported {added} IP addresses into the {destination.lower()}.")
                st.rerun()

    with bulk_col2:
        st.markdown("#### Export lists")
        export_choice = st.selectbox("Select list", ["Whitelist", "Blacklist", "Both"])
        if st.button("Export to text"):
            if export_choice in ("Whitelist", "Both"):
                whitelist_text = "\n".join(ip_manager.get_whitelist())
                if whitelist_text:
                    st.download_button(
                        "Download whitelist",
                        whitelist_text,
                        file_name="whitelist.txt",
                        mime="text/plain",
                    )
            if export_choice in ("Blacklist", "Both"):
                blacklist_text = "\n".join(ip_manager.get_blacklist())
                if blacklist_text:
                    st.download_button(
                        "Download blacklist",
                        blacklist_text,
                        file_name="blacklist.txt",
                        mime="text/plain",
                    )

    st.markdown("---")
    st.subheader("IP analysis")

    all_threats = db.get_threats(limit=10000)
    ip_stats = {}
    for threat in all_threats:
        if not threat.source_ip:
            continue
        if threat.source_ip not in ip_stats:
            ip_stats[threat.source_ip] = {
                "count": 0,
                "severities": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "whitelisted": ip_manager.is_whitelisted(threat.source_ip),
                "blacklisted": ip_manager.is_blacklisted(threat.source_ip),
            }
        ip_stats[threat.source_ip]["count"] += 1
        if threat.severity in ip_stats[threat.source_ip]["severities"]:
            ip_stats[threat.source_ip]["severities"][threat.severity] += 1

    if ip_stats:
        top_ips = sorted(ip_stats.items(), key=lambda item: item[1]["count"], reverse=True)[
            :50
        ]
        table_rows = []
        for ip_value, stats in top_ips:
            if stats["whitelisted"]:
                status = "Whitelisted"
            elif stats["blacklisted"]:
                status = "Blacklisted"
            else:
                status = "Unmanaged"
            table_rows.append(
                {
                    "IP Address": ip_value,
                    "Status": status,
                    "Total threats": stats["count"],
                    "Critical": stats["severities"]["CRITICAL"],
                    "High": stats["severities"]["HIGH"],
                    "Medium": stats["severities"]["MEDIUM"],
                    "Low": stats["severities"]["LOW"],
                }
            )

        df = pd.DataFrame(table_rows)
        st.dataframe(df, use_container_width=True, height=400)

        st.markdown("#### Quick actions")
        st.caption("Select an IP from the table to modify lists.")
        quick_col1, quick_col2 = st.columns(2)

        with quick_col1:
            selected_ip = st.selectbox(
                "Choose an IP",
                [row["IP Address"] for row in table_rows],
            )

        with quick_col2:
            col_whitelist, col_blacklist = st.columns(2)
            with col_whitelist:
                if st.button("Add to whitelist", use_container_width=True):
                    if ip_manager.add_whitelist(selected_ip):
                        st.success(f"Added {selected_ip} to the whitelist.")
                        st.rerun()
                    else:
                        st.warning("Already on the whitelist.")
            with col_blacklist:
                if st.button("Add to blacklist", use_container_width=True):
                    if ip_manager.add_blacklist(selected_ip):
                        st.success(f"Added {selected_ip} to the blacklist.")
                        st.rerun()
                    else:
                        st.warning("Already on the blacklist.")
    else:
        st.info("No IP statistics are available yet.")

    st.markdown("---")
    st.info(
        "Security note: whitelist only IPs you trust completely. Blacklisting marks an IP "
        "as suspicious but does not block traffic on its own. Always back up your lists "
        "before large changes."
    )

    db.close()

