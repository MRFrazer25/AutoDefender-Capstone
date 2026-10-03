"""Audit log page: what was done in the console, with a tamper check."""

import pandas as pd
import streamlit as st

from autodefender import audit
def show() -> None:
    """Render the audit log."""
    st.markdown('<div class="main-header">Audit Log</div>', unsafe_allow_html=True)
    st.caption(
        f"Sign-ins, approvals, unblocks, settings and data changes are recorded locally in {audit.audit_db_path()}. "
        "Each entry is hash-chained to the previous one, so edits or deletions are detectable."
    )

    ok, bad_id = audit.verify()
    if ok:
        st.success("Integrity check passed: the log has not been altered.")
    else:
        st.error(f"Integrity check failed at entry {bad_id}: the log was edited or entries were removed.")

    col1, col2 = st.columns(2)
    with col1:
        limit = st.number_input("Entries to show", min_value=50, max_value=10000, value=500, step=50)
    with col2:
        user_filter = st.text_input("Filter by action")

    rows = audit.entries(limit=int(limit))
    if user_filter:
        needle = user_filter.lower()
        rows = [r for r in rows if needle in r["action"].lower() or needle in r["details"].lower()]

    if not rows:
        st.info("No audit entries yet.")
        return

    st.dataframe(
        pd.DataFrame([
            {
                "ID": r["id"],
                "Time (UTC)": r["timestamp"][:19],
                "Source": r["username"],
                "Action": r["action"],
                "Details": r["details"],
            }
            for r in rows
        ]),
        use_container_width=True,
        height=500,
    )
