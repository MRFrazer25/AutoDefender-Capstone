"""Documentation page with help and guides."""

import streamlit as st

SECTIONS = {
    "Quick start": """
### Quick start guide

1. **Install prerequisites**: Suricata, Ollama, and the Python dependencies (`pip install -r requirements.txt`).
2. **Launch the web console**: set `AUTODEFENDER_UI_PASSWORD` (12+ characters), then run `streamlit run streamlit_app.py`.
3. **Complete the Setup page**: log path(s), database path, and Ollama details. Or click **Load demo configuration**.
4. **Start monitoring**: on the Dashboard, click **Start monitoring**.
5. **Investigate**: use Incidents and Threat Analysis, then approve or reject actions in Action Management.
""",
    "Dashboard guide": """
### Dashboard overview

- Enter one or more log paths (one per line) and click **Start monitoring**. Monitoring runs in the
  background and keeps going while you use other pages.
- Tick **Process existing entries** to analyze a whole log file instead of only new lines.
- **Metrics**, the severity chart, the timeline, and top source IPs update while monitoring.
- **Recent threats** can be filtered by severity and searched; pick a threat to see its details,
  MITRE ATT&CK techniques, AI explanation, and recommended actions.
""",
    "Incidents": """
### Incidents

- Threats from the same source are grouped into one incident until that source is quiet for longer
  than the gap you choose (default 60 minutes).
- Each incident shows its highest severity, duration, ATT&CK tactics, and a timeline of its threats.
- Use this page to answer "what is this attacker doing?" instead of reading alerts one by one.
""",
    "Threat analysis": """
### Threat analysis features

- Filter by severity, date range, source or destination IP, and AI explanation status.
- Search descriptions, AI explanations, source IPs, and event types.
- View results in table, chart, or IP analysis tabs. The table includes MITRE ATT&CK techniques.
- Download the filtered results as CSV or JSON. Exports are built in memory and not stored on the server.
""",
    "Action management": """
### Action management

- Review recommended actions for each threat and approve or reject them.
- `SURICATA_DROP_RULE` writes a drop rule for the threat's source IP (one IP per rule, never `any`,
  never a whitelisted IP).
- `BLOCK_IP`, `RATE_LIMIT`, and `TERMINATE` are manual steps: mark them done after you apply them in your firewall.
- **Active blocks** lists every drop rule AutoDefender wrote. You can unblock an IP there, and reload
  Suricata's rules if `suricatasc` is installed.
- Batch buttons approve or reject many actions at once.
""",
    "IP management": """
### IP management

- **Whitelist** trusted IPs: detection ignores them and they are never blocked.
- **Blacklist** known malicious IPs: their traffic raises HIGH alerts (it is not blocked automatically).
- Import or export IP lists in bulk, and add IPs straight from the IP analysis table.
""",
    "Configuration": """
### Configuration guidance

- **Setup**: log paths, database, Ollama endpoint and model, webhook, and Suricata basics.
- **Settings**: detection thresholds, dashboard refresh, AI connection test, Suricata options
  (dry run, block duration, automatic reload), and database backup, retention, and clearing.
- Settings apply to your browser session. Persist them with environment variables or a config.ini file (CLI).
- Paths must be inside the project folder or Suricata's default log folders; add other folders
  with `AUTODEFENDER_ALLOWED_DIRS`.
""",
    "AI features": """
### AI features overview

- Ollama runs the language model locally; threat data is never sent to an online AI service.
- HIGH and CRITICAL threats get AI explanations; others get a built-in explanation (the CLI's
  `--ai-severities` flag changes this for historical analysis).
- AI-suggested drop rules are only accepted if they block exactly the threat's own source IP.
- Log data is marked as untrusted in prompts, and AI output is shown as plain text, never as links or HTML.
- Smaller models such as phi4-mini work well for interactive use.
""",
    "Suricata integration": """
### Suricata integration details

- Enable integration in Settings and choose a rules directory, then include
  `autodefender_custom.rules` in your `suricata.yaml`.
- Use dry-run mode while testing: approved rules are logged but not written.
- A backup of the rules file is taken before every change (the 10 most recent are kept).
- Drop rules only block traffic when Suricata runs inline (IPS mode); in IDS mode they only alert.
- Reload Suricata after rule changes, using the reload button or `SURICATA_AUTO_RELOAD=true`.
""",
    "Audit log": """
### Audit log

- Sign-ins, failed sign-ins, lockouts, approvals, rejections, unblocks, IP list edits, exports,
  settings changes, and data deletion are recorded locally in `audit.db`.
- Each entry is chained to the previous one with a hash, so the Audit Log page can tell you if an
  entry was edited or deleted.
- Clearing threat data never clears the audit log.
""",
    "Security best practices": """
### Security best practices

- Keep the console on localhost, or put it behind a reverse proxy with HTTPS if others need it.
- Use a long, unique `AUTODEFENDER_UI_PASSWORD`. The console will not start without one.
- Review whitelists and blacklists regularly to avoid stale entries.
- Set a block duration (Settings -> Suricata) so old blocks expire; IP addresses get reassigned over time.
- Keep dry-run mode and manual approvals on until you trust the setup.
- Check the Audit Log page now and then.
- Use data retention (Settings -> Database) to keep only the threat history you need.
""",
}


def show() -> None:
    """Display the documentation page."""
    st.markdown('<div class="main-header">Documentation</div>', unsafe_allow_html=True)

    doc_section = st.selectbox("Select a topic", list(SECTIONS))
    st.markdown("---")
    st.markdown(SECTIONS[doc_section])
    st.markdown("---")
    st.info(
        "More documentation is in README.md and the docs/ folder "
        "(SURICATA_SETUP.md and AGENTIC_GUIDE.md) in the project directory."
    )
