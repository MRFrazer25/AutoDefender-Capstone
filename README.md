# AutoDefender

An AI-powered security tool that monitors Suricata network logs in real-time and analyzes historical log files to detect threats, provide AI-generated explanations, and recommend security actions.

**Try it online**: [https://autodefender.streamlit.app/](https://autodefender.streamlit.app/)

## About This Project

AutoDefender started as my senior year college capstone project in fall 2025. I still maintain it and update it from time to time with security fixes, more realistic detection, and new features.

## Features

- **Real-time Monitoring**: Watches Suricata `eve.json` log files and processes events as they occur
- **Multi-Source Aggregation**: Monitor multiple Suricata instances or log sources simultaneously
- **Historical Analysis**: Batch processes existing Suricata log files for threat detection
- **AI-Powered Detection**: Uses Ollama to analyze threats and provide plain English explanations
- **GeoIP Enrichment**: Optional offline geographic context for external IPs from local MaxMind GeoLite2 files (nothing is sent to a third party)
- **MITRE ATT&CK Mapping**: Threats are tagged with ATT&CK techniques (e.g. T1046 Network Service Discovery, T1110 Brute Force) in the UI, exports, and AI prompts
- **Incidents**: Related threats from the same source are grouped into incidents with a timeline
- **Audit Log**: A local, tamper-evident record of sign-ins, approvals, unblocks, and settings changes
- **Block Management**: See active blocks, unblock IPs, set an optional block duration, and reload Suricata rules without a restart
- **Docker**: One command starts AutoDefender, Ollama, and a demo log feed
- **Threat Detection**: Identifies port scans, unusual traffic patterns, and suspicious activity
- **Action Recommendations**: Suggests security actions based on threat severity
- **Dual Interface**: Choose between Terminal UI (Rich-based TUI) or Web UI (Streamlit)
- **Web Dashboard**: Modern, intuitive web interface with real-time monitoring, interactive charts, and action management
- **Playbook Editor**: Create and customize response workflows directly from the browser
- **Database Storage**: SQLite database for threats and actions
- **Threat Filtering**: Filter threats by severity, type, IP address, or date range
- **Search Functionality**: Search threats by description, IP, or event type
- **Export Capabilities**: Export threats (with MITRE ATT&CK tags) to CSV or JSON
- **IP Management**: Whitelist trusted IPs (ignored by detection) and blacklist known malicious IPs (their traffic raises HIGH alerts)
- **Configurable AI Analysis**: Choose which threat severities to analyze with AI
- **Agentic Suricata Integration**: AI-driven automatic Suricata rule generation with permission prompts and safety controls
- **Action Playbooks**: Group multiple response steps (rule + log + webhook) into single approval prompts
- **Webhook Notifications**: Optional Slack/Teams integration for approved threats (opt-in, privacy-first)
- **Interactive Approvals**: Real-time CLI prompts for reviewing and approving AI-generated rules

## Running with Docker

The quickest way to try everything (AutoDefender, a local Ollama, and a replayer that feeds the sample Suricata log):

```bash
cp .env.example .env        # then set AUTODEFENDER_UI_PASSWORD in .env
docker compose up -d --build
docker compose exec ollama ollama pull <model>   # optional; then set OLLAMA_MODEL=<model> in .env
```

Open http://localhost:8501, sign in, and start monitoring `/var/log/suricata/eve.json` on the Dashboard. Data (database, audit log, rules) is kept in the `autodefender-data` volume. The console is published on `127.0.0.1` only and Ollama is not exposed at all.

To watch a real Suricata on a Linux host, remove the `replayer` service and mount the host's log folder read-only on the `autodefender` service: `- /var/log/suricata:/var/log/suricata:ro`. (Docker Desktop on Windows/macOS can't capture host network traffic, so run Suricata itself outside Docker there.)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/MRFrazer25/AutoDefender-Capstone.git
cd AutoDefender-Capstone
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure Ollama is installed and running locally:
```bash
# Install Ollama from https://ollama.ai
ollama pull <model>  # any model you like
ollama serve  # Start Ollama server
```

**Note:** On first run, AutoDefender will automatically create:
- `autodefender.db` - SQLite database for threats and actions (user-specific, not in repository)
- `ip_lists.json` - IP whitelist/blacklist (starts empty, user-specific, not in repository)
- `suricata_rules/` - Custom Suricata rules directory

The demo database (`demo/demo_config.db`) is pre-populated and included in the repository - no setup needed to use it.

## Step-by-Step Setup (Non-Technical Friendly)

1. **Install the prerequisites**
   - [Python 3.10+](https://www.python.org/downloads/)
   - [Git](https://git-scm.com/downloads)
   - [Suricata IDS](https://docs.suricata.io/en/latest/install.html) (follow the installer for your platform or use `docs/SURICATA_SETUP.md`)
   - [Ollama](https://ollama.ai/download) for local AI models
   - Optional: Slack/MS Teams (or any webhook endpoint) if you want automated notifications (Microsoft Teams incoming webhooks work the same way as Slack)
   - Optional: Slack/MS Teams (or any webhook endpoint) if you want automated notifications

2. **Prepare Suricata**
   - Enable the `eve.json` output in `suricata.yaml` (already enabled by default)
   - Start Suricata on the interface you want to monitor:  
     `suricata -c suricata.yaml -i <interface>`
   - Official docs: [https://docs.suricata.io/](https://docs.suricata.io/)  
     Windows quick start: `docs/SURICATA_SETUP.md`

3. **Start Ollama**
   ```bash
   ollama serve
   ollama pull <model>   # optional: any model you like
   ```

4. **Clone AutoDefender and install Python requirements**
   ```bash
   git clone https://github.com/MRFrazer25/AutoDefender-Capstone.git
   cd AutoDefender-Capstone
   pip install -r requirements.txt
   ```

5. **Choose how you want to run AutoDefender**
   - **Streamlit UI (recommended for most people)**:  
     Set a console password (12+ characters) first, then start the UI:  
     PowerShell: `$env:AUTODEFENDER_UI_PASSWORD = "choose-a-long-password"`  
     macOS/Linux: `export AUTODEFENDER_UI_PASSWORD="choose-a-long-password"`  
     `python -m streamlit run streamlit_app.py`
     1. The browser opens at `http://localhost:8501`
     2. Go to the **Setup** page and fill in:
        - *Suricata eve.json path(s)*: the full path to `eve.json` (or multiple paths, one per line for aggregation)
        - *Database path*: leave default `autodefender.db` or point somewhere else
        - *Ollama endpoint*: `http://127.0.0.1:11434`
        - *Ollama model* (optional): the model you pulled; leave blank to use built-in explanations
        - *(Optional)* Notification webhook URL: paste the Slack/Teams webhook if you want approved actions to ping that channel
        - Optional: enable Suricata rule management and pick a rules directory (default `./suricata_rules`)
     3. Click **Save configuration**. You can now navigate to Dashboard, Threat Analysis, etc.
     4. Need a quick demo? Use the **Load demo configuration** button on the Setup page. It auto-fills:
        - Log path: `demo/example_suricata_log.json`
        - Database: a working copy of `demo/demo_config.db` (in `demo/generated/`, so the committed file never changes)
        - Ollama endpoint: `http://127.0.0.1:11434`
        - Model: whatever you already entered (blank = built-in explanations)
        - Rules dir: `./suricata_rules` with dry-run enabled
        The demo is ready right away; switch back to your real paths when you're done.

   - **Command-line interface (CLI)**:  
     `python main.py --monitor <path-to-eve.json>`  
     The CLI dashboard appears in the terminal and shows live stats. Use `python main.py --help` to see all options.

## Usage

AutoDefender offers two interfaces: **Command-Line Interface (CLI)** and **Web UI (Streamlit)**.

### Web UI (Recommended for Interactive Use)

Start the web interface:
```bash
python -m streamlit run streamlit_app.py
```

**Hosted Streamlit App**: [https://autodefender.streamlit.app/](https://autodefender.streamlit.app/)

The UI will open at `http://localhost:8501` and provides:
- Real-time dashboard with live threat monitoring
- Multi-source aggregation for monitoring multiple log files
- Threat analysis with filtering, search, and export tools
- Action management for approving AI-generated rules and playbooks
- Playbook Editor for customizing response workflows
- IP whitelist and blacklist management (the running monitor reloads `ip_lists.json` when it changes)
- Settings for Suricata, Ollama, and database options
- Built-in documentation

**First steps:**
1. Complete the Setup page before navigating elsewhere. Provide the Suricata log path, database path, and Ollama details.
2. Set the `AUTODEFENDER_UI_PASSWORD` environment variable (at least 12 characters) before launching. The console refuses to start without it. On Streamlit Community Cloud, add it under **App settings -> Secrets** instead (see `.streamlit/secrets.toml.example`). For local development only, you can skip the password with `AUTODEFENDER_DEV=1` plus `--server.address localhost`. Failed sign-ins lock that client after 5 attempts in 5 minutes; a higher global backoff slows guessing without locking the operator out from another address.
3. After setup is marked complete, open the Dashboard and click **Start monitoring**. A background monitor tails each log file (handling log rotation), detects threats, and writes them to the database while the dashboard refreshes. Tick "Process existing entries" to analyze a whole uploaded log.
4. Log paths may be inside the project folder or Suricata's default log folders (`/var/log/suricata`, `C:\Program Files\Suricata\log`). To use other folders (for example `/etc/suricata/rules` for the rules directory), list them in `AUTODEFENDER_ALLOWED_DIRS`, separated by `:` on Linux/macOS or `;` on Windows.

Additional guides now live under the `docs/` directory, including:
- `docs/SURICATA_SETUP.md` for Suricata installation and configuration (Windows, Linux, Mac)
- `docs/AGENTIC_GUIDE.md` for AI-driven agentic automation features

### Command-Line Interface (CLI)

#### Real-time Monitoring
Monitor a Suricata log file in real-time:
```bash
python main.py --monitor /var/log/suricata/eve.json
```
> Tip: Add `--read-log-from-start` to process the entire file instead of tailing only new events.

### Historical Analysis
Analyze one or more existing log files:
```bash
python main.py --analyze /path/to/log1.json /path/to/log2.json
```
`--analyze` reports and exports only threats from those paths. If a file has no detections, AutoDefender does not fall back to older rows already in the database.

### Filtering Threats
Filter threats by severity:
```bash
python main.py --analyze demo/example_suricata_log.json --filter-severity HIGH CRITICAL
```

### Search Threats
Search for specific threats:
```bash
python main.py --analyze demo/example_suricata_log.json --search "SSH"
```

### AI Analysis Selection
Choose which threats to analyze with AI:
```bash
# Analyze only HIGH and CRITICAL threats with AI
python main.py --analyze demo/example_suricata_log.json --ai-severities HIGH CRITICAL

# Analyze all MEDIUM threats with AI (without this flag, only HIGH and CRITICAL use the model)
python main.py --analyze demo/example_suricata_log.json --filter-severity MEDIUM --ai-severities MEDIUM
```

### Export Threats
Export filtered threats to CSV or JSON:
```bash
# Export to JSON
python main.py --analyze demo/example_suricata_log.json --filter-severity HIGH CRITICAL --export threats.json

# Export to CSV
python main.py --analyze demo/example_suricata_log.json --search "SSH" --export ssh_threats.csv
```

### Using AI Models
AI explanations are optional. Pass any Ollama model you've pulled; without `--model` (or `OLLAMA_MODEL`), AutoDefender uses its built-in explanations:
```bash
python main.py --analyze demo/example_suricata_log.json --model <model>
python main.py --monitor /var/log/suricata/eve.json --model <model>
```

### IP Whitelist/Blacklist Management
Manage trusted and malicious IP addresses:
```bash
# Add IP to whitelist (threats from this IP will be ignored)
python main.py --whitelist 192.168.1.100

# Add IP to blacklist (traffic from this IP raises a HIGH alert; it is not blocked automatically)
python main.py --blacklist 10.0.0.50

# Remove from whitelist
python main.py --remove-whitelist 192.168.1.100

# Remove from blacklist
python main.py --remove-blacklist 10.0.0.50

# List all whitelisted and blacklisted IPs
python main.py --list-ips
```

### Combined Operations
Combine multiple features:
```bash
# Filter, analyze with AI, and export
python main.py --analyze demo/example_suricata_log.json \
  --filter-severity HIGH CRITICAL \
  --ai-severities HIGH CRITICAL \
  --export high_priority_threats.json
```

### Both Modes
Run real-time monitoring and historical analysis simultaneously:
```bash
python main.py --both /var/log/suricata/eve.json /backup/logs/
```

### Demo Script
Run the interactive demo to see all features in action:
```bash
python demo/demo.py
```

Demo features:
- Threat detection and analysis
- AI-powered explanations
- Threat filtering and search
- Export functionality
- IP whitelist/blacklist management

### Demo Configuration

The project ships with a built-in demo dataset that works on both localhost and Streamlit Cloud:
- `demo/example_suricata_log.json` - sample Suricata log file
- `demo/demo_config.db` - pre-populated demo SQLite database (included in repository)
- `demo/log_replayer.py` - optional tool to replay demo events

**Note:** The demo database (`demo/demo_config.db`) is included in the repository and only contains private or documentation IP addresses and fictional organizations. It's ready to use immediately.

In the Streamlit Setup page, click **Load demo configuration** to pre-fill:
- Suricata log path: `demo/example_suricata_log.json`
- Database path: a working copy of `demo/demo_config.db` in `demo/generated/`
- Ollama endpoint: `http://127.0.0.1:11434`
- Ollama model: whatever you already entered (blank = built-in explanations)
- Suricata rules directory: `./suricata_rules`
- Suricata rule management enabled with dry-run mode

The demo works immediately on both localhost and the hosted Streamlit app. Switch back to your real paths afterwards to monitor live data.

Need more help with Suricata itself? Check the following resources:
- Official docs: [https://docs.suricata.io/](https://docs.suricata.io/)
- Windows quick start and troubleshooting: `docs/SURICATA_SETUP.md`
- General testing instructions with real Suricata logs: see `docs/SURICATA_SETUP.md` and the upstream [Suricata documentation portal](https://suricata.io/documentation/)

### Demo Database Features

The demo database (`demo/demo_config.db`) is pre-populated and included in the repository. It contains realistic sample threats showcasing all of AutoDefender's capabilities:

- **GeoIP-enriched threats**: Examples with location and (fictional) ISP data
- **Diverse attack types**: SSH brute force, Tor exit node scans, data exfiltration attempts, MITM attacks
- **Playbook actions**: Multi-step response workflows (drop rule + log + webhook) demonstrating action bundling
- **Various action states**: RECOMMENDED, EXECUTED, REJECTED, and FAILED actions for UI testing
- **Rich AI explanations**: Detailed, context-aware threat descriptions explaining what happened, why it matters, and what to do
- **Safe test data**: All IP addresses are private ranges or reserved documentation ranges (RFC 5737), and the ISP/organization names are fictional - no real companies or people

The demo database is ready to use immediately on both localhost and Streamlit Cloud. It includes 6 sample threats and 9 associated actions.

To refresh the demo database with new sample threats at any time (optional):
```bash
python tools/populate_demo_db.py
```

This command regenerates `demo/demo_config.db` with fresh sample data for testing and demonstrations.

### Slack / Teams Webhook Example (Optional)

1. Create an **Incoming Webhook**:
   - **Slack**: open your workspace settings -> **Integrations -> Incoming Webhook** -> add new webhook and copy the URL (`https://hooks.slack.com/services/...`).
   - **Microsoft Teams**:
     1. In the Teams channel where you want alerts, click the **...** menu next to the channel name.
     2. Choose **Connectors** -> search for **Incoming Webhook** -> click **Configure**.
     3. Give the webhook a friendly name (e.g., "AutoDefender Alerts") and optionally upload an icon.
     4. Click **Create**, then copy the URL (`https://<region>.webhook.office.com/webhookb2/...`).
2. Paste the webhook URL into the "Notification webhook URL" field on the Streamlit **Setup** page and click **Save configuration**.
3. Open **Action Management**. When you approve a playbook step that says `WEBHOOK_NOTIFY`, AutoDefender sends a simple JSON payload (same format for Slack and Teams) with threat details such as severity, source IP, and description. Example payload:
   ```json
   {
     "text": "[Playbook] Critical SSH brute force response executed",
     "threat": {
       "id": 42,
       "severity": "CRITICAL",
       "source_ip": "192.168.1.101",
       "event_type": "alert",
       "description": "Suricata Alert: SSH brute force attempts"
     }
   }
   ```
   - Slack will display the `text` field automatically.
   - Microsoft Teams shows the same `text` content inside the channel message; you can optionally wrap it in an Adaptive Card by pointing the webhook to your own middleware.
4. To disable notifications, clear the webhook field and save the Setup form. No data leaves your machine unless you explicitly configure the webhook.

### Agentic Enhancements

- **Playbook Actions**: AutoDefender bundles common responses (drop rule + log + webhook) into a single approval prompt. Approve once and all steps execute in order, keeping humans in the loop but reducing clicks.
- **Playbook Editor**: Customize response workflows from the Streamlit UI. Define conditions (severity, keywords) and action sequences without editing JSON files manually.
- **Webhook Notifications**: When you approve a playbook step with `WEBHOOK_NOTIFY`, the console sends a JSON payload to your configured webhook (e.g., Slack/Teams). Leave the webhook URL blank if you prefer to stay offline - no data leaves your machine by default.
- **GeoIP Context**: Download the free [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) City (and optionally ASN) database and set `AUTODEFENDER_GEOIP_CITY_DB` / `AUTODEFENDER_GEOIP_ASN_DB` to the `.mmdb` files. Public source IPs are then enriched with location and network data entirely offline. The context appears in AI explanations and webhook notifications.
- **Blocks and Expiry**: Action Management lists every active drop rule. You can unblock an IP, and Settings has an optional block duration (0 = permanent, the default) after which rules are removed automatically. With `suricatasc` installed, rules can be reloaded without restarting Suricata (button or `SURICATA_AUTO_RELOAD=true`).
- **Multi-Source Monitoring**: Monitor multiple Suricata instances, archived logs, or distributed sensors by entering multiple file paths (one per line) on the Setup page or Dashboard.
- **Manual Steps**: `BLOCK_IP`, `RATE_LIMIT`, and `TERMINATE` recommendations are recorded as "done" when you mark them, but AutoDefender does not change your firewall. Apply them yourself; only `SURICATA_DROP_RULE` writes a rule.

## Audit Log

Sign-ins (including failures and lockouts), approvals, rejections, unblocks, IP list edits, exports, settings changes, and data deletion are recorded in a local audit log (`audit.db`, separate from the threat database so clearing threats never clears it). Open the **Audit Log** page in the console to read it. Each entry is hash-chained to the previous one, so the page can tell you if any entry was edited or deleted. Nothing is sent anywhere.

## Configuration

Set environment variables or create a `config.ini` file (see `autodefender/config.py`) to customize:
- Suricata log file paths
- Ollama endpoint (default: `http://localhost:11434`)
- Database path
- Detection thresholds (port scan threshold and window, repeat alert cooldown)
- Suricata options (dry run, auto-approval, block duration, rule reload)

**Note:** AI is optional. Use the `--model` flag (or `OLLAMA_MODEL`) to pick any Ollama model you've pulled.

### Environment Variables
```bash
# Optional: any Ollama model you've pulled (or use the --model flag)
export OLLAMA_MODEL=your-model-name

# Set Ollama endpoint
export OLLAMA_ENDPOINT=http://localhost:11434

# Web console password (required, 12+ characters)
export AUTODEFENDER_UI_PASSWORD=choose-a-long-password

# Optional: offline GeoIP with local MaxMind GeoLite2 databases
export AUTODEFENDER_GEOIP_CITY_DB=/path/to/GeoLite2-City.mmdb
export AUTODEFENDER_GEOIP_ASN_DB=/path/to/GeoLite2-ASN.mmdb

# Optional: block duration in hours (0 = permanent), and reload rules via suricatasc
export AUTODEFENDER_BLOCK_HOURS=0
export SURICATA_AUTO_RELOAD=false
export SURICATA_SOCKET=/var/run/suricata/suricata-command.socket

# Suricata integration (optional)
export SURICATA_ENABLED=true
export SURICATA_RULES_DIR=./suricata_rules
export AUTO_APPROVE_SURICATA=false
export SURICATA_DRY_RUN=false
export WEBHOOK_URL=https://your-webhook-url   # must be https://
```

### Quick Reference (Non-Technical)

- **Try online**: [https://autodefender.streamlit.app/](https://autodefender.streamlit.app/) - Demo database is pre-loaded and ready to use
- **Start Suricata**: open PowerShell -> `cd "C:\Program Files\Suricata"` -> `.\suricata.exe -c suricata.yaml -i "Wi-Fi"`
- **Run AutoDefender UI**: in the project folder -> set `AUTODEFENDER_UI_PASSWORD` -> `python -m streamlit run streamlit_app.py`
- **Run CLI monitor**: `python main.py --monitor "C:\Program Files\Suricata\log\eve.json" --model <model>`
- **Load demo data**: Setup page -> "Load demo configuration" (works on both localhost and Streamlit Cloud)
- **Replay demo log** (optional): `python demo/log_replayer.py demo/example_suricata_log.json --interval 0.5 --loop`
- **Refresh demo database** (optional): `python tools/populate_demo_db.py` - Note: demo database is pre-populated in the repository
- **Enable Slack/Teams alerts**: paste your webhook URL into the Setup page, then approve a `WEBHOOK_NOTIFY` action in Action Management.

### Suricata Integration (Agentic Features)

When monitoring finds a HIGH or CRITICAL threat, AutoDefender can propose a Suricata drop rule for the attacker's IP (AI-written when Ollama is available, built-in otherwise). Every rule is validated to block exactly one non-whitelisted source IP, written only after approval (CLI prompt or the web console's Action Management page) unless you turn on auto-approval, and backed up before each change.

```bash
export SURICATA_ENABLED=true
export SURICATA_DRY_RUN=true          # Start here: rules are logged, not written
export AUTO_APPROVE_SURICATA=false    # Ask before writing each rule (recommended)
python main.py --monitor /var/log/suricata/eve.json --model <model>
```

Drop rules only block traffic when Suricata runs inline (IPS mode). Include `suricata_rules/autodefender_custom.rules` in your `suricata.yaml`, then reload (`suricatasc`, the console's reload button, or `SURICATA_AUTO_RELOAD=true`) or restart Suricata after changes. Active blocks can be unblocked or set to expire (see **Blocks and Expiry** above).

See [docs/AGENTIC_GUIDE.md](docs/AGENTIC_GUIDE.md) for the approval workflow, configuration options, rule format, and troubleshooting.

## Project Structure

```
AutoDefender-Capstone/
|-- main.py                     # CLI entry point
|-- streamlit_app.py            # Web console entry point (sign-in and navigation)
|-- streamlit_pages/            # Web console pages (Dashboard, Incidents, Settings, ...)
|-- autodefender/               # Core package
|   |-- config.py               # Configuration (env vars, config.ini)
|   |-- models.py               # Threat, Action, and stats data classes
|   |-- parser.py               # Suricata eve.json parsing
|   |-- detector.py             # Threat detection engine
|   |-- monitor.py              # Real-time log monitoring
|   |-- analyzer.py             # Historical analysis
|   |-- action_engine.py        # Action recommendations
|   |-- playbooks.py            # Playbook matching (steps come from playbooks/playbooks.json)
|   |-- ai_explainer.py         # AI explanations and rule suggestions (Ollama)
|   |-- suricata_manager.py     # Drop rule validation, writing, blocks, expiry, reload
|   |-- approval_handler.py     # CLI approval prompts
|   |-- database.py             # SQLite storage
|   |-- filter.py               # Threat filtering and search
|   |-- exporter.py             # CSV/JSON export
|   |-- ip_manager.py           # IP whitelist/blacklist
|   |-- mitre.py                # MITRE ATT&CK technique mapping
|   |-- incidents.py            # Groups threats into incidents
|   |-- audit.py                # Local hash-chained audit log
|   |-- notifications/          # Webhook notifications
|   |-- ui/                     # Terminal dashboard (Rich)
|   |-- utils/                  # Path checks, display escaping, offline GeoIP
|-- playbooks/playbooks.json    # Response playbooks (edited in the Playbook Editor)
|-- suricata_rules/             # Rules file AutoDefender writes (include it in suricata.yaml)
|-- demo/                       # Sample log, demo database, demo script, log replayer
|-- docs/                       # Suricata setup, agentic guide, threat model
|-- tests/                      # pytest suite (run: python -m pytest)
|-- tools/                      # check_demo_data.py (real-data check), populate_demo_db.py
|-- .streamlit/                 # Streamlit security config and secrets example
|-- .github/                    # CI checks (tests, real-data check, bandit, pip-audit)
|-- .devcontainer/              # VS Code / Codespaces dev container
|-- Dockerfile, docker-compose.yml, .env.example
|-- requirements.txt, requirements-dev.txt
```

## Security & Privacy

- **Password Required**: The web console refuses to start without `AUTODEFENDER_UI_PASSWORD` (12+ characters, and not one of the example values from these docs). There are no user accounts or sign-up pages. The password is compared in constant time; more than 5 wrong attempts in 5 minutes lock that client (this survives restarts). A higher global backoff slows mass guessing without locking the operator out from another address. Changing the password signs out open sessions
- **Audit Trail**: Security-relevant actions are recorded in a local, hash-chained, tamper-evident audit log
- **Local Processing**: Analysis, AI explanations (Ollama), and GeoIP lookups all run locally. Nothing leaves your machine unless you configure a webhook
- **Safe Rule Writing**: Only single-IP `drop` rules are written. AI-suggested rules must target the threat's own source IP; rules for `any`, loopback, or whitelisted IPs are refused, and SIDs are assigned by AutoDefender
- **Human Approval**: Firewall rules need manual approval unless you explicitly enable auto-approval
- **Network Exposure**: The console listens on localhost only (`.streamlit/config.toml`). Expose it only behind a reverse proxy with HTTPS
- **Sessions**: Idle sessions are signed out after 30 minutes
- **Data Retention**: Settings -> Database can delete threats older than N days (default from `AUTODEFENDER_RETENTION_DAYS`, 90). Clearing data also compacts the database so deleted records don't linger on disk
- **File Permissions**: On Linux/macOS, new databases and CLI exports are created readable by your user only; web exports are generated in memory, not saved on the server
- **Untrusted Log Data**: Log fields and AI output are escaped before display, fenced off in AI prompts, and neutralized in CSV exports (no spreadsheet formulas)
- **SQL Injection Protection**: All database queries use parameterized statements
- **Upload Handling**: Uploaded files are saved under `uploads/` with random names, an allow-listed extension, and a 50 MB limit
- **Data Minimization**: Stored threats keep only the event fields AutoDefender uses; URLs, DNS names, TLS details, and payloads from the original log are dropped
- **AI Limits**: AI work runs on a small bounded worker pool with a per-minute call budget (`AUTODEFENDER_AI_CALLS_PER_MINUTE`, default 30), so an alert flood can't overload Ollama or the machine
- **Safe Concurrent Approvals**: An action is claimed in the database before it runs, so approving it from two tabs (or the CLI and the web console) can't apply it twice
- **Webhook Targets**: Webhook URLs must be https and point at a public host (no localhost or private addresses)
- **CORS/XSRF Protection**: Streamlit's CORS and XSRF protections stay on (see `.streamlit/config.toml`)
- **No Data Collection**: No telemetry or usage data is collected
- **No Real-World Data in the Repo**: Demo data and docs only use private and documentation IP ranges, documentation AS numbers, and fictional organization names. `python tools/check_demo_data.py` enforces this, and the GitHub Actions workflow runs it (plus the test suite, bandit, and pip-audit) on every push.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what AutoDefender stores, what it talks to, and the risks each control covers.

## Development and Tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest
python tools/check_demo_data.py
```

The suite covers detection, rule safety, log tailing (rotation and partial lines), the database, exports, ATT&CK mapping, incidents, the audit chain, GeoIP, and the web console (sign-in, lockout, every page, monitoring, approvals).

## Requirements

- Python 3.10+
- Ollama (optional, for AI explanations; any model)
- Suricata log files (JSON format - eve.json)

## Troubleshooting

### Ollama Connection Issues
If you see "model not found" errors:
```bash
# Check if Ollama is running
ollama list

# Start Ollama if not running
ollama serve

# Pull the model you want to use (choose any model you prefer)
ollama pull <your-model-name>
```

### Database Errors
If you encounter database errors:
- Check file permissions on the database file
- Ensure sufficient disk space
- Verify the database file isn't locked by another process

### Log File Issues
If log files aren't being processed:
- Verify the file path is correct
- Check file permissions (read access required)
- Ensure the file is valid JSON format
- Check that Suricata is writing to the file

## Examples

### Example 1: Quick Threat Analysis
```bash
python main.py --analyze demo/example_suricata_log.json
```

### Example 2: Focus on High-Priority Threats
```bash
python main.py --analyze demo/example_suricata_log.json \
  --filter-severity HIGH CRITICAL \
  --ai-severities HIGH CRITICAL \
  --export critical_threats.json
```

### Example 3: Search and Export
```bash
python main.py --analyze demo/example_suricata_log.json --search "SSH" --export ssh_threats.json
```