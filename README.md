# AutoDefender

An AI-powered security tool that monitors Suricata network logs in real-time and analyzes historical log files to detect threats, provide AI-generated explanations, and recommend security actions.

## Features

- **Real-time Monitoring**: Watches Suricata `eve.json` log files and processes events as they occur
- **Historical Analysis**: Batch processes existing Suricata log files for threat detection
- **AI-Powered Detection**: Uses Ollama to analyze threats and provide plain English explanations
- **Threat Detection**: Identifies port scans, unusual traffic patterns, and suspicious activity
- **Action Recommendations**: Suggests security actions based on threat severity
- **Dual Interface**: Choose between Terminal UI (Rich-based TUI) or Web UI (Streamlit)
- **Web Dashboard**: Modern, intuitive web interface with real-time monitoring, interactive charts, and action management
- **Database Storage**: SQLite database for storing threats, actions, and statistics
- **Threat Filtering**: Filter threats by severity, type, IP address, or date range
- **Search Functionality**: Search threats by description, IP, or event type
- **Export Capabilities**: Export threats and statistics to CSV or JSON format
- **IP Management**: Whitelist trusted IPs and blacklist known malicious IPs
- **Configurable AI Analysis**: Choose which threat severities to analyze with AI
- **Agentic Suricata Integration**: AI-driven automatic Suricata rule generation with permission prompts and safety controls
- **Interactive Approvals**: Real-time CLI prompts for reviewing and approving AI-generated rules

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd AutoDefender_Hackathon
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure Ollama is installed and running locally:
```bash
# Install Ollama from https://ollama.ai
ollama pull <your-chosen-model>  # e.g., llama3, mistral, phi4-mini, etc.
ollama serve  # Start Ollama server
```

**Note:** On first run, AutoDefender will automatically create:
- `autodefender.db` - SQLite database for threats and actions
- `ip_lists.json` - IP whitelist/blacklist (starts empty)
- `suricata_rules/` - Custom Suricata rules directory

## Step-by-Step Setup (Non-Technical Friendly)

1. **Install the prerequisites**
   - [Python 3.10+](https://www.python.org/downloads/)
   - [Git](https://git-scm.com/downloads)
   - [Suricata IDS](https://docs.suricata.io/en/latest/install.html) (follow the installer for your platform or use `docs/SURICATA_SETUP.md`)
   - [Ollama](https://ollama.ai/download) for local AI models

2. **Prepare Suricata**
   - Enable the `eve.json` output in `suricata.yaml` (already enabled by default)
   - Start Suricata on the interface you want to monitor:  
     `suricata -c suricata.yaml -i <interface>`
   - Official docs: [https://docs.suricata.io/](https://docs.suricata.io/)  
     Windows quick start: `docs/SURICATA_SETUP.md`

3. **Start Ollama**
   ```bash
   ollama serve
   ollama pull phi4-mini   # Example model
   ```

4. **Clone AutoDefender and install Python requirements**
   ```bash
   git clone <repository-url>
   cd AutoDefender_Hackathon
   pip install -r requirements.txt
   ```

5. **Choose how you want to run AutoDefender**
   - **Streamlit UI (recommended for most people)**:  
     `python -m streamlit run streamlit_app.py`
     1. The browser opens at `http://localhost:8501`
     2. Go to the **Setup** page and fill in:
        - *Suricata eve.json path*: the full path to `eve.json`
        - *Database path*: leave default `autodefender.db` or point somewhere else
        - *Ollama endpoint*: `http://127.0.0.1:11434`
        - *Ollama model*: the model you pulled (e.g., `phi4-mini`)
        - Optional: enable Suricata rule management and pick a rules directory (default `./suricata_rules`)
     3. Click **Save configuration**. You can now navigate to Dashboard, Threat Analysis, etc.
     4. Need a quick demo? Use the **Load demo configuration** button on the Setup page. It auto-fills:
        - Log path: `demo/example_suricata_log.json`
        - Database: `demo/demo_config.db`
        - Ollama endpoint: `http://127.0.0.1:11434`
        - Model: `phi4-mini`
        - Rules dir: `./suricata_rules` with dry-run enabled
        Save the form afterwards, and switch back to your real paths when ready.

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

Hosted Streamlit link (update after deployment): `https://your-streamlit-app-url`

The UI will open at `http://localhost:8501` and provides:
- Real-time dashboard with live threat monitoring
- Threat analysis with filtering and export tools
- Action management for approving AI-generated rules
- IP whitelist and blacklist management
- Settings for Suricata, Ollama, and database options
- Built-in documentation

**First steps:**
1. Complete the Setup page before navigating elsewhere. Provide the Suricata log path, database path, and Ollama details.
2. Set the `AUTODEFENDER_UI_PASSWORD` environment variable to require a password when launching the console.
3. After setup is marked complete, open the Dashboard to begin monitoring.

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

# Analyze all MEDIUM threats with AI
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
Specify any Ollama model for AI explanations (required for AI features):
```bash
# Use llama3
python main.py --analyze demo/example_suricata_log.json --filter-severity HIGH --model llama3

# Use mistral
python main.py --analyze demo/example_suricata_log.json --model mistral

# Use phi4-mini
python main.py --analyze demo/example_suricata_log.json --model phi4-mini

# Use any installed Ollama model
python main.py --monitor /var/log/suricata/eve.json --model gemma:7b
```

### IP Whitelist/Blacklist Management
Manage trusted and malicious IP addresses:
```bash
# Add IP to whitelist (threats from this IP will be ignored)
python main.py --whitelist 192.168.1.100

# Add IP to blacklist (threats from this IP will be auto-blocked)
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

The project ships with a built-in demo dataset. To load it:
- `demo/example_suricata_log.json` – sample Suricata log
- `demo/demo_config.db` – demo SQLite database
- `demo/log_replayer.py` – optional tool to replay demo events

In the Streamlit Setup page, click **Load demo configuration** to pre-fill:
- Suricata log path: `demo/example_suricata_log.json`
- Database path: `demo/demo_config.db`
- Ollama endpoint: `http://127.0.0.1:11434`
- Ollama model: `phi4-mini`
- Suricata rules directory: `./suricata_rules`
- Suricata rule management enabled with dry-run mode

Review the fields and click **Save configuration** to apply. Switch back to your real paths afterwards to monitor live data.

Need more help with Suricata itself? Check the following resources:
- Official docs: [https://docs.suricata.io/](https://docs.suricata.io/)
- Windows quick start and troubleshooting: `docs/SURICATA_SETUP.md`
- General testing instructions with real Suricata logs: see `docs/SURICATA_SETUP.md` and the upstream [Suricata documentation portal](https://suricata.io/documentation/)

To refresh the demo database with new sample threats at any time:
```bash
python tools/populate_demo_db.py
```

## Configuration

Edit `config.py` or create a `config.ini` file to customize:
- Suricata log file paths
- Ollama endpoint (default: `http://localhost:11434`)
- Database path
- Detection thresholds (port scan threshold, suspicious ports)
- Action policies (auto-approval settings)

**Note:** Use the `--model` flag to specify which Ollama model to use for AI features.

### Environment Variables
```bash
# Set Ollama model (or use --model flag) - user must choose their model
export OLLAMA_MODEL=your-model-name

# Set Ollama endpoint
export OLLAMA_ENDPOINT=http://localhost:11434

# Suricata integration (optional)
export SURICATA_ENABLED=true
export SURICATA_RULES_DIR=./suricata_rules
export AUTO_APPROVE_SURICATA=false
export SURICATA_DRY_RUN=false
```

### Suricata Integration (Agentic Features)

AutoDefender can automatically generate and manage Suricata rules based on detected threats using AI.

#### Features
- **AI-Driven Rule Generation**: Uses Ollama to generate context-aware Suricata drop rules
- **Permission Prompts**: Requires manual approval by default (can be configured for auto-approval)
- **Interactive CLI Workflow**: Prompts appear in the terminal to approve or reject each AI-generated rule
- **Dry-Run Mode**: Test rule generation without making changes
- **Automatic Backups**: Creates timestamped backups before modifying rule files
- **Path Validation**: Only modifies files in safe, app-controlled directories
- **Rule Validation**: Validates rule syntax before writing
- **Real-Time Integration**: Processes HIGH/CRITICAL threats immediately

#### Configuration

**Via Environment Variables:**
```bash
export SURICATA_ENABLED=true                    # Enable Suricata integration
export SURICATA_RULES_DIR=./suricata_rules      # Path to rules directory
export AUTO_APPROVE_SURICATA=false              # Require manual approval (recommended)
export SURICATA_DRY_RUN=false                   # Dry-run mode (test without executing)
```

**Via config.ini:**
```ini
[suricata]
enabled = true
rules_dir = ./suricata_rules
auto_approve = false
dry_run = false
```

#### Usage

1. **Enable Suricata Integration**:
```bash
export SURICATA_ENABLED=true
python main.py --monitor /var/log/suricata/eve.json
```
> With `AUTO_APPROVE_SURICATA=false`, AutoDefender will pause to show an interactive approval prompt for each AI-generated rule.

2. **Dry-Run Mode (Test Without Executing)**:
```bash
export SURICATA_ENABLED=true
export SURICATA_DRY_RUN=true
python main.py --monitor /var/log/suricata/eve.json
```

3. **Auto-Approve Mode (Advanced)**:
```bash
export SURICATA_ENABLED=true
export AUTO_APPROVE_SURICATA=true  # Use with caution
python main.py --monitor /var/log/suricata/eve.json
```

#### Manual Approval Workflow

When `AUTO_APPROVE_SURICATA` is disabled (default), threats that qualify for Suricata remediation trigger an interactive prompt:

1. AutoDefender displays the full AI-generated rule along with context about the triggering threat.
2. Press `y` to approve (the rule is written to the Suricata rules file) or `n` to reject.
3. **Batch Approval**: If 3+ actions are pending, you'll be offered the option to approve/reject all at once or review individually.
4. The dashboard's **Pending Agentic Actions** panel updates in real time to reflect approvals/rejections.
5. Backups are created automatically before each approved rule is written.

This workflow keeps humans in the loop while still benefiting from real-time AI triage.

#### How It Works

1. **Threat Detection**: AutoDefender detects HIGH or CRITICAL threat
2. **AI Analysis**: AI generates a Suricata drop rule based on threat context
3. **Permission Prompt**: System asks for approval (unless auto-approve is enabled)
4. **Rule Execution**: Upon approval, rule is added to custom rules file with automatic backup
5. **Dashboard Display**: Pending actions shown in real-time dashboard

#### Safety Features

- **Default to Manual Approval**: Requires user confirmation before executing rules
- **Batch Approval**: Efficiently approve/reject multiple pending actions at once (3+ actions)
- **Dry-Run Mode**: Test rule generation without making changes
- **Automatic Backups**: Timestamped backups created before each modification
- **Path Validation**: Only modifies files within app-controlled directories
- **Rule Validation**: Checks rule syntax before writing
- **Master Switch**: `SURICATA_ENABLED` flag to disable all operations
- **Audit Logging**: All actions logged to database for review
- **Health Monitoring**: Automatic checks of rules directory, disk space, and file permissions
- **Restart Notifications**: Dashboard alerts when Suricata needs restart to apply new rules

#### Windows Support

Suricata integration works on Windows using file-based rule management:
- Rules are written to custom rules file immediately
- Dashboard displays a restart banner when new rules have been added
- Suricata must be restarted or reloaded to pick up new rules
- No control socket (`suricatasc`) required
- Health monitoring tracks rules file status and disk space

## Project Structure

```
AutoDefender_Hackathon/
├── main.py                 # CLI entry point
├── config.py               # Configuration management
├── analyzer.py             # Historical analysis
├── monitor.py              # Real-time monitoring
├── parser.py               # Suricata JSON log parsing
├── detector.py             # Threat detection engine
├── ai_explainer.py         # AI integration (Ollama)
├── action_engine.py        # Action recommendations
├── suricata_manager.py     # Suricata rule file management
├── approval_handler.py     # Permission prompt system
├── database.py             # SQLite database operations
├── filter.py               # Threat filtering and search
├── exporter.py             # Export functionality (CSV/JSON)
├── ip_manager.py           # IP whitelist/blacklist management
├── ui/                     # Terminal dashboard components
│   └── dashboard.py        # CLI dashboard with threat/stats panels
├── streamlit_app.py        # Streamlit entry point
├── streamlit_pages/        # Streamlit page implementations
├── demo/
│   ├── demo.py             # Interactive demo script
│   ├── example_suricata_log.json
│   ├── log_replayer.py     # Utility to replay events into eve.json
│   ├── generated/          # Temporary files created during demo
│   └── outputs/            # Demo export artifacts
├── docs/                   # Additional guides and references
│   ├── SURICATA_SETUP.md   # Suricata installation and configuration
│   └── AGENTIC_GUIDE.md    # AI-driven agentic automation guide
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

## Security & Privacy

- **Local Processing**: All analysis runs locally - no data sent to external services
- **SQL Injection Protection**: All database queries use parameterized statements
- **Input Validation**: All user inputs are validated and sanitized
- **File Permissions**: Database and IP list files use appropriate permissions
- **No Data Collection**: No telemetry or usage data is collected
- **Secure Storage**: Sensitive data stored in local SQLite database with proper access controls

## Requirements

- Python 3.10+
- Ollama (local installation)
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