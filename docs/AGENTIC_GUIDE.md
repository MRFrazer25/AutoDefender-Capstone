# Agentic Suricata Integration Guide

This guide covers AutoDefender's AI-driven agentic capabilities for automatic Suricata rule generation and management.

## Table of Contents
- [Overview](#overview)
- [Quick Start](#quick-start)
- [Features](#features)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Safety Features](#safety-features)
- [Implementation Details](#implementation-details)

---

## Overview

AutoDefender can automatically analyze threats and generate/execute Suricata rules in real-time using AI, with user permission prompts and comprehensive safety controls.

**Key Capabilities:**
- AI-driven Suricata drop rule generation
- Interactive permission prompts (manual approval by default)
- Dry-run mode for safe testing
- Automatic rule file backups
- Path validation and rule syntax checking
- Real-time integration with HIGH/CRITICAL threats

---

## Quick Start

### Dry-Run Mode (Safe Testing)

**Windows PowerShell:**
```powershell
# Enable Suricata integration in dry-run mode
$env:SURICATA_ENABLED="true"
$env:SURICATA_DRY_RUN="true"
$env:SURICATA_RULES_DIR="./suricata_rules"
$env:AUTO_APPROVE_SURICATA="false"

# Run monitor
python main.py --monitor "C:\Program Files\Suricata\log\eve.json" --model phi4-mini
```

**Linux/Mac:**
```bash
# Enable Suricata integration in dry-run mode
export SURICATA_ENABLED=true
export SURICATA_DRY_RUN=true
export SURICATA_RULES_DIR=./suricata_rules
export AUTO_APPROVE_SURICATA=false

# Run monitor
python main.py --monitor /var/log/suricata/eve.json --model phi4-mini
```

### What to Expect

When HIGH or CRITICAL threats are detected:
1. AutoDefender analyzes the threat with AI
2. AI generates a Suricata drop rule
3. An interactive approval prompt appears in the terminal
4. You can approve (y) or reject (n) the proposed rule
5. Approved rules are added to the rules file (or simulated in dry-run mode)
6. The dashboard shows pending actions in real-time

---

## Features

### Core Features

- **AI-Driven Rule Generation**: Uses Ollama to generate context-aware Suricata drop rules
- **Permission Prompts**: Requires manual approval by default (configurable for auto-approval)
- **Interactive CLI Workflow**: Rich-formatted prompts for action approval/rejection
- **Batch Approval**: Efficiently approve/reject multiple pending actions at once (3+ actions)
- **Dry-Run Mode**: Test rule generation without making actual changes
- **Automatic Backups**: Creates timestamped backups before modifying rule files
- **Path Validation**: Only modifies files in safe, app-controlled directories
- **Rule Validation**: Validates rule syntax before writing
- **Real-Time Integration**: Processes HIGH/CRITICAL threats immediately

### Safety Features

- **Default to Manual Approval**: Requires user confirmation before executing rules
- **Dry-Run Mode**: Test without affecting actual Suricata rules
- **Automatic Backups**: Timestamped backups created before each modification
- **Path Validation**: Only modifies files within app-controlled directories
- **Rule Validation**: Checks rule syntax before writing
- **Master Switch**: `SURICATA_ENABLED` flag to disable all operations
- **Audit Logging**: All actions logged to database for review
- **Health Monitoring**: Automatic checks of rules directory, disk space, and file permissions
- **Restart Notifications**: Dashboard alerts when Suricata needs restart to apply new rules

---

## Configuration

### Environment Variables

```bash
# Master switch - enable/disable Suricata integration
SURICATA_ENABLED=true

# Rules directory path
SURICATA_RULES_DIR=./suricata_rules

# Dry-run mode - test without executing
SURICATA_DRY_RUN=true

# Auto-approval - requires manual approval when false (recommended)
AUTO_APPROVE_SURICATA=false
```

### Via config.ini

```ini
[suricata]
enabled = true
rules_dir = ./suricata_rules
auto_approve = false
dry_run = false
```

### Configuration Precedence

1. Command-line environment variables (highest priority)
2. `config.ini` file
3. Default values in `config.py` (lowest priority)

---

## Usage Examples

### Example 1: Safe Testing with Dry-Run

```bash
# Enable dry-run mode
export SURICATA_ENABLED=true
export SURICATA_DRY_RUN=true
export AUTO_APPROVE_SURICATA=false

# Monitor Suricata logs
python main.py --monitor /var/log/suricata/eve.json --model phi4-mini
```

**Result:** AI-generated rules are displayed in the terminal but not written to disk.

### Example 2: Manual Approval (Production Mode)

```bash
# Enable Suricata integration with manual approval
export SURICATA_ENABLED=true
export SURICATA_DRY_RUN=false
export AUTO_APPROVE_SURICATA=false

# Monitor Suricata logs
python main.py --monitor /var/log/suricata/eve.json --model phi4-mini
```

**Result:** Each AI-generated rule requires manual approval before being written.

### Example 3: Auto-Approval (Advanced)

```bash
# Enable auto-approval (use with caution)
export SURICATA_ENABLED=true
export SURICATA_DRY_RUN=false
export AUTO_APPROVE_SURICATA=true

# Monitor Suricata logs
python main.py --monitor /var/log/suricata/eve.json --model phi4-mini
```

**Result:** HIGH/CRITICAL threats automatically trigger rule generation without approval prompts.

### Example 4: Historical Analysis with Agentic Features

```bash
# Enable Suricata integration
export SURICATA_ENABLED=true
export SURICATA_DRY_RUN=true

# Analyze existing log files
python main.py --analyze /var/log/suricata/eve.json --model phi4-mini
```

**Result:** Analyzes historical threats and suggests rules (in dry-run mode).

---

## Manual Approval Workflow

When `AUTO_APPROVE_SURICATA` is disabled (default), threats that qualify for Suricata remediation trigger an interactive prompt:

1. AutoDefender displays the full AI-generated rule along with context about the triggering threat
2. Press `y` to approve (the rule is written to the Suricata rules file) or `n` to reject
3. **Batch Approval**: If 3+ actions are pending, you'll be offered the option to approve/reject all at once or review individually
4. The dashboard's **Pending Agentic Actions** panel updates in real-time to reflect approvals/rejections
5. Backups are created automatically before each approved rule is written

**Example Prompt:**
```
┌─────────────────────────────────────────────────────────────┐
│ Agentic Action Requires Approval                            │
├─────────────────────────────────────────────────────────────┤
│ Action Type: SURICATA_DROP_RULE                            │
│ Proposed Rule:                                              │
│ drop tcp any any -> 192.168.1.100 22 (msg:"AutoDefender:   │
│ Block SSH brute force from 10.0.0.50"; sid:1000001; rev:1;)│
│                                                             │
│ Threat: SSH Root Login Attempt from 10.0.0.50             │
│                                                             │
│ Requested at: 2025-11-14 10:30:15                         │
└─────────────────────────────────────────────────────────────┘

Approve this action? [y/N]:
```

---

## Implementation Details

### New Files

1. **`suricata_manager.py`**: Complete Suricata rule file management system
   - Add drop rules to custom rules file with automatic SID management
   - Automatic timestamped backups before modifications
   - Rule syntax validation
   - Path safety validation
   - Dry-run mode support
   - Backup cleanup functionality

2. **`approval_handler.py`**: Permission prompt and approval system
   - Interactive CLI prompts for action approval
   - Rich-formatted display of pending actions
   - Callback support for approval/rejection workflows
   - Batch approval functionality

### Modified Files

1. **`config.py`**: Added Suricata configuration options
2. **`action_engine.py`**: Added `SURICATA_DROP_RULE` action type
3. **`ai_explainer.py`**: New `suggest_suricata_rule()` function
4. **`monitor.py`**: Real-time integration with agentic features
5. **`analyzer.py`**: Historical analysis integration
6. **`main.py`**: CLI support for agentic features

### How It Works

1. **Threat Detection**: AutoDefender detects HIGH or CRITICAL threat
2. **AI Analysis**: AI generates a Suricata drop rule based on threat context
3. **Permission Prompt**: System asks for approval (unless auto-approve is enabled)
4. **Rule Execution**: Upon approval, rule is added to custom rules file with automatic backup
5. **Dashboard Display**: Pending actions shown in real-time dashboard
6. **Suricata Restart**: Dashboard displays a restart banner when new rules are added

### Rule File Structure

AutoDefender creates and manages a custom rules file:
- **Location**: `./suricata_rules/autodefender_custom.rules` (configurable)
- **SID Range**: Auto-generated starting from 1000001
- **Format**: Standard Suricata rule syntax
- **Backups**: Timestamped backups created before each modification

**Example Rules File:**
```
# AutoDefender Custom Rules
# Generated: 2025-11-14 10:30:15

drop tcp any any -> 192.168.1.100 22 (msg:"AutoDefender: Block SSH brute force from 10.0.0.50"; sid:1000001; rev:1;)
drop tcp 10.0.0.50 any -> any any (msg:"AutoDefender: Block malicious source 10.0.0.50"; sid:1000002; rev:1;)
```

### Database Schema

Actions are stored in the `actions` table:
- `id`: Unique action ID
- `threat_id`: Associated threat ID
- `action_type`: Action type (e.g., `SURICATA_DROP_RULE`)
- `description`: Full rule or action description
- `status`: `RECOMMENDED`, `APPROVED`, `EXECUTED`, `REJECTED`
- `timestamp`: When the action was created
- `executed_at`: When the action was executed (if approved)

---

## Windows Support

Suricata integration works on Windows using file-based rule management:
- Rules are written to custom rules file immediately
- Dashboard displays a restart banner when new rules have been added
- Suricata must be restarted or reloaded to pick up new rules
- No control socket (`suricatasc`) required
- Health monitoring tracks rules file status and disk space

**Restarting Suricata on Windows:**
```powershell
# Stop Suricata (press Ctrl+C in the terminal where it's running)
# Or kill the process
Get-Process suricata | Stop-Process

# Restart Suricata
cd "C:\Program Files\Suricata"
.\suricata.exe -c suricata.yaml -i "Wi-Fi"
```

---

## Troubleshooting

### No approval prompts appearing

- Check `AUTO_APPROVE_SURICATA` is set to `false`
- Verify `SURICATA_ENABLED` is set to `true`
- Ensure threats are HIGH or CRITICAL severity
- Check console output for errors

### Rules not being written

- Check if dry-run mode is enabled (`SURICATA_DRY_RUN=true`)
- Verify rules directory exists and is writable
- Check console output for permission errors
- Verify path validation is passing

### Suricata not picking up new rules

- Restart Suricata after new rules are added
- Check if the rules file is included in `suricata.yaml`
- Verify rules file path in Suricata config
- Check Suricata logs for rule parsing errors

### Performance issues

- Reduce AI analysis scope with `--ai-severities` flag
- Use auto-approval for non-critical environments
- Increase monitoring interval in `monitor.py`

---

## Best Practices

1. **Always start with dry-run mode** when testing new configurations
2. **Use manual approval** in production environments
3. **Regularly review** approved actions in the database
4. **Test AI-generated rules** before deploying to production Suricata
5. **Monitor disk space** for backup files
6. **Keep backups** of your rules files
7. **Document custom rules** with clear messages
8. **Restart Suricata** after adding new rules
9. **Review dashboard alerts** for restart notifications
10. **Use appropriate Ollama models** for your security requirements


