# Agentic Suricata Integration Guide

This guide covers how AutoDefender uses AI to propose Suricata drop rules, how you approve them, and the safety controls around them.

## Table of Contents
- [Overview](#overview)
- [Quick Start](#quick-start)
- [Features](#features)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Manual Approval Workflow](#manual-approval-workflow)
- [Managing Active Blocks](#managing-active-blocks)
- [How It Works](#how-it-works)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

---

## Overview

When AutoDefender detects a HIGH or CRITICAL threat while monitoring, it can ask a local AI model (Ollama) to propose a Suricata drop rule for the attacker's IP. A person approves the rule before it is written, unless you explicitly turn on auto-approval.

**Key capabilities:**
- AI-proposed drop rules, validated so they can only block the threat's own source IP
- Approval prompts in the CLI and approve/reject buttons in the web console
- Dry-run mode for safe testing
- Automatic rule file backups
- Active block list with unblock, optional block expiry, and rule reload via `suricatasc`
- Every approval, rejection, and unblock recorded in the local audit log

---

## Quick Start

### Dry-Run Mode (Safe Testing)

**Windows PowerShell:**
```powershell
$env:SURICATA_ENABLED="true"
$env:SURICATA_DRY_RUN="true"
$env:SURICATA_RULES_DIR="./suricata_rules"
$env:AUTO_APPROVE_SURICATA="false"

python main.py --monitor "C:\Program Files\Suricata\log\eve.json" --model <model>
```

**Linux/Mac:**
```bash
export SURICATA_ENABLED=true
export SURICATA_DRY_RUN=true
export SURICATA_RULES_DIR=./suricata_rules
export AUTO_APPROVE_SURICATA=false

python main.py --monitor /var/log/suricata/eve.json --model <model>
```

### What to Expect

When HIGH or CRITICAL threats are detected:
1. AutoDefender asks the AI for a drop rule (or uses its built-in rule if Ollama is unavailable or busy)
2. The rule is validated: one `drop` rule for exactly the threat's source IP
3. An approval prompt appears in the terminal
4. You approve (`y`) or reject (`n`)
5. Approved rules are added to the rules file (or only logged in dry-run mode)

---

## Features

- **AI-proposed rules**: Ollama suggests a rule with a descriptive message; AutoDefender rebuilds it in a fixed format with its own SID
- **Strict validation**: rules for `any`, address ranges, loopback/unspecified/multicast, or whitelisted IPs are refused, as is anything with extra options or more than one line
- **Approval prompts**: Rich-formatted CLI prompts, with batch approve/reject when 3 or more rules are waiting
- **Web console approvals**: Action Management lists pending actions with Approve/Reject buttons
- **No double-applies**: an action is claimed in the database before it runs, so the CLI and the web console can't both apply it
- **Dry-run mode**: test the whole flow without changing the rules file
- **Backups**: a timestamped backup before every change; the 10 most recent are kept
- **Path validation**: only the configured rules directory is written
- **Active blocks**: see every rule AutoDefender wrote, unblock IPs, and optionally let blocks expire
- **Rule reload**: reload Suricata's rules with `suricatasc` instead of restarting
- **Audit log**: approvals, rejections, auto-approvals, and unblocks are recorded in `audit.db` (hash-chained)
- **Bounded AI use**: AI requests run on a small worker pool with a per-minute budget; extra threats get the built-in rule

---

## Configuration

### Environment Variables

```bash
# Master switch
SURICATA_ENABLED=true

# Rules directory
SURICATA_RULES_DIR=./suricata_rules

# Dry run: log proposed rules without writing them
SURICATA_DRY_RUN=true

# Write AI-proposed rules without asking (not recommended)
AUTO_APPROVE_SURICATA=false

# How long a block lasts in hours (0 = permanent until you unblock it)
AUTODEFENDER_BLOCK_HOURS=0

# Reload Suricata's rules with suricatasc after each change
SURICATA_AUTO_RELOAD=false
SURICATA_SOCKET=/var/run/suricata/suricata-command.socket
```

### Via config.ini (CLI `--config`)

```ini
[suricata]
enabled = true
rules_dir = ./suricata_rules
auto_approve = false
dry_run = false
block_hours = 0
auto_reload = false
socket = /var/run/suricata/suricata-command.socket
```

### Configuration Precedence

1. `config.ini` passed with `--config` (highest priority)
2. Environment variables
3. Defaults in `autodefender/config.py` (lowest priority)

In the web console, the Setup and Settings pages override these for your browser session.

---

## Usage Examples

### Example 1: Safe Testing with Dry-Run

```bash
export SURICATA_ENABLED=true
export SURICATA_DRY_RUN=true
export AUTO_APPROVE_SURICATA=false
python main.py --monitor /var/log/suricata/eve.json --model <model>
```

**Result:** Proposed rules are shown and logged but not written.

### Example 2: Manual Approval (Production Mode)

```bash
export SURICATA_ENABLED=true
export SURICATA_DRY_RUN=false
export AUTO_APPROVE_SURICATA=false
python main.py --monitor /var/log/suricata/eve.json --model <model>
```

**Result:** Each rule needs your approval before it is written.

### Example 3: Auto-Approval with Expiring Blocks (Advanced)

```bash
export SURICATA_ENABLED=true
export SURICATA_DRY_RUN=false
export AUTO_APPROVE_SURICATA=true
export AUTODEFENDER_BLOCK_HOURS=24
python main.py --monitor /var/log/suricata/eve.json --model <model>
```

**Result:** HIGH/CRITICAL threats are blocked without a prompt, and each block is removed after 24 hours. Rules are still limited to one non-whitelisted source IP, and every auto-approval is recorded in the audit log.

### Example 4: Historical Analysis

```bash
python main.py --analyze /var/log/suricata/eve.json
```

**Result:** Threats and recommended actions (including `SURICATA_DROP_RULE`) are stored in the database. Historical analysis doesn't write rules; review and approve them later in the web console's Action Management page.

---

## Manual Approval Workflow

When `AUTO_APPROVE_SURICATA` is off (the default), qualifying threats trigger a prompt:

1. AutoDefender shows the proposed rule and the threat that triggered it
2. Press `y` to approve (the rule is written) or `n` to reject
3. With 3 or more rules waiting, you can approve or reject them all at once, or review each one
4. If the prompt can't be shown (for example, no interactive terminal), nothing is approved; the action stays pending for the web console
5. A backup of the rules file is made before each approved rule is written

**Example prompt:**
```
+-------------------------------------------------------------------+
| Agentic Action Requires Approval                                  |
+-------------------------------------------------------------------+
| Action Type: SURICATA_DROP_RULE                                   |
| Proposed Rule:                                                    |
| drop ip 203.0.113.45 any -> any any (msg:"AutoDefender: SSH       |
| brute force"; sid:9000001; rev:1;)                                |
|                                                                   |
| Threat: SSH Root Login Attempt from 203.0.113.45                  |
|                                                                   |
| Requested at: 2025-11-14 10:30:15                                 |
+-------------------------------------------------------------------+

Approve this action? [y/N]:
```

---

## Managing Active Blocks

In the web console, open **Action Management -> Active blocks** to:
- See each blocked IP, its SID, the reason, when it was blocked, and when it expires
- **Unblock** an IP (its rule is removed after a backup)
- **Reload Suricata rules now** if `suricatasc` is installed

Set a block duration in **Settings -> Suricata integration** (0 = permanent, the default). Expired blocks are removed automatically while monitoring runs and whenever Action Management is opened. IP addresses get reassigned over time, so permanent blocks can eventually hit innocent users.

---

## How It Works

1. **Detection**: the detector raises a HIGH or CRITICAL threat
2. **Rule proposal**: the AI (or the built-in rule) proposes a drop rule for the source IP
3. **Validation**: `parse_drop_rule()` and `build_drop_rule()` in `autodefender/suricata_manager.py` accept only the exact single-IP format
4. **Approval**: CLI prompt, web console button, or auto-approval if enabled
5. **Write**: `SuricataManager.add_custom_rule()` backs up the file, skips IPs that are already blocked, assigns the SID, appends the rule, and records the block (and its expiry) in `autodefender_blocks.json`
6. **Reload**: Suricata picks up the change after a reload or restart; the CLI dashboard and web console say when one is needed

### Main components

- **`autodefender/suricata_manager.py`**: rule validation, writing, backups, active blocks, unblock, expiry, and `suricatasc` reload
- **`autodefender/ai_explainer.py`**: AI explanations and rule suggestions, with untrusted-data fencing and a per-minute call budget
- **`autodefender/monitor.py`**: real-time processing with a bounded AI worker pool and the CLI approval queue
- **`autodefender/approval_handler.py`**: CLI approval prompts and batch approval
- **`autodefender/audit.py`**: the hash-chained audit log

### Rule File Structure

- **Location**: `./suricata_rules/autodefender_custom.rules` (configurable)
- **SIDs**: assigned by AutoDefender starting at 9000001 (the AI's suggested SID is ignored)
- **Format**: `drop ip <ip> any -> any any (msg:"..."; sid:N; rev:1;)`
- **Block records**: `autodefender_blocks.json` in the same folder (when each rule was added and when it expires)
- **Backups**: timestamped copies; the 10 most recent are kept
- **Enforcement**: drop rules only block traffic when Suricata runs inline (IPS mode); in IDS mode they only alert

**Example rules file:**
```
drop ip 203.0.113.45 any -> any any (msg:"AutoDefender: Suricata Alert: ET SCAN Potential SSH Scan"; sid:9000001; rev:1;)
drop ip 10.0.0.50 any -> any any (msg:"AutoDefender: Port scan detected from 10.0.0.50"; sid:9000002; rev:1;)
```

### Database Schema

Actions are stored in the `actions` table:
- `id`: Unique action ID
- `threat_id`: Associated threat ID
- `action_type`: e.g. `SURICATA_DROP_RULE`
- `description`: Full rule or action description
- `status`: `RECOMMENDED`, `PROCESSING` (briefly, while being applied), `EXECUTED`, `REJECTED`, `FAILED`
- `timestamp`: When the action was created
- `executed_at`: When the action was executed

---

## Windows Support

Rule management is file-based, so it works on Windows:
- Rules are written to the custom rules file immediately
- Restart Suricata (or reload with `suricatasc` if available) to apply them

**Restarting Suricata on Windows:**
```powershell
# Stop Suricata (press Ctrl+C in the terminal where it's running)
# Or stop the process
Get-Process suricata | Stop-Process

# Start it again
cd "C:\Program Files\Suricata"
.\suricata.exe -c suricata.yaml -i "Wi-Fi"
```

---

## Troubleshooting

### No approval prompts appearing

- Check `AUTO_APPROVE_SURICATA` is `false` and `SURICATA_ENABLED` is `true`
- Make sure threats are HIGH or CRITICAL severity
- Check the console output for errors

### Rules not being written

- Dry-run mode may be on (`SURICATA_DRY_RUN=true`)
- The IP may be whitelisted, loopback, or already blocked
- Make sure the rules directory exists and is writable
- Check the console or server log for "Refusing rule" messages

### Suricata not picking up new rules

- Reload or restart Suricata after rules change
- Check that `autodefender_custom.rules` is listed in `suricata.yaml`
- Check Suricata's logs for rule parsing errors

### Performance issues

- Limit AI explanations in historical analysis with `--ai-severities`
- Raise the repeat alert cooldown (Settings -> Detection) so noisy sources create fewer threats
- Lower `AUTODEFENDER_AI_CALLS_PER_MINUTE` if Ollama can't keep up

---

## Best Practices

1. **Start with dry-run mode** when testing a new setup
2. **Keep manual approval on** in production
3. **Set a block duration** so blocks don't outlive the IP's owner
4. **Review Action Management history and the Audit Log page** regularly
5. **Include `autodefender_custom.rules` in `suricata.yaml`** and reload after changes
6. **Pick any local Ollama model** that suits your hardware, or none to use built-in explanations
