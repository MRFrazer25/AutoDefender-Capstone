# AutoDefender Threat Model

A short summary of what AutoDefender protects, what could go wrong, and how the code handles it.

## What it stores

| Data | Where | Notes |
| --- | --- | --- |
| Threats and recommended actions | SQLite database (`autodefender.db` by default) | IP addresses, ports, alert signatures, AI explanations. Only the event fields AutoDefender uses are kept (no URLs, DNS names, TLS details, or payloads). Optional retention purge. |
| Audit log | `audit.db` | Sign-ins and changes, hash-chained so edits are detectable. |
| IP lists | `ip_lists.json` | Whitelist and blacklist. |
| Drop rules | `suricata_rules/autodefender_custom.rules` + `autodefender_blocks.json` | Rules AutoDefender wrote and when they expire. |

On Linux/macOS the databases and CLI exports are created readable by the current user only. Nothing above is committed to git (see `.gitignore`).

## Who can do what

- **Web console**: anyone who knows `AUTODEFENDER_UI_PASSWORD`. There are no user accounts or sign-up pages. The console listens on localhost only.
- **CLI**: anyone who can run commands on the machine (same trust as the files themselves).
- **Log authors**: anyone who can send network traffic can influence log fields (signatures, IPs, HTTP data). Treated as untrusted input.

## Secrets it needs

- `AUTODEFENDER_UI_PASSWORD` (environment variable or Streamlit secrets, never in the repo).
- Optional webhook URL (Slack/Teams URLs are secrets; never logged).

## Outside services

| Service | When | What is sent |
| --- | --- | --- |
| Ollama | AI explanations and rule suggestions | Threat details. Runs locally by default. |
| Webhook (Slack/Teams) | Only when you approve a `WEBHOOK_NOTIFY` step | Threat summary. https and public hosts only. |
| GeoIP | Never over the network | Uses local GeoLite2 files. |

## Main risks and controls

| Risk | Control |
| --- | --- |
| Someone else opens the console and approves rules | Required password (12+ characters, no example values), localhost binding, lockout after 5 failures per 5 minutes that survives restarts, 30-minute idle sign-out, sign-out when the password changes |
| Malicious log data tricks the AI into a harmful rule (prompt injection) | Log data is fenced off as untrusted in prompts; AI rules must be exactly one `drop` rule for the threat's own source IP; `any`, loopback, and whitelisted IPs are refused |
| Rule file corruption or injected extra rules | Rules are rebuilt from validated parts on one line, SIDs assigned by AutoDefender, backups before every change |
| Log data or AI output rendered as links/HTML in the console | All untrusted text is escaped before display; terminal output escapes Rich markup |
| Spreadsheet formula injection in exports | CSV cells starting with `=`, `+`, `-`, `@` are neutralized |
| Path tricks to read or write other files | Paths must stay inside the project, Suricata's log folders, or `AUTODEFENDER_ALLOWED_DIRS`; symlinks are resolved first |
| Alert floods exhausting the machine | Bounded AI worker pool, a per-minute AI call budget, repeat-alert cooldowns, capped per-IP tracking |
| Two people approving the same action at once | Actions are claimed atomically in the database before anything is written |
| Real people or companies named in demo data | `tools/check_demo_data.py` fails on real IPs, AS numbers, or organization names (runs in CI) |
| Vulnerable or fake dependencies | Only well-known packages; pip-audit in CI plus GitHub's Dependabot alerts (a repo setting); GitHub Actions pinned to commit SHAs |

## Out of scope

- Protecting against someone who already has shell access to the machine.
- Blocking traffic by itself: drop rules only take effect when Suricata runs inline (IPS mode).
- Hosting the console on the public internet without a reverse proxy that adds HTTPS.
