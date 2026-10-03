#!/usr/bin/env python3
"""AutoDefender demo.

Shows threat analysis, AI explanations, filtering, export, and IP management.
"""

import json
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

BASE_DIR = Path(__file__).resolve().parent
# Allow running as "python demo/demo.py" from the project root
if str(BASE_DIR.parent) not in sys.path:
    sys.path.insert(0, str(BASE_DIR.parent))

from analyzer import HistoricalAnalyzer  # noqa: E402
from config import Config  # noqa: E402
from exporter import threats_to_csv, threats_to_json  # noqa: E402
from filter import ThreatFilter  # noqa: E402
from ip_manager import IPManager  # noqa: E402

OUTPUT_DIR = BASE_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)
TEMP_DIR = BASE_DIR / "generated"
TEMP_DIR.mkdir(exist_ok=True)

console = Console()


def create_demo_log_file() -> Path:
    """Create a demo Suricata log file with various threat types."""
    demo_file = TEMP_DIR / "demo_suricata_log.json"

    events = [
        {
            "timestamp": "2025-01-15T10:00:00.123456+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.0.1",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2019416,
                "rev": 4,
                "signature": "ET CRITICAL SSH Root Login Attempt",
                "category": "Attempted User Privilege Gain",
                "severity": 1,
            },
        },
        {
            "timestamp": "2025-01-15T10:01:00.234567+0000",
            "event_type": "alert",
            "src_ip": "172.16.0.50",
            "dest_ip": "10.0.0.1",
            "dest_port": 445,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2024298,
                "rev": 2,
                "signature": "ET EXPLOIT SMB EternalBlue Exploit Attempt",
                "category": "A Network Trojan was detected",
                "severity": 1,
            },
        },
        {
            "timestamp": "2025-01-15T10:02:00.345678+0000",
            "event_type": "flow",
            "src_ip": "203.0.113.10",
            "dest_ip": "10.0.0.1",
            "dest_port": 80,
            "proto": "TCP",
            "flow": {"pkts_toserver": 10, "pkts_toclient": 5},
        },
        {
            "timestamp": "2025-01-15T10:03:00.456789+0000",
            "event_type": "alert",
            "src_ip": "198.51.100.25",
            "dest_ip": "10.0.0.1",
            "dest_port": 1433,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2012888,
                "rev": 12,
                "signature": "ET EXPLOIT MSSQL SQL Injection Attempt",
                "category": "Attempted Information Leak",
                "severity": 1,
            },
        },
        {
            "timestamp": "2025-01-15T10:04:00.567890+0000",
            "event_type": "flow",
            "src_ip": "192.0.2.100",
            "dest_ip": "10.0.0.1",
            "dest_port": 3389,
            "proto": "TCP",
            "flow": {"pkts_toserver": 15, "pkts_toclient": 8},
        },
    ]

    with demo_file.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")

    console.print(f"[green][OK][/green] Created demo log file: {demo_file.relative_to(BASE_DIR)}")
    return demo_file


def run_demo() -> None:
    """Run the complete AutoDefender demo."""
    console.print(Panel.fit("[bold cyan]AutoDefender - Interactive Demo[/bold cyan]", border_style="cyan"))
    console.print("\nDemo: threat analysis, AI explanations, filtering, export, and IP management.\n")
    input("Press Enter to start...")

    demo_file = create_demo_log_file()
    console.print("\n[bold]Analyzing threats...[/bold]")
    config = Config.get_default()
    # Use a throwaway database so the demo never touches your real autodefender.db
    demo_db = TEMP_DIR / "demo_run.db"
    demo_db.unlink(missing_ok=True)
    config.db_path = str(demo_db)
    analyzer = HistoricalAnalyzer(config)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Processing sample log...", total=None)
        threats = analyzer.analyze_file(str(demo_file), generate_explanations=False)
        progress.update(task, completed=True)

    console.print(f"[green][OK][/green] Detected {len(threats)} threats")

    console.print("\nFiltering for high-severity threats...")
    filter_obj = ThreatFilter()
    high_critical = filter_obj.filter_by_severity_list(threats, ["HIGH", "CRITICAL"])
    console.print(f"[green][OK][/green] Found {len(high_critical)} HIGH/CRITICAL threats")

    console.print("\nGenerating AI explanations for severe threats...")
    try:
        analyzer.generate_ai_explanations(high_critical, use_ai=True)
        console.print("[green][OK][/green] AI explanations generated")
    except Exception as exc:
        console.print(f"[yellow][!][/yellow] AI explanations unavailable: {exc}")

    console.print("\nSearching for SSH-related threats...")
    ssh_threats = filter_obj.search_threats(threats, "SSH")
    console.print(f"[green][OK][/green] Found {len(ssh_threats)} SSH-related threats")

    console.print("\nExporting results to JSON and CSV...")
    json_path = OUTPUT_DIR / "demo_threats.json"
    csv_path = OUTPUT_DIR / "demo_threats.csv"
    json_path.write_text(threats_to_json(threats), encoding="utf-8")
    csv_path.write_text(threats_to_csv(threats), encoding="utf-8", newline="")
    console.print(f"[green][OK][/green] Wrote {json_path.relative_to(BASE_DIR)}")
    console.print(f"[green][OK][/green] Wrote {csv_path.relative_to(BASE_DIR)}")

    console.print("\nUpdating demo IP lists...")
    ip_list_path = TEMP_DIR / "demo_ip_lists.json"
    ip_manager = IPManager(str(ip_list_path))
    ip_manager.add_whitelist("192.168.1.100")
    ip_manager.add_blacklist("203.0.113.10")
    console.print("[green][OK][/green] Demo IP lists updated")

    console.print("\nSummary of demo results")
    summary_panel = Panel(escape(analyzer.get_summary()), title="Demo Results", border_style="green")
    console.print(summary_panel)

    console.print("\nCleaning up temporary files...")
    try:
        demo_file.unlink(missing_ok=True)
        ip_list_path.unlink(missing_ok=True)
    except Exception as exc:
        console.print(f"[yellow]Warning:[/yellow] Could not remove temporary files: {exc}")

    analyzer.close()
    demo_db.unlink(missing_ok=True)
    console.print("\nDemo complete. Review files in the demo/outputs directory for exports.\n")


if __name__ == "__main__":
    try:
        run_demo()
    except KeyboardInterrupt:
        console.print("\nDemo interrupted by user")
    except Exception:
        console.print_exception()

