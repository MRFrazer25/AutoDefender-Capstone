#!/usr/bin/env python3
"""AutoDefender - AI-powered Suricata log analysis.

CLI features:
- Real-time monitoring
- Historical analysis
- Threat filtering and search
- Export to CSV/JSON
- IP whitelist/blacklist
"""

import argparse
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel

from config import Config
from monitor import RealTimeMonitor
from analyzer import HistoricalAnalyzer
from database import Database
from filter import ThreatFilter
from exporter import Exporter
from ip_manager import IPManager
from approval_handler import ApprovalHandler
from ui.dashboard import Dashboard
from utils.path_utils import sanitize_path

# Configure logging (can be overridden via --debug flag)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

console = Console()


def setup_signal_handlers(monitor: RealTimeMonitor, analyzer: HistoricalAnalyzer = None):
    """Setup signal handlers for graceful shutdown."""
    def signal_handler(_sig, _frame):
        console.print("\n[yellow]Shutting down...[/yellow]")
        if monitor:
            monitor.stop()
        if analyzer:
            analyzer.close()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def monitor_mode(config: Config, log_path: str, ip_manager: Optional[IPManager] = None,
                 read_from_start: bool = False):
    """Run in real-time monitoring mode."""
    console.print(Panel.fit(
        "[bold cyan]AutoDefender - Real-Time Monitoring Mode[/bold cyan]",
        border_style="cyan"
    ))
    
    # Validate log file exists
    log_file = Path(log_path)
    if not log_file.exists():
        console.print(f"[red]Error:[/red] Log file not found: {log_path}")
        console.print("[yellow]Hint:[/yellow] Make sure the path is correct and the file exists")
        sys.exit(1)
    log_stat = log_file.stat()
    last_modified = datetime.fromtimestamp(log_stat.st_mtime)
    console.print(
        f"[dim]Log file: {log_file} (size: {log_stat.st_size} bytes | "
        f"last modified: {last_modified})[/dim]"
    )
    if log_stat.st_size == 0:
        console.print(
            "[yellow]Warning:[/yellow] Log file is empty. "
            "Suricata may not be writing events yet."
        )
    
    if not log_file.is_file():
        console.print(f"[red]Error:[/red] Path is not a file: {log_path}")
        sys.exit(1)
    
    # Initialize components
    try:
        database = Database(config.db_path)
    except Exception as e:
        console.print(f"[red]Error:[/red] Failed to initialize database: {e}")
        console.print("[yellow]Hint:[/yellow] Check database file permissions and disk space")
        sys.exit(1)
    
    try:
        monitor = RealTimeMonitor(
            log_path,
            config,
            ip_manager=ip_manager,
            read_from_start=read_from_start
        )
    except Exception as e:
        console.print(f"[red]Error:[/red] Failed to initialize monitor: {e}")
        console.print("[yellow]Hint:[/yellow] Check log file permissions and format")
        database.close()
        sys.exit(1)
    
    # Setup signal handlers
    setup_signal_handlers(monitor)
    
    # Callback for when threats are detected
    def on_threat_detected(threat, _actions):
        """Called when a threat is detected."""
        console.print(f"[red][!] Threat detected:[/red] {threat.description}")
    
    monitor.set_threat_callback(on_threat_detected)
    
    dashboard = None
    dashboard_thread = None
    
    # Start monitoring
    try:
        monitor.start()
        
        # Create dashboard
        dashboard = Dashboard(database, console)
        
        # Determine manual approval mode
        suricata_enabled = getattr(config, 'SURICATA_ENABLED', False) and bool(getattr(monitor, 'suricata_manager', None))
        manual_approval_mode = suricata_enabled and not getattr(config, 'AUTO_APPROVE_SURICATA', False)
        
        # Update callback for dashboard
        def update_callback():
            threats = database.get_threats(limit=config.MAX_DISPLAYED_THREATS)
            stats = database.get_stats()
            monitor_stats = monitor.get_stats()
            pending_actions = monitor.get_pending_suricata_actions() if hasattr(monitor, 'get_pending_suricata_actions') else []
            
            # Get restart status and health info
            restart_needed = monitor_stats.get('needs_restart', False)
            health_info = monitor_stats.get('suricata_health')
            
            return threats, stats, monitor_stats, pending_actions, restart_needed, health_info
        
        # Start dashboard in background thread so we can process approvals concurrently
        def dashboard_runner():
            try:
                dashboard.run_live(
                    update_callback,
                    refresh_rate=config.REFRESH_RATE,
                    screen=not manual_approval_mode  # avoid alternate screen when prompting for approvals
                )
            except Exception as e:
                logger.exception(f"Dashboard encountered an error: {e}")
        
        dashboard_thread = threading.Thread(target=dashboard_runner, daemon=True)
        dashboard_thread.start()
        
        # Manual approval workflow
        if manual_approval_mode:
            approval_handler = ApprovalHandler(console)
            approval_handler.set_approval_callback(monitor.approve_suricata_action)
            approval_handler.set_rejection_callback(monitor.reject_suricata_action)
            
            console.print("[cyan]Suricata auto-approval disabled. Manual approval prompts will appear for AI-generated rules.[/cyan]")
            
            while monitor.is_running():
                # Wait until at least one pending action is available or timeout to check running state
                monitor.wait_for_pending_actions(timeout=0.5)
                if not monitor.is_running():
                    break
                
                # Check if we have multiple pending actions (3+) for batch approval
                pending = monitor.get_pending_suricata_actions()
                if len(pending) >= 3:
                    console.print(f"\n[cyan]{len(pending)} pending actions detected[/cyan]")
                    approval_handler.prompt_batch_approval(pending)
                else:
                    # Process individual actions
                    while True:
                        action = monitor.peek_pending_suricata_action()
                        if not action:
                            break
                        
                        threat_description = None
                        if action.threat_id:
                            threat = database.get_threat(action.threat_id)
                            threat_description = threat.description if threat else None
                        
                        approval_handler.prompt_approval(action, threat_description)
        else:
            # Keep main thread alive while dashboard renders
            while monitor.is_running():
                time.sleep(0.5)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping monitor...[/yellow]")
    finally:
        monitor.stop()
        if dashboard:
            try:
                dashboard.stop()
            except Exception:
                pass
        if dashboard_thread and dashboard_thread.is_alive():
            dashboard_thread.join(timeout=1)
        database.close()


def analyze_mode(config: Config, file_paths: list, 
                severity_filter: Optional[list] = None,
                search_query: Optional[str] = None,
                export_path: Optional[str] = None,
                export_format: str = 'json',
                ai_severities: Optional[list] = None,
                ip_manager: Optional[IPManager] = None):
    """Run in historical analysis mode with filtering and export."""
    console.print(Panel.fit(
        "[bold cyan]AutoDefender - Historical Analysis Mode[/bold cyan]",
        border_style="cyan"
    ))
    
    # Validate at least one file exists
    valid_paths = []
    for path_str in file_paths:
        path = Path(path_str)
        if not path.exists():
            console.print(f"[yellow]Warning:[/yellow] Path not found: {path_str}")
            continue
        valid_paths.append(path_str)
    
    if not valid_paths:
        console.print("[red]Error:[/red] No valid file or directory paths provided")
        console.print("[yellow]Hint:[/yellow] Check that the paths exist and are accessible")
        sys.exit(1)
    
    # Initialize analyzer
    try:
        analyzer = HistoricalAnalyzer(config, ip_manager=ip_manager)
    except Exception as e:
        console.print(f"[red]Error:[/red] Failed to initialize analyzer: {e}")
        console.print("[yellow]Hint:[/yellow] Check database permissions and configuration")
        sys.exit(1)
    
    threat_filter = ThreatFilter()
    
    # Determine if paths are files or directories
    paths_to_analyze = []
    for path_str in valid_paths:
        path = Path(path_str)
        if path.is_file():
            paths_to_analyze.append(str(path))
        elif path.is_dir():
            try:
                # Analyze all JSON files in directory (results stored in database)
                _ = analyzer.analyze_directory(str(path), generate_explanations=False)
                console.print(f"[green][OK][/green] Analyzed directory: {path}")
            except Exception as e:
                console.print(f"[red][X][/red] Error analyzing directory {path}: {e}")
                logger.exception(f"Error analyzing directory {path}")
    
    # Analyze files
    all_threats = []
    if paths_to_analyze:
        console.print(f"[cyan]Analyzing {len(paths_to_analyze)} file(s)...[/cyan]")
        try:
            all_threats = analyzer.analyze_files(paths_to_analyze, generate_explanations=False)
            console.print(f"[green][OK][/green] Analysis complete: {len(all_threats)} threats detected")
        except Exception as e:
            console.print(f"[red]Error:[/red] Failed to analyze files: {e}")
            console.print("[yellow]Hint:[/yellow] Check file permissions and JSON format")
            analyzer.close()
            sys.exit(1)
    
    # Get all threats from database if we have any
    if not all_threats:
        all_threats = analyzer.database.get_threats(limit=1000)
    
    # Apply filters
    filtered_threats = all_threats
    
    if severity_filter:
        filtered_threats = threat_filter.filter_by_severity_list(filtered_threats, severity_filter)
        console.print(f"[cyan]Filtered by severity: {', '.join(severity_filter)} - {len(filtered_threats)} threats[/cyan]")
    
    if search_query:
        filtered_threats = threat_filter.search_threats(filtered_threats, search_query)
        console.print(f"[cyan]Search results for '{search_query}': {len(filtered_threats)} threats[/cyan]")
    
    # Generate AI explanations for selected threats
    if ai_severities:
        console.print(f"[cyan]Generating AI explanations for {', '.join(ai_severities)} severity threats...[/cyan]")
        threats_to_analyze = threat_filter.filter_by_severity_list(filtered_threats, ai_severities)
        try:
            analyzer.generate_ai_explanations(threats_to_analyze, use_ai=True)
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Some AI explanations failed: {e}")
            console.print("[yellow]Hint:[/yellow] Make sure Ollama is running and the model is available")
        # Update filtered threats with AI explanations
        for threat in filtered_threats:
            if threat.id and threat.severity in [s.upper() for s in ai_severities]:
                updated = analyzer.database.get_threat(threat.id)
                if updated:
                    threat.ai_explanation = updated.ai_explanation
    elif len(filtered_threats) <= 20:
        # If few threats, analyze all with AI
        console.print(f"[cyan]Generating AI explanations for all {len(filtered_threats)} threats...[/cyan]")
        try:
            analyzer.generate_ai_explanations(filtered_threats, use_ai=True)
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Some AI explanations failed: {e}")
            console.print("[yellow]Hint:[/yellow] Make sure Ollama is running and the model is available")
        # Refresh threats with AI explanations
        for i, threat in enumerate(filtered_threats):
            if threat.id:
                updated = analyzer.database.get_threat(threat.id)
                if updated:
                    filtered_threats[i] = updated
    
    # Generate and display report
    summary = analyzer.get_summary()
    
    console.print()
    console.print(Panel(summary, title="[bold]Analysis Report[/bold]", border_style="green"))
    
    # Export if requested
    if export_path:
        try:
            # Sanitize the export path to prevent path traversal attacks
            # Use standard library functions that static analysis tools recognize
            # First, validate using our custom sanitize_path function
            validated_path_obj = sanitize_path(export_path)
            # Additional validation using os.path for explicit normalization
            # This ensures the path is absolute and doesn't contain traversal sequences
            abs_path = os.path.abspath(str(validated_path_obj))
            normalized_path = os.path.normpath(abs_path)
            # Verify the normalized path doesn't contain traversal sequences
            # Note: sanitize_path() already validated, but this provides defense in depth
            if ".." in normalized_path:
                raise ValueError("Path contains traversal sequences after normalization")
            # Use the normalized absolute path - this is safe for file operations
            safe_output_path = normalized_path
            exporter = Exporter(analyzer.database)
            if export_format.lower() == 'csv':
                success = exporter.export_threats_csv(filtered_threats, safe_output_path)
            else:
                # Path is validated: sanitize_path() checks for ".." and resolves to absolute,
                # then os.path.abspath() and os.path.normpath() further normalize it.
                # The explicit ".." check above ensures no traversal sequences remain.
                success = exporter.export_threats_json(filtered_threats, safe_output_path)
            
            if success:
                console.print(f"[green][OK][/green] Exported {len(filtered_threats)} threats to {safe_output_path}")
            else:
                console.print("[red][X][/red] Failed to export threats")
                console.print("[yellow]Hint:[/yellow] Check file permissions and disk space")
        except ValueError as e:
            console.print(f"[red]Error:[/red] Invalid export path: {e}")
            console.print("[yellow]Hint:[/yellow] Path contains invalid characters or traversal sequences")
        except Exception as e:
            console.print(f"[red]Error:[/red] Export failed: {e}")
            console.print("[yellow]Hint:[/yellow] Check file path and permissions")
    
    # Close analyzer
    analyzer.close()


def both_mode(config: Config, monitor_path: str, analyze_paths: list,
              ip_manager: Optional[IPManager] = None, read_from_start: bool = False):
    """Run both real-time monitoring and historical analysis."""
    console.print(Panel.fit(
        "[bold cyan]AutoDefender - Combined Mode[/bold cyan]",
        border_style="cyan"
    ))
    
    # Start historical analysis in background
    if analyze_paths:
        console.print("[cyan]Starting historical analysis...[/cyan]")
        try:
            analyzer = HistoricalAnalyzer(config, ip_manager=ip_manager)
        except Exception as e:
            console.print(f"[red]Error:[/red] Failed to initialize analyzer: {e}")
            console.print("[yellow]Hint:[/yellow] Check database permissions and configuration")
            sys.exit(1)
        
        # Analyze in background thread
        def analyze_background():
            try:
                for path_str in analyze_paths:
                    path = Path(path_str)
                    if path.is_dir():
                        analyzer.analyze_directory(str(path), generate_explanations=True)
                    elif path.is_file():
                        analyzer.analyze_file(str(path), generate_explanations=True)
                console.print("[green][OK][/green] Historical analysis complete")
            except Exception as e:
                console.print(f"[red]Error in background analysis:[/red] {e}")
                logger.exception("Error in background analysis")
        
        analysis_thread = threading.Thread(target=analyze_background, daemon=True)
        analysis_thread.start()
    
    # Start real-time monitoring
    monitor_mode(config, monitor_path, ip_manager, read_from_start=read_from_start)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AutoDefender - AI-powered security tool for Suricata log analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Real-time monitoring
  python main.py --monitor /var/log/suricata/eve.json
  
  # Historical analysis
  python main.py --analyze /path/to/log1.json /path/to/log2.json
  
  # Use a specific Ollama model
  python main.py --analyze logs.json --model llama3
  
  # Both modes
  python main.py --both /var/log/suricata/eve.json /backup/logs/
        """
    )
    
    parser.add_argument(
        '--monitor',
        type=str,
        metavar='PATH',
        help='Path to Suricata eve.json file for real-time monitoring'
    )
    
    parser.add_argument(
        '--analyze',
        type=str,
        nargs='+',
        metavar='PATH',
        help='Path(s) to log file(s) or directory for historical analysis'
    )
    
    parser.add_argument(
        '--filter-severity',
        type=str,
        nargs='+',
        metavar='SEVERITY',
        choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        help='Filter threats by severity level(s)'
    )
    
    parser.add_argument(
        '--search',
        type=str,
        metavar='QUERY',
        help='Search threats by description, IP, or event type'
    )
    
    parser.add_argument(
        '--export',
        type=str,
        metavar='PATH',
        help='Export filtered threats to file (use .csv or .json extension)'
    )
    
    parser.add_argument(
        '--ai-severities',
        type=str,
        nargs='+',
        metavar='SEVERITY',
        choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        help='Generate AI explanations for specified severity levels (default: HIGH/CRITICAL)'
    )
    
    parser.add_argument(
        '--whitelist',
        type=str,
        metavar='IP',
        help='Add IP address to whitelist (threats from this IP will be ignored)'
    )
    
    parser.add_argument(
        '--blacklist',
        type=str,
        metavar='IP',
        help='Add IP address to blacklist (threats from this IP will be auto-blocked)'
    )
    
    parser.add_argument(
        '--remove-whitelist',
        type=str,
        metavar='IP',
        help='Remove IP address from whitelist'
    )
    
    parser.add_argument(
        '--remove-blacklist',
        type=str,
        metavar='IP',
        help='Remove IP address from blacklist'
    )
    
    parser.add_argument(
        '--list-ips',
        action='store_true',
        help='List all whitelisted and blacklisted IPs'
    )
    
    parser.add_argument(
        '--both',
        type=str,
        nargs='+',
        metavar='PATH',
        help='Run both modes: first path is monitor file, rest are analyze paths'
    )
    
    parser.add_argument(
        '--read-log-from-start',
        action='store_true',
        help='When monitoring, read the entire log file from the beginning instead of tailing new entries'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging output'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        metavar='FILE',
        help='Path to configuration file (optional)'
    )
    
    parser.add_argument(
        '--db',
        type=str,
        metavar='PATH',
        help='Path to database file (default: autodefender.db)'
    )
    
    parser.add_argument(
        '--model',
        type=str,
        metavar='NAME',
        help='Ollama model to use for AI explanations (required for AI features)'
    )
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled via --debug flag")
    
    # Load configuration
    config = Config(args.config) if args.config else Config.get_default()
    if args.db:
        config.db_path = args.db
    
    # Override Ollama model if specified
    if args.model:
        config.ollama_model = args.model
        logger.info(f"Using Ollama model: {args.model}")
    
    # Handle IP list management commands first
    ip_manager = IPManager()
    if args.whitelist:
        if ip_manager.add_whitelist(args.whitelist):
            console.print(f"[green][OK][/green] Added {args.whitelist} to whitelist")
        else:
            console.print(f"[yellow][!][/yellow] {args.whitelist} is already whitelisted")
        sys.exit(0)
    
    if args.blacklist:
        if ip_manager.add_blacklist(args.blacklist):
            console.print(f"[green][OK][/green] Added {args.blacklist} to blacklist")
        else:
            console.print(f"[yellow][!][/yellow] {args.blacklist} is already blacklisted")
        sys.exit(0)
    
    if args.remove_whitelist:
        if ip_manager.remove_whitelist(args.remove_whitelist):
            console.print(f"[green][OK][/green] Removed {args.remove_whitelist} from whitelist")
        else:
            console.print(f"[red][X][/red] {args.remove_whitelist} not found in whitelist")
        sys.exit(0)
    
    if args.remove_blacklist:
        if ip_manager.remove_blacklist(args.remove_blacklist):
            console.print(f"[green][OK][/green] Removed {args.remove_blacklist} from blacklist")
        else:
            console.print(f"[red][X][/red] {args.remove_blacklist} not found in blacklist")
        sys.exit(0)
    
    if args.list_ips:
        whitelist = ip_manager.get_whitelist()
        blacklist = ip_manager.get_blacklist()
        console.print("\n[bold]IP Lists[/bold]")
        console.print(f"\n[green]Whitelist ({len(whitelist)} IPs):[/green]")
        if whitelist:
            for ip in whitelist:
                console.print(f"  {ip}")
        else:
            console.print("  (empty)")
        console.print(f"\n[red]Blacklist ({len(blacklist)} IPs):[/red]")
        if blacklist:
            for ip in blacklist:
                console.print(f"  {ip}")
        else:
            console.print("  (empty)")
        sys.exit(0)
    
    # Validate arguments
    if not any([args.monitor, args.analyze, args.both]):
        parser.print_help()
        console.print("\n[red]Error:[/red] You must specify --monitor, --analyze, or --both")
        sys.exit(1)
    
    # Run appropriate mode
    try:
        if args.both:
            if len(args.both) < 2:
                console.print("[red]Error:[/red] --both requires at least 2 paths (monitor path + analyze path(s))")
                sys.exit(1)
            both_mode(
                config,
                args.both[0],
                args.both[1:],
                ip_manager,
                read_from_start=args.read_log_from_start
            )
        elif args.monitor:
            monitor_mode(
                config,
                args.monitor,
                ip_manager,
                read_from_start=args.read_log_from_start
            )
        elif args.analyze:
            # Determine export format from file extension
            export_format = 'json'
            if args.export:
                export_path = Path(args.export)
                if export_path.suffix.lower() == '.csv':
                    export_format = 'csv'
                elif export_path.suffix.lower() == '.json':
                    export_format = 'json'
            
            analyze_mode(
                config, 
                args.analyze,
                severity_filter=args.filter_severity,
                search_query=args.search,
                export_path=args.export,
                export_format=export_format,
                ai_severities=args.ai_severities,
                ip_manager=ip_manager
            )
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        logger.exception("Unhandled exception")
        sys.exit(1)


if __name__ == "__main__":
    main()

