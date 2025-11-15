"""Terminal dashboard using Rich library.

Real-time display of threats, stats, and monitoring status.
"""

import logging
from datetime import datetime
from typing import List, Optional
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from models import Threat, Action, DetectionStats
from database import Database

logger = logging.getLogger(__name__)


class ThreatPanel:
    """Panel for displaying threats."""
    
    SEVERITY_COLORS = {
        'CRITICAL': 'bold red',
        'HIGH': 'red',
        'MEDIUM': 'yellow',
        'LOW': 'green'
    }
    
    def render(self, threats: List[Threat], max_items: int = 20) -> Panel:
        """Render the threats panel."""
        table = Table(show_header=True, header_style="bold magenta", box=None)
        table.add_column("Time", style="dim", width=12)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=15)
        table.add_column("Source IP", width=18)
        table.add_column("Description", ratio=2)
        
        sorted_threats = sorted(threats, key=lambda t: t.timestamp, reverse=True)[:max_items]
        
        for threat in sorted_threats:
            time_str = threat.timestamp.strftime("%H:%M:%S")
            severity_style = self.SEVERITY_COLORS.get(threat.severity, 'white')
            
            desc = threat.description
            if len(desc) > 50:
                desc = desc[:47] + "..."
            
            source_ip = threat.source_ip or "N/A"
            if len(source_ip) > 16:
                source_ip = source_ip[:13] + "..."
            
            table.add_row(
                time_str,
                Text(threat.severity, style=severity_style),
                threat.event_type[:15],
                source_ip,
                desc
            )
        
        if not threats:
            table.add_row("", "", "", "", "No threats detected", style="dim")
        
        return Panel(
            table,
            title="[bold]Threats Detected[/bold]",
            border_style="blue"
        )
    
    def render_detailed(self, threat: Threat) -> Panel:
        """Render detailed threat information."""
        content = Text()
        
        content.append("Threat Details\n", style="bold")
        content.append(f"ID: {threat.id}\n", style="dim")
        content.append(f"Timestamp: {threat.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
        content.append(f"Type: {threat.event_type}\n")
        content.append("Severity: ", style="bold")
        content.append(f"{threat.severity}\n", style=self.SEVERITY_COLORS.get(threat.severity, 'white'))
        content.append(f"Source IP: {threat.source_ip or 'Unknown'}\n")
        content.append(f"Destination IP: {threat.dest_ip or 'Unknown'}\n")
        if threat.dest_port:
            content.append(f"Destination Port: {threat.dest_port}\n")
        content.append(f"\nDescription:\n{threat.description}\n", style="dim")
        
        if threat.ai_explanation:
            content.append(f"\nAI Explanation:\n{threat.ai_explanation}\n", style="cyan")
        
        return Panel(
            content,
            title=f"[bold]Threat #{threat.id}[/bold]",
            border_style=self.SEVERITY_COLORS.get(threat.severity, 'white')
        )


class StatsPanel:
    """Panel for displaying statistics."""
    
    def render(self, stats: DetectionStats) -> Panel:
        """Render the statistics panel."""
        content = Text()
        
        content.append("Detection Statistics\n", style="bold")
        content.append(f"Total Threats: {stats.total_threats}\n\n", style="bold cyan")
        
        content.append("By Severity:\n", style="bold")
        content.append("  Critical: ", style="bold red")
        content.append(f"{stats.by_severity.get('CRITICAL', 0)}\n")
        content.append("  High: ", style="red")
        content.append(f"{stats.by_severity.get('HIGH', 0)}\n")
        content.append("  Medium: ", style="yellow")
        content.append(f"{stats.by_severity.get('MEDIUM', 0)}\n")
        content.append("  Low: ", style="green")
        content.append(f"{stats.by_severity.get('LOW', 0)}\n\n")
        
        if stats.by_type:
            content.append("By Type:\n", style="bold")
            for threat_type, count in sorted(stats.by_type.items(), key=lambda x: x[1], reverse=True)[:5]:
                content.append(f"  {threat_type}: {count}\n", style="dim")
            content.append("\n")
        
        if stats.top_sources:
            content.append("Top Sources:\n", style="bold")
            for ip, count in stats.top_sources[:5]:
                content.append(f"  {ip}: {count}\n", style="dim")
        
        return Panel(
            content,
            title="[bold]Statistics[/bold]",
            border_style="green"
        )
    
    def render_table(self, stats: DetectionStats) -> Panel:
        """Render statistics as a table."""
        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")
        
        table.add_row("Total Threats", str(stats.total_threats))
        table.add_row("Critical", str(stats.by_severity.get('CRITICAL', 0)), style="bold red")
        table.add_row("High", str(stats.by_severity.get('HIGH', 0)), style="red")
        table.add_row("Medium", str(stats.by_severity.get('MEDIUM', 0)), style="yellow")
        table.add_row("Low", str(stats.by_severity.get('LOW', 0)), style="green")
        
        return Panel(
            table,
            title="[bold]Statistics[/bold]",
            border_style="green"
        )


class Dashboard:
    """Main terminal dashboard."""
    
    def __init__(self, database: Database, console: Optional[Console] = None):
        """Initialize the dashboard."""
        self.database = database
        self.console = console or Console()
        self.running = False
    
    def create_layout(self, show_pending_actions: bool = False, show_restart_banner: bool = False) -> Layout:
        """Create the dashboard layout."""
        layout = Layout()
        
        # Build layout sections based on what needs to be shown
        sections = [
            ("header", 3),
        ]
        
        if show_restart_banner:
            sections.append(("restart_banner", 4))
        
        if show_pending_actions:
            sections.append(("pending_actions", 8))
        
        sections.append(("main", None))  # Main gets remaining space
        sections.append(("footer", 3))
        
        # Split layout
        layout_args = []
        for name, size in sections:
            if size:
                layout_args.append(Layout(name=name, size=size))
            else:
                layout_args.append(Layout(name=name))
        
        layout.split_column(*layout_args)
        
        layout["main"].split_row(
            Layout(name="threats", ratio=2),
            Layout(name="stats", ratio=1)
        )
        
        return layout
    
    def render_header(self) -> Panel:
        """Render the header panel."""
        header_text = Text("AutoDefender - AI Security Monitor", style="bold cyan")
        header_text.append(f" | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style="dim")
        return Panel(header_text, border_style="cyan")
    
    def render_footer(self, stats: dict) -> Panel:
        """Render the footer panel."""
        footer_text = Text()
        footer_text.append("Status: ", style="dim")
        footer_text.append("RUNNING" if stats.get('running', False) else "STOPPED", 
                          style="green" if stats.get('running', False) else "red")
        footer_text.append(" | ", style="dim")
        footer_text.append(f"Events: {stats.get('events_processed', 0)}", style="dim")
        footer_text.append(" | ", style="dim")
        footer_text.append(f"Threats: {stats.get('threats_detected', 0)}", style="dim")
        footer_text.append(" | ", style="dim")
        footer_text.append("Press Ctrl+C to exit", style="dim yellow")
        
        return Panel(footer_text, border_style="dim")
    
    def render_threats_panel(self, threats: List[Threat], max_items: int = 20) -> Panel:
        """Render the threats panel."""
        threat_panel = ThreatPanel()
        return threat_panel.render(threats, max_items)
    
    def render_stats_panel(self, stats: DetectionStats) -> Panel:
        """Render the statistics panel."""
        stats_panel = StatsPanel()
        return stats_panel.render(stats)
    
    def render_pending_actions_panel(self, pending_actions: List[Action]) -> Panel:
        """Render the pending Suricata actions panel."""
        if not pending_actions:
            content = Text("No pending actions", style="dim")
        else:
            content = Text()
            content.append(f"{len(pending_actions)} Pending Suricata Action(s)\n\n", style="bold yellow")
            
            for i, action in enumerate(pending_actions[:5], 1):  # Show max 5
                # Action type and status
                content.append(f"{i}. ", style="bold")
                content.append(f"{action.action_type}", style="cyan")
                content.append(f" [{action.status}]\n", style="yellow")
                
                # Description (truncated)
                desc = action.description[:80] + "..." if len(action.description) > 80 else action.description
                content.append(f"   {desc}\n", style="dim")
                
                # Timestamp
                content.append(f"   {action.timestamp.strftime('%H:%M:%S')}\n", style="dim")
            
            if len(pending_actions) > 5:
                content.append(f"\n...and {len(pending_actions) - 5} more", style="dim")
            
            content.append("\n[dim]Note: Use CLI to approve/reject pending actions[/dim]")
        
        return Panel(content, title="[bold yellow][!] Pending Agentic Actions[/bold yellow]", border_style="yellow")
    
    def render_restart_banner(self, health_info: Optional[dict] = None) -> Panel:
        """Render restart notification banner."""
        content = Text()
        content.append("[!] Suricata Restart Recommended\n\n", style="bold yellow")
        content.append("New Suricata rules have been added. ", style="yellow")
        content.append("Restart Suricata to apply changes.\n\n", style="yellow")
        
        if health_info:
            content.append("Rules Directory Health: ", style="dim")
            status_style = {
                'healthy': 'green',
                'warning': 'yellow',
                'error': 'red'
            }.get(health_info.get('status', 'unknown'), 'white')
            content.append(f"{health_info.get('status', 'unknown').upper()}\n", style=status_style)
            
            if health_info.get('total_rules'):
                content.append(f"Active Rules: {health_info['total_rules']}\n", style="dim")
            if health_info.get('issues'):
                content.append(f"Issues: {', '.join(health_info['issues'][:2])}\n", style="dim red")
        
        return Panel(content, title="[bold yellow]System Notification[/bold yellow]", border_style="yellow")
    
    def update(self, threats: List[Threat], stats: DetectionStats, monitor_stats: dict, 
               pending_actions: Optional[List[Action]] = None, restart_needed: bool = False,
               health_info: Optional[dict] = None):
        """Update the dashboard with new data."""
        has_pending = pending_actions and len(pending_actions) > 0
        layout = self.create_layout(show_pending_actions=has_pending, show_restart_banner=restart_needed)
        
        # Header
        layout["header"].update(self.render_header())
        
        # Restart banner (if needed)
        if restart_needed:
            layout["restart_banner"].update(self.render_restart_banner(health_info))
        
        # Pending actions panel (if any)
        if has_pending:
            layout["pending_actions"].update(self.render_pending_actions_panel(pending_actions))
        
        # Threats panel
        layout["threats"].update(self.render_threats_panel(threats))
        
        # Stats panel
        layout["stats"].update(self.render_stats_panel(stats))
        
        # Footer
        layout["footer"].update(self.render_footer(monitor_stats))
        
        return layout
    
    def run_live(self, update_callback, refresh_rate: float = 1.0, screen: bool = True):
        """
        Run the dashboard with live updates.
        
        Args:
            update_callback: Function that returns (threats, stats, monitor_stats[, pending_actions])
            refresh_rate: Seconds between updates
            screen: Whether to use rich's alternate screen mode
        """
        self.running = True
        
        def generate_layout():
            result = update_callback()
            # Handle various return tuple sizes
            if len(result) == 6:
                threats, stats, monitor_stats, pending_actions, restart_needed, health_info = result
            elif len(result) == 5:
                threats, stats, monitor_stats, pending_actions, restart_needed = result
                health_info = None
            elif len(result) == 4:
                threats, stats, monitor_stats, pending_actions = result
                restart_needed = False
                health_info = None
            else:
                threats, stats, monitor_stats = result
                pending_actions = []
                restart_needed = False
                health_info = None
            return self.update(threats, stats, monitor_stats, pending_actions, restart_needed, health_info)
        
        try:
            with Live(generate_layout(), refresh_per_second=1/refresh_rate, screen=screen) as live:
                while self.running:
                    live.update(generate_layout())
                    import time
                    time.sleep(refresh_rate)
        except KeyboardInterrupt:
            self.running = False
            logger.info("Dashboard stopped by user")
    
    def stop(self):
        """Stop the dashboard."""
        self.running = False

