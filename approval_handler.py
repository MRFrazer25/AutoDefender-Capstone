"""Approval prompts for security actions.

Handles user approval workflows, especially for Suricata rule generation.
"""

import logging
from typing import Optional, Callable
from models import Action
from rich.console import Console
from rich.prompt import Confirm
from rich.panel import Panel

logger = logging.getLogger(__name__)


class ApprovalHandler:
    """Handles approval workflows for security actions."""
    
    def __init__(self, console: Optional[Console] = None):
        """
        Initialize approval handler.
        
        Args:
            console: Rich Console instance for display
        """
        self.console = console or Console()
        self.approval_callback: Optional[Callable] = None
        self.rejection_callback: Optional[Callable] = None
    
    def set_approval_callback(self, callback: Callable):
        """
        Set callback to be called when action is approved.
        
        Args:
            callback: Function to call with approved action
        """
        self.approval_callback = callback
    
    def set_rejection_callback(self, callback: Callable):
        """
        Set callback to be called when action is rejected.
        
        Args:
            callback: Function to call with rejected action
        """
        self.rejection_callback = callback
    
    def prompt_approval(self, action: Action, threat_description: Optional[str] = None) -> bool:
        """
        Display approval prompt for an action.
        
        Args:
            action: Action requiring approval
            threat_description: Optional threat description for context
            
        Returns:
            True if approved, False if rejected
        """
        try:
            # Build prompt message
            message = self._build_prompt_message(action, threat_description)
            
            # Display in panel
            self.console.print()
            self.console.print(Panel(
                message,
                title="[bold yellow]Agentic Action Requires Approval[/bold yellow]",
                border_style="yellow"
            ))
            
            # Prompt for approval
            approved = Confirm.ask(
                "[bold]Approve this action?[/bold]",
                default=False
            )
            
            # Handle response
            if approved:
                self.console.print("[green][OK][/green] Action approved")
                if self.approval_callback:
                    self.approval_callback(action)
                return True
            else:
                self.console.print("[red][X][/red] Action rejected")
                if self.rejection_callback:
                    self.rejection_callback(action)
                return False
                
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Approval cancelled by user[/yellow]")
            if self.rejection_callback:
                self.rejection_callback(action)
            return False
        except Exception as e:
            logger.error(f"Error in approval prompt: {e}")
            return False
    
    def _build_prompt_message(self, action: Action, threat_description: Optional[str] = None) -> str:
        """Build approval prompt message."""
        lines = []
        
        # Action info
        lines.append(f"[bold]Action Type:[/bold] {action.action_type}")
        if action.action_type == 'SURICATA_DROP_RULE':
            lines.append("[bold]Proposed Rule:[/bold]")
            lines.append(f"[green]{action.description}[/green]")
        else:
            lines.append(f"[bold]Description:[/bold] {action.description}")
        
        # Threat context
        if threat_description:
            lines.append(f"\n[bold]Threat:[/bold] {threat_description}")
        
        # Timestamp
        lines.append(f"\n[dim]Requested at: {action.timestamp.strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        
        return "\n".join(lines)
    
    def prompt_batch_approval(self, actions: list[Action]) -> dict[int, bool]:
        """
        Prompt for approval of multiple actions with batch options.
        
        Args:
            actions: List of actions requiring approval
            
        Returns:
            Dictionary mapping action IDs to approval status
        """
        results = {}
        
        if not actions:
            return results
        
        # If 3+ actions, offer batch approval option
        if len(actions) >= 3:
            self.console.print(f"\n[bold cyan]{len(actions)} actions require approval[/bold cyan]")
            self.console.print("\n[dim]Options:[/dim]")
            self.console.print("  [green]1.[/green] Review each action individually")
            self.console.print("  [green]2.[/green] Approve all actions")
            self.console.print("  [green]3.[/green] Reject all actions")
            
            try:
                choice = self.console.input("\n[bold]Select option (1-3):[/bold] ").strip()
                
                if choice == "2":
                    # Approve all
                    self.console.print("[green][OK][/green] Approving all actions...")
                    for action in actions:
                        if self.approval_callback:
                            self.approval_callback(action)
                        if action.id:
                            results[action.id] = True
                    return results
                elif choice == "3":
                    # Reject all
                    self.console.print("[red][X][/red] Rejecting all actions...")
                    for action in actions:
                        if self.rejection_callback:
                            self.rejection_callback(action)
                        if action.id:
                            results[action.id] = False
                    return results
                # Fall through to individual review for choice "1" or invalid choice
                
            except Exception as e:
                logger.warning(f"Error in batch approval prompt: {e}")
                # Fall through to individual review
        
        # Individual review
        self.console.print(f"\n[bold cyan]Reviewing {len(actions)} action(s) individually:[/bold cyan]")
        
        for i, action in enumerate(actions, 1):
            self.console.print(f"\n[bold]Action {i}/{len(actions)}:[/bold]")
            approved = self.prompt_approval(action)
            if action.id:
                results[action.id] = approved
        
        return results
    
    def display_pending_actions(self, actions: list[Action]):
        """
        Display list of pending actions.
        
        Args:
            actions: List of pending actions
        """
        if not actions:
            self.console.print("[dim]No pending actions[/dim]")
            return
        
        self.console.print(f"\n[bold cyan]Pending Actions ({len(actions)}):[/bold cyan]")
        
        for i, action in enumerate(actions, 1):
            status_color = {
                'RECOMMENDED': 'yellow',
                'APPROVED': 'green',
                'REJECTED': 'red',
                'EXECUTED': 'blue'
            }.get(action.status, 'white')
            
            self.console.print(
                f"  {i}. [{status_color}]{action.status}[/{status_color}] "
                f"- {action.action_type}: {action.description[:80]}"
            )

