"""Multi-source log aggregation for monitoring multiple Suricata instances."""

import logging
from typing import List, Callable, Optional
from pathlib import Path
from monitor import RealTimeMonitor
from models import Threat, Action
from database import Database
from threading import Lock

logger = logging.getLogger(__name__)


class MultiSourceMonitor:
    """
    Aggregates monitoring from multiple log sources.
    
    Useful for:
    - Monitoring multiple Suricata instances
    - Processing archived logs alongside live feeds
    - Distributed sensor deployments
    """
    
    def __init__(
        self,
        log_paths: List[str],
        database: Database,
        threat_callback: Optional[Callable] = None,
        config=None,
        start_from_beginning: bool = False,
    ):
        """
        Initialize multi-source monitor.
        
        Args:
            log_paths: List of eve.json file paths to monitor
            database: Shared database instance
            threat_callback: Optional callback for each detected threat
            config: Configuration object
            start_from_beginning: Whether to process existing log entries
        """
        self.log_paths = [Path(p) for p in log_paths]
        self.database = database
        self.config = config
        self.start_from_beginning = start_from_beginning
        
        # Shared callback wrapper to aggregate stats
        self._stats_lock = Lock()
        self._total_events = 0
        self._total_threats = 0
        self._threat_callback = threat_callback
        
        # Create a monitor for each log source
        self.monitors: List[RealTimeMonitor] = []
        for log_path in self.log_paths:
            monitor = RealTimeMonitor(
                log_path=str(log_path),
                database=database,
                threat_callback=self._wrapped_callback,
                config=config,
                start_from_beginning=start_from_beginning,
            )
            self.monitors.append(monitor)
            logger.info(f"Initialized monitor for {log_path}")
    
    def _wrapped_callback(self, threat: Threat, actions: List[Action]):
        """Wrapper callback to track aggregated stats."""
        with self._stats_lock:
            self._total_threats += 1
        
        if self._threat_callback:
            self._threat_callback(threat, actions)
    
    def start(self):
        """Start monitoring all log sources."""
        logger.info(f"Starting multi-source monitoring for {len(self.monitors)} log files")
        
        for i, monitor in enumerate(self.monitors):
            try:
                monitor.start()
                logger.info(f"Monitor {i+1}/{len(self.monitors)} started: {monitor.log_path}")
            except Exception as e:
                logger.error(f"Failed to start monitor for {monitor.log_path}: {e}")
    
    def stop(self):
        """Stop all monitors."""
        logger.info("Stopping multi-source monitoring")
        
        for monitor in self.monitors:
            try:
                monitor.stop()
            except Exception as e:
                logger.error(f"Error stopping monitor {monitor.log_path}: {e}")
    
    def get_stats(self) -> dict:
        """Get aggregated statistics from all monitors."""
        with self._stats_lock:
            total_events = sum(m.events_processed for m in self.monitors)
            total_threats = sum(m.threats_detected for m in self.monitors)
        
        # Individual monitor stats
        monitor_stats = []
        for i, monitor in enumerate(self.monitors):
            stats = monitor.get_stats()
            stats['monitor_id'] = i
            monitor_stats.append(stats)
        
        return {
            'total_events': total_events,
            'total_threats': total_threats,
            'num_sources': len(self.monitors),
            'running': any(m.running for m in self.monitors),
            'sources': monitor_stats,
        }
    
    def approve_suricata_action(self, action_id: int):
        """Approve a pending Suricata action (delegates to first monitor with it)."""
        for monitor in self.monitors:
            try:
                monitor.approve_suricata_action(action_id)
                return
            except ValueError:
                continue
        raise ValueError(f"Action {action_id} not found in any monitor")
    
    def reject_suricata_action(self, action_id: int):
        """Reject a pending Suricata action (delegates to first monitor with it)."""
        for monitor in self.monitors:
            try:
                monitor.reject_suricata_action(action_id)
                return
            except ValueError:
                continue
        raise ValueError(f"Action {action_id} not found in any monitor")
    
    def get_pending_suricata_actions(self) -> List[Action]:
        """Get all pending Suricata actions across all monitors."""
        all_actions = []
        for monitor in self.monitors:
            all_actions.extend(monitor.get_pending_suricata_actions())
        return all_actions

