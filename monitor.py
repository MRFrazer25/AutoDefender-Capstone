"""Real-time Suricata log monitoring using
file system watchers. Processes new log entries as they're written
and triggers threat detection and AI analysis in background threads
to avoid blocking the main monitoring loop.
"""

import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
import time
from parser import SuricataParser
from detector import ThreatDetector
from database import Database
from action_engine import ActionEngine
from ai_explainer import AIExplainer
from models import Threat, Action
from config import Config
from suricata_manager import SuricataManager
from utils.geoip import enrich_threat_context

logger = logging.getLogger(__name__)


class SuricataLogHandler(FileSystemEventHandler):
    """File system event handler for Suricata log files."""
    
    def __init__(
        self,
        callback: Callable,
        file_path: str,
        start_from_beginning: bool = False,
    ):
        """Initialize the handler."""
        self.callback = callback
        self.file_path = Path(file_path)
        self._resolved_path = self.file_path.resolve()
        self.last_position = 0
        self.start_from_beginning = start_from_beginning
        self._initialize_position()
    
    def _initialize_position(self):
        """Initialize file position to end of file."""
        if self.start_from_beginning:
            logger.debug(
                "Log handler configured to read from start of file: %s",
                self.file_path,
            )
            self.last_position = 0
        elif self.file_path.exists():
            self.last_position = self.file_path.stat().st_size
            logger.debug(
                "Initialized log handler position at EOF (%s bytes) for %s",
                self.last_position,
                self.file_path,
            )
        else:
            logger.debug(
                "Log handler could not find file at init (will wait): %s",
                self.file_path,
            )
    
    def on_modified(self, event: FileModifiedEvent):
        """Handle file modification events."""
        # Normalize paths for comparison (Windows path handling)
        event_path = Path(event.src_path).resolve()
        if event_path == self._resolved_path:
            logger.debug(f"File modified event detected: {event.src_path}")
            self.process_new_lines()
    
    def process_new_lines(self):
        """Process new lines added to the log file."""
        if not self.file_path.exists():
            logger.warning(f"Log file does not exist: {self.file_path}")
            return
        
        try:
            current_size = self.file_path.stat().st_size
            
            # Check if file actually grew
            if current_size <= self.last_position:
                logger.debug(f"No new content (size: {current_size}, last_pos: {self.last_position})")
                return
            
            with open(self.file_path, 'r', encoding='utf-8') as f:
                # Seek to last known position
                f.seek(self.last_position)
                
                # Read new lines
                new_lines = f.readlines()
                new_position = f.tell()
                
                logger.debug(f"Read {len(new_lines)} new lines from position {self.last_position} to {new_position}")
                
                # Update position
                self.last_position = new_position
                
                # Process each new line
                for line in new_lines:
                    if line.strip():
                        logger.debug(f"Processing line: {line.strip()[:100]}...")
                        self.callback(line.strip())
        
        except Exception as e:
            logger.error(f"Error reading new lines from {self.file_path}: {e}", exc_info=True)


class RealTimeMonitor:
    """Real-time Suricata log monitor."""
    
    def __init__(
        self,
        log_path: str,
        config: Optional[Config] = None,
        ip_manager=None,
        read_from_start: bool = False,
        poll_interval: float = 1.0,
    ):
        """
        Initialize the real-time monitor.
        
        Args:
            log_path: Path to Suricata eve.json log file
            config: Configuration object
            ip_manager: Optional IPManager for whitelist/blacklist support
        """
        self.log_path = Path(log_path)
        self.config = config or Config.get_default()
        self.read_from_start = read_from_start
        self._poll_interval = poll_interval
        
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {log_path}")
        
        if not self.log_path.is_file():
            raise ValueError(f"Path is not a file: {log_path}")
        
        self.parser = SuricataParser()
        self.detector = ThreatDetector(self.config, ip_manager=ip_manager)
        try:
            self.database = Database(self.config.db_path)
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
        self.action_engine = ActionEngine(self.config)
        self.ai_explainer = AIExplainer(self.config)
        self._polling_thread: Optional[threading.Thread] = None
        
        # Initialize Suricata manager if enabled
        self.suricata_manager: Optional[SuricataManager] = None
        if hasattr(self.config, 'SURICATA_ENABLED') and self.config.SURICATA_ENABLED:
            try:
                self.suricata_manager = SuricataManager(self.config)
                logger.info("Suricata integration enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize Suricata manager: {e}")
        
        self.observer: Optional[Observer] = None
        self.event_handler: Optional[SuricataLogHandler] = None
        self.running = False
        self.threat_callback: Optional[Callable] = None
        
        # Statistics
        self.events_processed = 0
        self.threats_detected = 0
        
        # Pending Suricata actions (for approval workflow)
        self.pending_suricata_actions: list[Action] = []
        self._pending_lock = threading.Lock()
        self._pending_event = threading.Event()
        
        # Health monitoring
        self._last_health_check: Optional[datetime] = None
        self._health_check_interval = 300  # Check every 5 minutes
    
    def set_threat_callback(self, callback: Callable):
        """Set callback function to be called when threats are detected."""
        self.threat_callback = callback
    
    def start(self):
        """Start monitoring the log file."""
        if not self.log_path.exists():
            logger.error(f"Log file does not exist: {self.log_path}")
            raise FileNotFoundError(f"Log file not found: {self.log_path}")
        
        logger.info(f"Starting real-time monitoring of {self.log_path}")
        
        # Create event handler
        self.event_handler = SuricataLogHandler(
            callback=self._process_event,
            file_path=str(self.log_path),
            start_from_beginning=self.read_from_start,
        )
        
        # Create observer
        self.observer = Observer()
        self.observer.schedule(
            self.event_handler,
            path=str(self.log_path.parent),
            recursive=False
        )
        
        self.observer.start()
        self.running = True
        
        # Start polling loop to supplement watchdog events
        self._polling_thread = threading.Thread(
            target=self._poll_log_file,
            daemon=True,
            name="LogPollingThread",
        )
        self._polling_thread.start()
        logger.info("Real-time monitoring started")
    
    def stop(self):
        """Stop monitoring."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        
        if self._polling_thread and self._polling_thread.is_alive():
            self.running = False
            self._polling_thread.join(timeout=2)
            self._polling_thread = None
        
        if self.database:
            self.database.close()
        
        self.running = False
        # Unblock any waiters on pending action events
        if hasattr(self, "_pending_event"):
            self._pending_event.set()
        logger.info("Real-time monitoring stopped")
    
    def _poll_log_file(self):
        """Poll log file periodically to ensure new lines are processed."""
        logger.debug(
            "Starting log file polling loop (interval: %ss)", self._poll_interval
        )
        while self.running:
            if self.event_handler:
                try:
                    self.event_handler.process_new_lines()
                except Exception as poll_error:
                    logger.error(
                        "Polling loop error while processing log file: %s",
                        poll_error,
                        exc_info=True,
                    )
            time.sleep(self._poll_interval)
        logger.debug("Log file polling loop terminated")
    
    def _process_event(self, event_line: str):
        """Process a single log event."""
        try:
            logger.debug(f"Processing event line: {event_line[:100]}...")
            
            # Parse event
            event = self.parser.parse_event(event_line)
            if not event:
                logger.debug("Failed to parse event (returned None)")
                return
            
            self.events_processed += 1
            logger.debug(f"Event parsed successfully. Events processed: {self.events_processed}")
            
            # Extract event data
            event_data = self.parser.extract_event_data(event)
            
            # Detect threats
            threat = self.detector.detect(event_data)
            if threat:
                logger.info(f"Threat detected: {threat.description} (severity: {threat.severity})")
                self._handle_threat(threat)
            else:
                logger.debug("No threat detected from this event")
        
        except Exception as e:
            logger.error(f"Error processing event: {e}", exc_info=True)
    
    def _handle_threat(self, threat: Threat):
        """Handle a detected threat."""
        self.threats_detected += 1
        logger.info(f"Threat detected: {threat.description}")
        
        # Enrich with geographic context if available
        threat_dict = threat.__dict__.copy()
        enriched = enrich_threat_context(threat_dict)
        if "geo_context" in enriched:
            threat.metadata = threat.metadata or {}
            threat.metadata["geo_context"] = enriched["geo_context"]
        
        # Store in database
        threat_id = self.database.add_threat(threat)
        threat.id = threat_id
        
        # Generate AI explanation (in background thread to not block)
        import threading
        thread = threading.Thread(target=self._generate_explanation_sync, args=(threat,))
        thread.daemon = True
        thread.start()
        
        # Generate action recommendations
        actions = self.action_engine.recommend_actions(threat)
        for action in actions:
            action.threat_id = threat_id
            action_id = self.database.add_action(action)
            action.id = action_id
        
        # Handle Suricata actions for HIGH/CRITICAL threats
        if self.suricata_manager and threat.severity in ['HIGH', 'CRITICAL']:
            self._handle_suricata_action(threat, actions)
        
        # Call callback if set
        if self.threat_callback:
            try:
                self.threat_callback(threat, actions)
            except Exception as e:
                logger.error(f"Error in threat callback: {e}")
    
    def _handle_suricata_action(self, threat: Threat, actions: list[Action]):
        """
        Handle Suricata rule generation for a threat.
        
        Args:
            threat: Threat object
            actions: List of actions already generated
        """
        try:
            # Find SURICATA_DROP_RULE actions
            suricata_actions = [a for a in actions if a.action_type == 'SURICATA_DROP_RULE']
            
            if not suricata_actions:
                return
            
            # Generate AI-suggested rule in background
            def generate_and_execute():
                try:
                    # Use AI to suggest rule
                    ai_rule = self.ai_explainer.suggest_suricata_rule(threat)
                    
                    if not ai_rule:
                        logger.warning(f"No Suricata rule generated for threat {threat.id}")
                        return
                    
                    # Normalize rule text
                    rule_text = ai_rule.strip()
                    
                    # Update action descriptions with full rule for auditing
                    for action in suricata_actions:
                        action.description = rule_text
                        if action.id:
                            try:
                                self.database.update_action_description(action.id, rule_text)
                            except Exception as db_err:
                                logger.error(f"Failed updating action {action.id} description: {db_err}")
                    
                    # Check auto-approval
                    if hasattr(self.config, 'AUTO_APPROVE_SURICATA') and self.config.AUTO_APPROVE_SURICATA:
                        # Auto-execute
                        success = self.suricata_manager.add_custom_rule(rule_text)
                        if success:
                            logger.info(f"Auto-executed Suricata rule for threat {threat.id}")
                            # Update action status
                            for action in suricata_actions:
                                if action.id:
                                    self.database.update_action_status(action.id, 'EXECUTED', datetime.now())
                        else:
                            logger.error(f"Failed to execute Suricata rule for threat {threat.id}")
                            for action in suricata_actions:
                                if action.id:
                                    self.database.update_action_status(action.id, 'FAILED')
                    else:
                        # Queue for manual approval
                        with self._pending_lock:
                            for action in suricata_actions:
                                self.pending_suricata_actions.append(action)
                            self._pending_event.set()
                        logger.info(f"Queued Suricata action for approval (threat {threat.id})")
                
                except Exception as e:
                    logger.error(f"Error handling Suricata action: {e}")
            
            # Run in background thread
            thread = threading.Thread(target=generate_and_execute)
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            logger.error(f"Error in _handle_suricata_action: {e}")
    
    def approve_suricata_action(self, action: Action) -> bool:
        """
        Approve a pending Suricata action.
        
        Args:
            action: Action to approve
            
        Returns:
            True if successful, False otherwise
        """
        if not self.suricata_manager:
            logger.warning("Suricata manager not initialized")
            return False
        
        try:
            # The action description contains the complete rule text
            rule = action.description.strip()
            
            if not rule:
                logger.warning("Empty rule in action description")
                return False
            
            # Execute rule
            success = self.suricata_manager.add_custom_rule(rule)
            
            if success:
                # Update action status
                if action.id:
                    self.database.update_action_status(action.id, 'EXECUTED', datetime.now())
                # Remove from pending queue if present
                with self._pending_lock:
                    if action in self.pending_suricata_actions:
                        self.pending_suricata_actions.remove(action)
                    if not self.pending_suricata_actions:
                        self._pending_event.clear()
                logger.info(f"Approved and executed Suricata action {action.id}")
                return True
            else:
                logger.error(f"Failed to execute Suricata action {action.id}")
                if action.id:
                    self.database.update_action_status(action.id, 'FAILED')
                with self._pending_lock:
                    if action in self.pending_suricata_actions:
                        self.pending_suricata_actions.remove(action)
                    if not self.pending_suricata_actions:
                        self._pending_event.clear()
                return False
                
        except Exception as e:
            logger.error(f"Error approving Suricata action: {e}")
            return False
    
    def reject_suricata_action(self, action: Action) -> bool:
        """
        Reject a pending Suricata action.
        
        Args:
            action: Action to reject
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Update action status
            if action.id:
                self.database.update_action_status(action.id, 'REJECTED')
            
            # Remove from pending
            with self._pending_lock:
                if action in self.pending_suricata_actions:
                    self.pending_suricata_actions.remove(action)
                if not self.pending_suricata_actions:
                    self._pending_event.clear()
            
            logger.info(f"Rejected Suricata action {action.id}")
            return True
            
        except Exception as e:
            logger.error(f"Error rejecting Suricata action: {e}")
            return False
    
    def get_pending_suricata_actions(self) -> list[Action]:
        """Get list of pending Suricata actions."""
        with self._pending_lock:
            return list(self.pending_suricata_actions)
    
    def wait_for_pending_actions(self, timeout: Optional[float] = None) -> bool:
        """Wait for pending Suricata actions to become available."""
        return self._pending_event.wait(timeout)
    
    def peek_pending_suricata_action(self) -> Optional[Action]:
        """Peek at the next pending Suricata action without removing it."""
        with self._pending_lock:
            return self.pending_suricata_actions[0] if self.pending_suricata_actions else None
    
    def _generate_explanation_sync(self, threat: Threat):
        """Generate AI explanation in background thread."""
        try:
            explanation = self.ai_explainer.explain_threat(threat, use_ai=True)
            if explanation and threat.id:
                self.database.update_threat_explanation(threat.id, explanation)
                threat.ai_explanation = explanation
        except Exception as e:
            logger.error(f"Error generating AI explanation: {e}")
    
    def get_stats(self) -> dict:
        """Get monitoring statistics."""
        stats = {
            'events_processed': self.events_processed,
            'threats_detected': self.threats_detected,
            'running': self.running,
            'parser_stats': self.parser.get_stats()
        }
        
        # Log file health
        try:
            log_stat = self.log_path.stat()
            last_modified = datetime.fromtimestamp(log_stat.st_mtime)
            age_seconds = (datetime.now() - last_modified).total_seconds()
            stats['log_file'] = {
                'path': str(self.log_path),
                'size': log_stat.st_size,
                'last_modified': last_modified.isoformat(),
                'age_seconds': age_seconds,
            }
            stats['log_file_stale'] = age_seconds > 60  # Consider stale if > 1 minute old
        except FileNotFoundError:
            stats['log_file'] = {
                'path': str(self.log_path),
                'missing': True
            }
            stats['log_file_stale'] = True
        
        # Add Suricata health status if applicable
        if self.suricata_manager:
            # Periodic health check
            now = datetime.now()
            if (not self._last_health_check or 
                (now - self._last_health_check).total_seconds() > self._health_check_interval):
                health = self.suricata_manager.check_health()
                self._last_health_check = now
            else:
                health = self.suricata_manager.get_health_status()
            
            stats['suricata_health'] = health
            stats['needs_restart'] = self.suricata_manager.needs_restart()
        
        return stats
    
    def is_running(self) -> bool:
        """Check if monitor is running."""
        return self.running

