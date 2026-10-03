"""Real-time Suricata log monitoring using
file system watchers. Processes new log entries as they're written
and triggers threat detection and AI analysis in background threads
to avoid blocking the main monitoring loop.
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
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
import audit
from config import Config
from suricata_manager import SuricataManager
from utils.geoip import enrich_threat_context

logger = logging.getLogger(__name__)

# AI work (explanations and rule suggestions) runs on a small, bounded pool
AI_WORKERS = 2
MAX_AI_BACKLOG = 200


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
        self._read_lock = threading.Lock()
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
        """Process complete new lines added to the log file.
        
        Handles log rotation/truncation (the file shrinking) by starting
        over from the beginning, and leaves a partially written last line
        for the next read so events are never cut in half.
        """
        # Watchdog events and the polling thread can both call this
        with self._read_lock:
            if not self.file_path.exists():
                logger.warning(f"Log file does not exist: {self.file_path}")
                return
            
            try:
                current_size = self.file_path.stat().st_size
                
                if current_size < self.last_position:
                    logger.info(f"Log file {self.file_path} was rotated or truncated; reading from the start")
                    self.last_position = 0
                
                # Check if file actually grew
                if current_size == self.last_position:
                    return
                
                with open(self.file_path, 'rb') as f:
                    f.seek(self.last_position)
                    data = f.read(current_size - self.last_position)
                
                # Only consume up to the last complete line
                end = data.rfind(b'\n')
                if end == -1:
                    return
                self.last_position += end + 1

                for raw_line in data[:end].split(b'\n'):
                    line = raw_line.decode('utf-8', errors='replace').strip()
                    if line:
                        self.callback(line)
            
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
        queue_suricata_approvals: bool = True,
    ):
        """
        Initialize the real-time monitor.
        
        Args:
            log_path: Path to Suricata eve.json log file
            config: Configuration object
            ip_manager: Optional IPManager for whitelist/blacklist support
            read_from_start: Process existing log entries instead of only new ones
            poll_interval: Seconds between polls that back up file-change events
            queue_suricata_approvals: Keep rules awaiting approval in memory for the
                CLI prompt. The web console approves from the database instead.
        """
        self.log_path = Path(log_path)
        self.queue_suricata_approvals = queue_suricata_approvals
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
        # Bounded pool for AI work, so an alert flood can't start unlimited threads or model calls
        self._ai_pool = ThreadPoolExecutor(max_workers=AI_WORKERS, thread_name_prefix="autodefender-ai")
        self._ai_backlog = 0
        self._ai_backlog_lock = threading.Lock()
        
        # Initialize Suricata manager if enabled
        self.suricata_manager: Optional[SuricataManager] = None
        if hasattr(self.config, 'SURICATA_ENABLED') and self.config.SURICATA_ENABLED:
            try:
                self.suricata_manager = SuricataManager(self.config, ip_manager=ip_manager)
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
        
        self.running = False
        # Drop queued AI work; a request already in progress finishes on its own
        self._ai_pool.shutdown(wait=False, cancel_futures=True)
        
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
        last_expiry_check = 0.0
        while self.running:
            # Remove expired blocks about once a minute
            if self.suricata_manager and time.monotonic() - last_expiry_check > 60:
                last_expiry_check = time.monotonic()
                try:
                    self.suricata_manager.expire_blocks()
                except Exception as expiry_error:
                    logger.error("Error expiring blocks: %s", expiry_error)
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
        
        # Enrich with geographic context if available
        threat_dict = threat.__dict__.copy()
        enriched = enrich_threat_context(threat_dict)
        if "geo_context" in enriched:
            threat.metadata = threat.metadata or {}
            threat.metadata["geo_context"] = enriched["geo_context"]

        # Store in database
        threat_id = self.database.add_threat(threat)
        threat.id = threat_id

        # Generate the AI explanation in the bounded worker pool; if it's full
        # (alert flood), store the built-in explanation right away instead
        if not self._submit_ai_task(self._generate_explanation_sync, threat):
            self._generate_explanation_sync(threat, use_ai=False)
        
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
    
    def _submit_ai_task(self, func, *args) -> bool:
        """Run func in the bounded AI worker pool. Returns False if the backlog is full."""
        with self._ai_backlog_lock:
            if self._ai_backlog >= MAX_AI_BACKLOG:
                return False
            self._ai_backlog += 1

        def run():
            try:
                func(*args)
            finally:
                with self._ai_backlog_lock:
                    self._ai_backlog -= 1

        try:
            self._ai_pool.submit(run)
        except RuntimeError:
            # Pool already shut down (monitor stopping)
            with self._ai_backlog_lock:
                self._ai_backlog -= 1
            return False
        return True

    def _handle_suricata_action(self, threat: Threat, actions: list[Action]):
        """
        Prepare the drop rule for a threat's SURICATA_DROP_RULE actions.

        Uses the AI suggestion when the worker pool has room, otherwise the
        built-in rule. Either way the rule is validated before it is stored.

        Args:
            threat: Threat object
            actions: List of actions already generated
        """
        suricata_actions = [a for a in actions if a.action_type == 'SURICATA_DROP_RULE']
        if not suricata_actions:
            return
        if not self._submit_ai_task(self._process_suricata_actions, threat, suricata_actions, True):
            logger.warning("AI backlog full; using the built-in rule for threat %s", threat.id)
            self._process_suricata_actions(threat, suricata_actions, False)

    def _process_suricata_actions(self, threat: Threat, suricata_actions: list[Action], use_ai: bool):
        """Generate the rule, store it on the actions, then auto-apply or queue for approval."""
        try:
            if use_ai:
                rule = self.ai_explainer.suggest_suricata_rule(threat)
            else:
                rule = self.ai_explainer._fallback_suricata_rule(threat)
            if not rule or not self.running:
                if not rule:
                    logger.warning(f"No Suricata rule generated for threat {threat.id}")
                return
            rule_text = rule.strip()

            # Store the full rule on each action so reviewers see exactly what would be written
            for action in suricata_actions:
                action.description = rule_text
                if action.id:
                    self.database.update_action_description(action.id, rule_text)

            if getattr(self.config, 'AUTO_APPROVE_SURICATA', False):
                for action in suricata_actions:
                    # Claim first so a person approving in the web console can't race this
                    if action.id and not self.database.transition_action(action.id, 'RECOMMENDED', 'PROCESSING'):
                        continue
                    success = self.suricata_manager.add_custom_rule(rule_text)
                    if action.id:
                        if success:
                            self.database.update_action_status(action.id, 'EXECUTED', datetime.now())
                        else:
                            self.database.update_action_status(action.id, 'FAILED')
                    if success:
                        logger.info(f"Auto-executed Suricata rule for threat {threat.id}")
                        audit.record("system", "rule_auto_approved", {"threat_id": threat.id, "rule": rule_text})
                    else:
                        logger.error(f"Failed to execute Suricata rule for threat {threat.id}")
            elif self.queue_suricata_approvals:
                # Queue for the CLI approval prompt
                with self._pending_lock:
                    self.pending_suricata_actions.extend(suricata_actions)
                    self._pending_event.set()
                logger.info(f"Queued Suricata action for approval (threat {threat.id})")
        except Exception as e:
            if self.running:
                logger.error(f"Error handling Suricata action: {e}")

    def skip_suricata_action(self, action: Action):
        """Take an action off the CLI queue without deciding; it stays RECOMMENDED for the web console."""
        logger.warning(f"Left Suricata action {action.id} pending (approval prompt unavailable)")
        self._remove_pending(action)
    
    def _remove_pending(self, action: Action):
        """Drop an action from the CLI approval queue."""
        with self._pending_lock:
            if action in self.pending_suricata_actions:
                self.pending_suricata_actions.remove(action)
            if not self.pending_suricata_actions:
                self._pending_event.clear()
    
    def approve_suricata_action(self, action: Action) -> bool:
        """
        Approve a pending Suricata action.
        
        Args:
            action: Action to approve
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.suricata_manager:
                logger.warning("Suricata manager not initialized")
                return False
            # Claim the action so the web console can't approve it at the same time
            if action.id and not self.database.transition_action(action.id, 'RECOMMENDED', 'PROCESSING'):
                logger.info(f"Suricata action {action.id} was already handled")
                return False
            
            # The action description contains the complete rule text
            rule = action.description.strip()
            try:
                success = bool(rule) and self.suricata_manager.add_custom_rule(rule)
            except Exception as e:
                logger.error(f"Error approving Suricata action: {e}")
                success = False
            
            if action.id:
                if success:
                    self.database.update_action_status(action.id, 'EXECUTED', datetime.now())
                else:
                    self.database.update_action_status(action.id, 'FAILED')
            if success:
                logger.info(f"Approved and executed Suricata action {action.id}")
                audit.record("cli", "action_approved", {"action_id": action.id, "rule": rule})
            else:
                logger.error(f"Failed to execute Suricata action {action.id}")
                audit.record("cli", "action_failed", {"action_id": action.id})
            return success
        finally:
            # Always leave the queue, or the CLI would keep asking about this action
            self._remove_pending(action)
    
    def reject_suricata_action(self, action: Action) -> bool:
        """
        Reject a pending Suricata action.
        
        Args:
            action: Action to reject
            
        Returns:
            True if this call rejected it, False if it was already handled or failed
        """
        try:
            rejected = not action.id or self.database.transition_action(action.id, 'RECOMMENDED', 'REJECTED')
            if rejected:
                logger.info(f"Rejected Suricata action {action.id}")
                audit.record("cli", "action_rejected", {"action_id": action.id})
            return rejected
        except Exception as e:
            logger.error(f"Error rejecting Suricata action: {e}")
            return False
        finally:
            self._remove_pending(action)
    
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
    
    def _generate_explanation_sync(self, threat: Threat, use_ai: bool = True):
        """Generate and store an explanation (runs in the AI worker pool)."""
        try:
            explanation = self.ai_explainer.explain_threat(threat, use_ai=use_ai)
            if explanation and threat.id and self.running:
                self.database.update_threat_explanation(threat.id, explanation)
                threat.ai_explanation = explanation
        except Exception as e:
            if self.running:
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

