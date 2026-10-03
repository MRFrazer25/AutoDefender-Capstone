"""SQLite database for threats, actions, and stats.

Uses parameterized queries to prevent SQL injection.
"""

import functools
import os
import sqlite3
import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from parser import to_utc
from typing import List, Optional
from models import Threat, Action, DetectionStats

logger = logging.getLogger(__name__)


def _locked(method):
    """Run a Database method while holding the connection lock.

    The monitor shares one connection between its reader, AI, and rule
    threads, and sqlite3 connections are not safe for concurrent use.
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class Database:
    """SQLite database operations for AutoDefender."""
    
    def __init__(self, db_path: str = "autodefender.db"):
        """Initialize database connection and create tables."""
        self.db_path = db_path
        self._lock = threading.RLock()
        is_new = db_path != ":memory:" and not os.path.exists(db_path)
        self.conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        if is_new and os.name == "posix":
            # Threat data includes IP addresses; keep it readable by this user only
            os.chmod(db_path, 0o600)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
    
    def _create_tables(self):
        """Create database tables if they don't exist."""
        cursor = self.conn.cursor()
        
        # Threats table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                dest_ip TEXT,
                dest_port INTEGER,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                raw_event TEXT,
                ai_explanation TEXT,
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Migrate existing databases - add metadata column if it doesn't exist
        try:
            cursor.execute("SELECT metadata FROM threats LIMIT 1")
        except sqlite3.OperationalError:
            logger.info("Adding metadata column to existing threats table")
            cursor.execute("ALTER TABLE threats ADD COLUMN metadata TEXT")
            self.conn.commit()
        
        # Actions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id INTEGER,
                action_type TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                executed_at TEXT,
                FOREIGN KEY (threat_id) REFERENCES threats(id)
            )
        """)
        
        # Indexes for performance
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threats_source_ip ON threats(source_ip)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_actions_threat_id ON actions(threat_id)
        """)
        
        self.conn.commit()
        logger.info("Database tables created/verified")
    
    @_locked
    def add_threat(self, threat: Threat) -> int:
        """Add a threat to the database and return its ID."""
        cursor = self.conn.cursor()
        
        # Serialize metadata to JSON if present
        metadata_json = None
        if threat.metadata:
            metadata_json = json.dumps(threat.metadata)
        
        cursor.execute("""
            INSERT INTO threats (
                timestamp, source_ip, dest_ip, dest_port, event_type,
                severity, description, raw_event, ai_explanation, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            threat.timestamp.isoformat(),
            threat.source_ip,
            threat.dest_ip,
            threat.dest_port,
            threat.event_type,
            threat.severity,
            threat.description,
            json.dumps(threat.raw_event) if threat.raw_event else None,
            threat.ai_explanation,
            metadata_json
        ))
        self.conn.commit()
        threat_id = cursor.lastrowid
        logger.debug(f"Added threat with ID {threat_id}")
        return threat_id
    
    @_locked
    def get_threat(self, threat_id: int) -> Optional[Threat]:
        """Get a threat by ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM threats WHERE id = ?", (threat_id,))
        row = cursor.fetchone()
        if row:
            return self._row_to_threat(row)
        return None
    
    @_locked
    def get_threats(self, limit: int = 100, severity: Optional[str] = None,
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   source_ip: Optional[str] = None) -> List[Threat]:
        """Get threats with optional filtering."""
        cursor = self.conn.cursor()
        query = "SELECT * FROM threats WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        return [self._row_to_threat(row) for row in cursor.fetchall()]
    
    @_locked
    def update_threat_explanation(self, threat_id: int, explanation: str):
        """Update AI explanation for a threat."""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE threats SET ai_explanation = ? WHERE id = ?
        """, (explanation, threat_id))
        self.conn.commit()
        logger.debug(f"Updated explanation for threat {threat_id}")
    
    @_locked
    def add_action(self, action: Action) -> int:
        """Add an action to the database and return its ID."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO actions (
                threat_id, action_type, description, status, timestamp, executed_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            action.threat_id,
            action.action_type,
            action.description,
            action.status,
            action.timestamp.isoformat(),
            action.executed_at.isoformat() if action.executed_at else None
        ))
        self.conn.commit()
        action_id = cursor.lastrowid
        logger.debug(f"Added action with ID {action_id}")
        return action_id
    
    @_locked
    def get_actions(self, threat_id: Optional[int] = None,
                   status: Optional[str] = None, limit: int = 100) -> List[Action]:
        """Get actions with optional filtering."""
        cursor = self.conn.cursor()
        query = "SELECT * FROM actions WHERE 1=1"
        params = []
        
        if threat_id:
            query += " AND threat_id = ?"
            params.append(threat_id)
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        return [self._row_to_action(row) for row in cursor.fetchall()]
    
    @_locked
    def update_action_status(self, action_id: int, status: str, executed_at: Optional[datetime] = None):
        """Update action status."""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE actions SET status = ?, executed_at = ? WHERE id = ?
        """, (status, executed_at.isoformat() if executed_at else None, action_id))
        self.conn.commit()
        logger.debug(f"Updated action {action_id} status to {status}")
    
    @_locked
    def update_action_description(self, action_id: int, description: str):
        """Update action description (e.g., store AI-generated rule)."""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE actions SET description = ? WHERE id = ?
        """, (description, action_id))
        self.conn.commit()
        logger.debug(f"Updated action {action_id} description")
    
    @_locked
    def get_stats(self) -> DetectionStats:
        """Get detection statistics."""
        cursor = self.conn.cursor()
        
        # Calculate current stats from threats table
        cursor.execute("""
            SELECT 
                COUNT(*) as total_threats,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
                SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
                SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low_count
            FROM threats
        """)
        row = cursor.fetchone()
        
        # Get by type
        cursor.execute("""
            SELECT event_type, COUNT(*) as count
            FROM threats
            GROUP BY event_type
        """)
        by_type = {row['event_type']: row['count'] for row in cursor.fetchall()}
        
        # Get top sources
        cursor.execute("""
            SELECT source_ip, COUNT(*) as count
            FROM threats
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
        """)
        top_sources = [(row['source_ip'], row['count']) for row in cursor.fetchall()]
        
        return DetectionStats(
            total_threats=row['total_threats'] or 0,
            by_severity={
                'CRITICAL': row['critical_count'] or 0,
                'HIGH': row['high_count'] or 0,
                'MEDIUM': row['medium_count'] or 0,
                'LOW': row['low_count'] or 0
            },
            by_type=by_type,
            top_sources=top_sources
        )
    
    
    def _row_to_threat(self, row: sqlite3.Row) -> Threat:
        """
        Convert database row to Threat object.
        
        Args:
            row: SQLite Row object
            
        Returns:
            Threat object
            
        Note: Uses json.loads for raw_event to safely parse stored JSON data.
        """
        try:
            raw_event = json.loads(row['raw_event']) if row['raw_event'] else {}
        except json.JSONDecodeError:
            # Fallback if JSON parsing fails
            logger.warning(f"Failed to parse raw_event JSON for threat {row['id']}")
            raw_event = {}
        
        # Parse metadata if present
        metadata = None
        try:
            if row['metadata']:
                try:
                    metadata = json.loads(row['metadata'])
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse metadata JSON for threat {row['id']}")
        except (KeyError, IndexError):
            # Column doesn't exist or is not accessible - this is fine for old databases
            pass
        
        return Threat(
            id=row['id'],
            timestamp=to_utc(datetime.fromisoformat(row['timestamp'])),
            source_ip=row['source_ip'],
            dest_ip=row['dest_ip'],
            dest_port=row['dest_port'],
            event_type=row['event_type'],
            severity=row['severity'],
            description=row['description'],
            raw_event=raw_event,
            ai_explanation=row['ai_explanation'],
            metadata=metadata
        )
    
    def _row_to_action(self, row: sqlite3.Row) -> Action:
        """Convert database row to Action object."""
        return Action(
            id=row['id'],
            threat_id=row['threat_id'],
            action_type=row['action_type'],
            description=row['description'],
            status=row['status'],
            timestamp=datetime.fromisoformat(row['timestamp']),
            executed_at=datetime.fromisoformat(row['executed_at']) if row['executed_at'] else None
        )
    
    @_locked
    def purge_threats_older_than(self, days: int) -> int:
        """Delete threats (and their actions) older than `days` days. Returns threats deleted."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cursor = self.conn.cursor()
        # Timestamps are stored in ISO format, so compare them as parsed values
        old_ids = [
            row['id'] for row in cursor.execute("SELECT id, timestamp FROM threats").fetchall()
            if to_utc(datetime.fromisoformat(row['timestamp'])).isoformat() < cutoff
        ]
        for start in range(0, len(old_ids), 500):
            chunk = old_ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            # marks is only "?" placeholders; the IDs are bound as parameters
            cursor.execute(f"DELETE FROM actions WHERE threat_id IN ({marks})", chunk)  # nosec B608
            cursor.execute(f"DELETE FROM threats WHERE id IN ({marks})", chunk)  # nosec B608
        self.conn.commit()
        logger.info(f"Purged {len(old_ids)} threats older than {days} days")
        return len(old_ids)
    
    @_locked
    def clear(self, threats: bool = False, actions: bool = False):
        """Delete all threats and/or all actions."""
        cursor = self.conn.cursor()
        if threats:
            # Actions belong to threats, so they go too
            cursor.execute("DELETE FROM actions")
            cursor.execute("DELETE FROM threats")
        elif actions:
            cursor.execute("DELETE FROM actions")
        self.conn.commit()
        if threats or actions:
            cursor.execute("VACUUM")  # Don't leave deleted data in free pages
    
    @_locked
    def close(self):
        """Close database connection."""
        self.conn.close()
        logger.info("Database connection closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

