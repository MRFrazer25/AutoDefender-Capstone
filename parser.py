"""Suricata eve.json parser.

Parses JSON log files and extracts IPs, ports, protocols, and alerts.
Handles malformed JSON gracefully.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Iterator
from dateutil import parser as date_parser

logger = logging.getLogger(__name__)


class SuricataParser:
    """Parser for Suricata eve.json log files."""
    
    def __init__(self):
        """Initialize the parser."""
        self.processed_count = 0
        self.error_count = 0
    
    def parse_event(self, event_str: str) -> Optional[Dict]:
        """
        Parse a single JSON event from Suricata log.
        
        Args:
            event_str: JSON string from log file
            
        Returns:
            Parsed event dictionary or None if parsing fails
        """
        try:
            event = json.loads(event_str.strip())
            self.processed_count += 1
            return event
        except json.JSONDecodeError as e:
            self.error_count += 1
            logger.warning(f"Failed to parse JSON event: {e}")
            return None
        except Exception as e:
            self.error_count += 1
            logger.error(f"Unexpected error parsing event: {e}")
            return None
    
    def extract_event_data(self, event: Dict) -> Dict:
        """
        Extract relevant data from a Suricata event.
        
        Args:
            event: Parsed Suricata event dictionary
            
        Returns:
            Dictionary with extracted fields
        """
        extracted = {
            'event_type': event.get('event_type', 'unknown'),
            'timestamp': self._parse_timestamp(event.get('timestamp')),
            'src_ip': event.get('src_ip'),
            'dest_ip': event.get('dest_ip'),
            'dest_port': event.get('dest_port'),
            'src_port': event.get('src_port'),
            'protocol': event.get('protocol'),
            'alert': event.get('alert', {}),
            'flow': event.get('flow', {}),
            'http': event.get('http', {}),
            'dns': event.get('dns', {}),
            'tls': event.get('tls', {}),
            'raw_event': event
        }
        
        return extracted
    
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """
        Parse Suricata timestamp string to datetime object.
        
        Args:
            timestamp_str: Timestamp string or datetime object
            
        Returns:
            datetime object or None if parsing fails
        """
        if not timestamp_str:
            return None
        
        # If already a datetime object, return it
        if isinstance(timestamp_str, datetime):
            return timestamp_str
        
        # If it's not a string, try to convert
        if not isinstance(timestamp_str, str):
            try:
                timestamp_str = str(timestamp_str)
            except Exception:
                logger.warning(f"Could not convert timestamp to string: {timestamp_str}")
                return None
        
        try:
            return date_parser.parse(timestamp_str)
        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse timestamp {timestamp_str}: {e}")
            return None
    
    def parse_file(self, file_path: str) -> Iterator[Dict]:
        """
        Parse a Suricata log file and yield events.
        
        Args:
            file_path: Path to Suricata eve.json file
            
        Yields:
            Extracted event dictionaries
        """
        path = Path(file_path)
        if not path.exists():
            logger.error(f"Log file not found: {file_path}")
            return
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    
                    event = self.parse_event(line)
                    if event:
                        try:
                            extracted = self.extract_event_data(event)
                            yield extracted
                        except Exception as e:
                            logger.error(f"Error extracting data from event at line {line_num}: {e}")
                            continue
        
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
    
    def parse_files(self, file_paths: List[str]) -> Iterator[Dict]:
        """
        Parse multiple Suricata log files.
        
        Args:
            file_paths: List of paths to Suricata log files
            
        Yields:
            Extracted event dictionaries from all files
        """
        for file_path in file_paths:
            logger.info(f"Parsing file: {file_path}")
            for event in self.parse_file(file_path):
                yield event
    
    def parse_directory(self, directory_path: str, pattern: str = "*.json") -> Iterator[Dict]:
        """
        Parse all matching files in a directory.
        
        Args:
            directory_path: Path to directory containing log files
            pattern: File pattern to match (default: *.json)
            
        Yields:
            Extracted event dictionaries from all matching files
        """
        path = Path(directory_path)
        if not path.is_dir():
            logger.error(f"Directory not found: {directory_path}")
            return
        
        json_files = list(path.glob(pattern))
        logger.info(f"Found {len(json_files)} files matching pattern {pattern}")
        
        for json_file in json_files:
            for event in self.parse_file(str(json_file)):
                yield event
    
    def get_stats(self) -> Dict:
        """Get parsing statistics."""
        return {
            'processed': self.processed_count,
            'errors': self.error_count,
            'success_rate': (self.processed_count / (self.processed_count + self.error_count) * 100) 
                           if (self.processed_count + self.error_count) > 0 else 0
        }

