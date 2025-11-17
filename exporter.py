"""CSV and JSON export for threats and stats.

Exports include metadata for traceability.
"""

import csv
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List

from models import Threat, DetectionStats
from database import Database
from utils.path_utils import sanitize_filename

logger = logging.getLogger(__name__)

# Fixed exports directory - all exports must be within this directory
EXPORTS_DIR = os.path.join(os.getcwd(), "exports")


class Exporter:
    """Export threats and analysis results to various formats."""
    
    def __init__(self, database: Database):
        """Initialize the exporter."""
        self.database = database
    
    def _prepare_output_path(self, filename: str) -> str:
        """Prepare output path within the exports directory.
        
        Args:
            filename: Filename (not full path) for the export file
            
        Returns:
            Full path within exports directory
            
        Raises:
            ValueError: If filename contains path traversal or invalid characters
        """
        # Sanitize filename to remove any path components
        safe_filename = sanitize_filename(filename, default="export")
        
        # Remove any directory separators that might have been in the filename
        safe_filename = os.path.basename(safe_filename)
        
        # Construct path within exports directory
        output_path = os.path.join(EXPORTS_DIR, safe_filename)
        
        # Normalize and validate the path is within exports directory
        normalized_path = os.path.abspath(os.path.normpath(output_path))
        exports_dir_normalized = os.path.abspath(os.path.normpath(EXPORTS_DIR))
        
        # Ensure the path is within exports directory
        if not normalized_path.startswith(exports_dir_normalized + os.sep) and normalized_path != exports_dir_normalized:
            raise ValueError(f"Export path {normalized_path} is outside exports directory")
        
        # Create exports directory if it doesn't exist
        os.makedirs(EXPORTS_DIR, exist_ok=True)
        
        return normalized_path

    def export_threats_csv(self, threats: List[Threat], output_path: str) -> bool:
        """
        Export threats to CSV file.
        
        Args:
            threats: List of Threat objects to export
            output_path: Path to output CSV file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            path_str = self._prepare_output_path(output_path)
            safe_path = os.path.realpath(path_str) if os.path.exists(path_str) else os.path.abspath(os.path.normpath(path_str))
            with open(safe_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, quoting=csv.QUOTE_ALL)
                
                # Write header
                writer.writerow([
                    'ID', 'Timestamp', 'Source IP', 'Destination IP', 'Destination Port',
                    'Event Type', 'Severity', 'Description', 'AI Explanation'
                ])
                
                # Write threat data
                for threat in threats:
                    writer.writerow([
                        threat.id,
                        threat.timestamp.isoformat() if threat.timestamp else '',
                        threat.source_ip or '',
                        threat.dest_ip or '',
                        threat.dest_port or '',
                        threat.event_type,
                        threat.severity,
                        threat.description,
                        threat.ai_explanation or ''
                    ])
            
            logger.info(f"Exported {len(threats)} threats to {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error exporting threats to CSV: {e}")
            return False
    
    def export_threats_json(self, threats: List[Threat], output_path: str) -> bool:
        """
        Export threats to JSON file.
        
        Args:
            threats: List of Threat objects to export
            output_path: Path to output JSON file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            path_str = self._prepare_output_path(output_path)
            safe_path = os.path.realpath(path_str) if os.path.exists(path_str) else os.path.abspath(os.path.normpath(path_str))
            data = {
                'export_timestamp': datetime.now().isoformat(),
                'total_threats': len(threats),
                'threats': []
            }
            
            for threat in threats:
                threat_data = {
                    'id': threat.id,
                    'timestamp': threat.timestamp.isoformat() if threat.timestamp else None,
                    'source_ip': threat.source_ip,
                    'dest_ip': threat.dest_ip,
                    'dest_port': threat.dest_port,
                    'event_type': threat.event_type,
                    'severity': threat.severity,
                    'description': threat.description,
                    'ai_explanation': threat.ai_explanation
                }
                data['threats'].append(threat_data)
            
            with open(safe_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Exported {len(threats)} threats to {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error exporting threats to JSON: {e}")
            return False
    
    def export_statistics(self, stats: DetectionStats, output_path: str, format: str = 'json') -> bool:
        """
        Export statistics to CSV or JSON.
        
        Args:
            stats: DetectionStats object
            output_path: Path to output file
            format: Export format ('json' or 'csv')
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if format.lower() == 'csv':
                path_str = self._prepare_output_path(output_path)
                with open(path_str, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f, quoting=csv.QUOTE_ALL)
                    writer.writerow(['Metric', 'Value'])
                    writer.writerow(['Total Threats', stats.total_threats])
                    writer.writerow(['Critical', stats.by_severity.get('CRITICAL', 0)])
                    writer.writerow(['High', stats.by_severity.get('HIGH', 0)])
                    writer.writerow(['Medium', stats.by_severity.get('MEDIUM', 0)])
                    writer.writerow(['Low', stats.by_severity.get('LOW', 0)])
                    
                    writer.writerow([])  # Empty row
                    writer.writerow(['Threat Type', 'Count'])
                    for threat_type, count in stats.by_type.items():
                        writer.writerow([threat_type, count])
                    
                    writer.writerow([])  # Empty row
                    writer.writerow(['Source IP', 'Threat Count'])
                    for ip, count in stats.top_sources:
                        writer.writerow([ip, count])
                
                logger.info(f"Exported statistics to {output_path}")
                return True
            else:
                # JSON format
                path_str = self._prepare_output_path(output_path)
                data = {
                    'export_timestamp': datetime.now().isoformat(),
                    'total_threats': stats.total_threats,
                    'by_severity': stats.by_severity,
                    'by_type': stats.by_type,
                    'top_sources': [{'ip': ip, 'count': count} for ip, count in stats.top_sources]
                }
                
                with open(path_str, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                logger.info(f"Exported statistics to {output_path}")
                return True
        except Exception as e:
            logger.error(f"Error exporting statistics: {e}")
            return False

