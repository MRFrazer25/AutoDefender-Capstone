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
from utils.path_utils import sanitize_path

logger = logging.getLogger(__name__)


class Exporter:
    """Export threats and analysis results to various formats."""
    
    def __init__(self, database: Database):
        """Initialize the exporter."""
        self.database = database
    
    def _prepare_output_path(self, output_path: str) -> str:
        """Sanitize and ensure the output path is ready for writing.
        
        Returns validated path as normalized string.
        """
        normalized_path = sanitize_path(output_path)
        # Use os.path operations for directory creation
        parent_dir = os.path.dirname(normalized_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
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
            with open(path_str, 'w', newline='', encoding='utf-8') as f:
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
            
            with open(path_str, 'w', encoding='utf-8') as f:
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

