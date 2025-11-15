"""Historical log file analyzer."""

import logging
from pathlib import Path
from typing import List, Optional
from parser import SuricataParser
from detector import ThreatDetector
from database import Database
from action_engine import ActionEngine
from ai_explainer import AIExplainer
from filter import ThreatFilter
from models import Threat
from config import Config

logger = logging.getLogger(__name__)


class HistoricalAnalyzer:
    """Analyzes historical Suricata log files."""
    
    def __init__(self, config: Optional[Config] = None, ip_manager=None):
        """
        Initialize the historical analyzer.
        
        Args:
            config: Configuration object
            ip_manager: Optional IPManager for whitelist/blacklist support
        """
        self.config = config or Config.get_default()
        
        self.parser = SuricataParser()
        self.detector = ThreatDetector(self.config, ip_manager=ip_manager)
        try:
            self.database = Database(self.config.db_path)
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
        self.action_engine = ActionEngine(self.config)
        self.ai_explainer = AIExplainer(self.config)
        self.filter = ThreatFilter()
        
        self.analyzed_files = 0
        self.events_processed = 0
        self.threats_detected = 0
    
    def analyze_file(self, file_path: str, generate_explanations: bool = True) -> List[Threat]:
        """
        Analyze a single log file.
        
        Args:
            file_path: Path to Suricata log file
            generate_explanations: Whether to generate AI explanations (currently unused)
            
        Returns:
            List of detected threats
        """
        _ = generate_explanations
        
        logger.info(f"Analyzing file: {file_path}")
        threats = []
        
        try:
            for event in self.parser.parse_file(file_path):
                self.events_processed += 1
                
                # Detect threats
                threat = self.detector.detect(event)
                if threat:
                    threats.append(threat)
                    self.threats_detected += 1
                    
                    # Store in database
                    threat_id = self.database.add_threat(threat)
                    threat.id = threat_id
                    
                    # AI explanation will be generated later based on user selection
                    # Don't generate here - let user choose which threats to analyze
                    
                    # Generate action recommendations
                    actions = self.action_engine.recommend_actions(threat)
                    for action in actions:
                        action.threat_id = threat_id
                        self.database.add_action(action)
            
            self.analyzed_files += 1
            logger.info(f"Completed analysis of {file_path}: {len(threats)} threats detected")
        
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
        
        return threats
    
    def analyze_files(self, file_paths: List[str], generate_explanations: bool = True) -> List[Threat]:
        """
        Analyze multiple log files.
        
        Args:
            file_paths: List of paths to log files
            generate_explanations: Whether to generate AI explanations
            
        Returns:
            List of all detected threats
        """
        all_threats = []
        
        for file_path in file_paths:
            threats = self.analyze_file(file_path, generate_explanations)
            all_threats.extend(threats)
        
        return all_threats
    
    def analyze_directory(self, directory_path: str, pattern: str = "*.json",
                         generate_explanations: bool = True) -> List[Threat]:
        """
        Analyze all matching files in a directory.
        
        Args:
            directory_path: Path to directory containing log files
            pattern: File pattern to match (default: *.json)
            generate_explanations: Whether to generate AI explanations
            
        Returns:
            List of all detected threats
        """
        path = Path(directory_path)
        if not path.is_dir():
            logger.error(f"Directory not found: {directory_path}")
            return []
        
        json_files = list(path.glob(pattern))
        logger.info(f"Found {len(json_files)} files matching pattern {pattern}")
        
        return self.analyze_files([str(f) for f in json_files], generate_explanations)
    
    def generate_report(self) -> dict:
        """
        Generate analysis report.
        
        Returns:
            Dictionary with analysis results and statistics
        """
        stats = self.database.get_stats()
        parser_stats = self.parser.get_stats()
        
        report = {
            'files_analyzed': self.analyzed_files,
            'events_processed': self.events_processed,
            'threats_detected': self.threats_detected,
            'parser_stats': parser_stats,
            'threat_statistics': {
                'total': stats.total_threats,
                'by_severity': stats.by_severity,
                'by_type': stats.by_type,
                'top_sources': stats.top_sources
            }
        }
        
        return report
    
    def get_summary(self) -> str:
        """
        Get a text summary of the analysis.
        
        Returns:
            Formatted summary string
        """
        report = self.generate_report()
        stats = report['threat_statistics']
        
        # Get sample AI explanations for high-severity threats
        high_threats = self.database.get_threats(limit=5, severity='HIGH')
        critical_threats = self.database.get_threats(limit=3, severity='CRITICAL')
        
        summary = f"""
Analysis Summary
================
Files Analyzed: {report['files_analyzed']}
Events Processed: {report['events_processed']}
Threats Detected: {report['threats_detected']}

Threat Breakdown:
  Total: {stats['total']}
  Critical: {stats['by_severity'].get('CRITICAL', 0)}
  High: {stats['by_severity'].get('HIGH', 0)}
  Medium: {stats['by_severity'].get('MEDIUM', 0)}
  Low: {stats['by_severity'].get('LOW', 0)}

Threat Types:
"""
        for threat_type, count in stats['by_type'].items():
            summary += f"  {threat_type}: {count}\n"
        
        if stats['top_sources']:
            summary += "\nTop Threat Sources:\n"
            for ip, count in stats['top_sources'][:10]:
                summary += f"  {ip}: {count} threats\n"
        
        # Add AI explanations section
        summary += "\n" + "="*60 + "\n"
        summary += "AI-Generated Threat Explanations\n"
        summary += "="*60 + "\n"
        
        if critical_threats:
            summary += "\n[CRITICAL SEVERITY THREATS]\n"
            for threat in critical_threats[:2]:
                summary += f"\nThreat #{threat.id}: {threat.description[:60]}...\n"
                if threat.ai_explanation:
                    summary += f"AI Explanation: {threat.ai_explanation}\n"
                else:
                    summary += "AI Explanation: (Fallback) " + self.ai_explainer._fallback_explanation(threat) + "\n"
        
        if high_threats:
            summary += "\n[HIGH SEVERITY THREATS]\n"
            for threat in high_threats[:3]:
                summary += f"\nThreat #{threat.id}: {threat.description[:60]}...\n"
                if threat.ai_explanation:
                    summary += f"AI Explanation: {threat.ai_explanation}\n"
                else:
                    summary += "AI Explanation: (Fallback) " + self.ai_explainer._fallback_explanation(threat) + "\n"
        
        return summary
    
    def generate_ai_explanations(self, threats: List[Threat], use_ai: bool = True) -> List[Threat]:
        """
        Generate AI explanations for selected threats.
        
        Args:
            threats: List of threats to generate explanations for
            use_ai: Whether to use AI (True) or fallback (False)
            
        Returns:
            List of threats with AI explanations added
        """
        for threat in threats:
            if threat.id:
                try:
                    explanation = self.ai_explainer.explain_threat(threat, use_ai=use_ai)
                    if explanation:
                        self.database.update_threat_explanation(threat.id, explanation)
                        threat.ai_explanation = explanation
                except Exception as e:
                    logger.warning(f"Failed to generate explanation for threat {threat.id}: {e}")
        
        return threats
    
    def close(self):
        """Close database connection."""
        self.database.close()
        logger.info("Historical analyzer closed")

