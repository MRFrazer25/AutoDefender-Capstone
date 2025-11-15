"""Configuration from env vars and INI files.

Loads settings from environment variables (preferred) or config.ini.
Sensitive data should use env vars, not be hardcoded.
"""

import os
from typing import Optional


class Config:
    """Configuration settings for AutoDefender."""
    
    # Suricata log file paths
    DEFAULT_SURICATA_LOG_PATH = "/var/log/suricata/eve.json"
    
    # Ollama settings
    OLLAMA_ENDPOINT = os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", None)  # No default - user must specify
    
    # Database settings
    DEFAULT_DB_PATH = "autodefender.db"
    
    # Detection thresholds
    PORT_SCAN_THRESHOLD = 10  # Number of ports from same IP to trigger port scan
    SUSPICIOUS_PORT_THRESHOLD = 1024  # Ports above this are suspicious if accessed unexpectedly
    
    # Action policies
    AUTO_APPROVE_LOW_SEVERITY = False
    AUTO_APPROVE_MEDIUM_SEVERITY = False
    AUTO_APPROVE_HIGH_SEVERITY = False
    AUTO_APPROVE_CRITICAL_SEVERITY = False  # Never auto-approve critical
    
    # Suricata integration settings
    SURICATA_ENABLED = os.getenv("SURICATA_ENABLED", "false").lower() == "true"
    SURICATA_RULES_DIR = os.getenv("SURICATA_RULES_DIR", "./suricata_rules")
    SURICATA_CONFIG_PATH = os.getenv("SURICATA_CONFIG_PATH", "")
    AUTO_APPROVE_SURICATA = os.getenv("AUTO_APPROVE_SURICATA", "false").lower() == "true"
    SURICATA_DRY_RUN = os.getenv("SURICATA_DRY_RUN", "false").lower() == "true"
    
    # UI settings
    REFRESH_RATE = 1.0  # Seconds between UI updates
    MAX_DISPLAYED_THREATS = 50
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration, optionally loading from file."""
        self.suricata_log_path = self.DEFAULT_SURICATA_LOG_PATH
        self.ollama_endpoint = self.OLLAMA_ENDPOINT
        self.ollama_model = self.OLLAMA_MODEL
        self.db_path = self.DEFAULT_DB_PATH
        
        # Initialize Suricata settings
        self.SURICATA_ENABLED = self.SURICATA_ENABLED
        self.SURICATA_RULES_DIR = self.SURICATA_RULES_DIR
        self.SURICATA_CONFIG_PATH = self.SURICATA_CONFIG_PATH
        self.AUTO_APPROVE_SURICATA = self.AUTO_APPROVE_SURICATA
        self.SURICATA_DRY_RUN = self.SURICATA_DRY_RUN
        
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)
    
    def load_from_file(self, config_file: str):
        """Load configuration from INI file."""
        import configparser
        config = configparser.ConfigParser()
        config.read(config_file)
        
        if 'suricata' in config:
            self.suricata_log_path = config['suricata'].get('log_path', self.suricata_log_path)
        
        if 'ollama' in config:
            self.ollama_endpoint = config['ollama'].get('endpoint', self.ollama_endpoint)
            self.ollama_model = config['ollama'].get('model', self.ollama_model)
        
        if 'database' in config:
            self.db_path = config['database'].get('path', self.db_path)
        
        if 'detection' in config:
            self.PORT_SCAN_THRESHOLD = config['detection'].getint('port_scan_threshold', self.PORT_SCAN_THRESHOLD)
            self.SUSPICIOUS_PORT_THRESHOLD = config['detection'].getint('suspicious_port_threshold', self.SUSPICIOUS_PORT_THRESHOLD)
        
        if 'suricata' in config:
            self.SURICATA_ENABLED = config['suricata'].getboolean('enabled', self.SURICATA_ENABLED)
            self.SURICATA_RULES_DIR = config['suricata'].get('rules_dir', self.SURICATA_RULES_DIR)
            self.SURICATA_CONFIG_PATH = config['suricata'].get('config_path', self.SURICATA_CONFIG_PATH)
            self.AUTO_APPROVE_SURICATA = config['suricata'].getboolean('auto_approve', self.AUTO_APPROVE_SURICATA)
            self.SURICATA_DRY_RUN = config['suricata'].getboolean('dry_run', self.SURICATA_DRY_RUN)
    
    @staticmethod
    def get_default() -> 'Config':
        """Get default configuration instance."""
        return Config()

