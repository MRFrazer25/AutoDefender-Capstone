"""Configuration from env vars and INI files.

Loads settings from environment variables (preferred) or config.ini.
Sensitive data should use env vars, not be hardcoded.
"""

import os
from typing import Optional


class Config:
    """Configuration settings for AutoDefender."""
    
    # Suricata log file paths (can be comma-separated for multiple sources)
    DEFAULT_SURICATA_LOG_PATH = "/var/log/suricata/eve.json"
    
    # Ollama settings
    OLLAMA_ENDPOINT = os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", None)  # No default - user must specify

    # Notification settings
    WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")
    
    # Database settings
    DEFAULT_DB_PATH = os.getenv("AUTODEFENDER_DB_PATH", "autodefender.db")
    
    # Detection thresholds
    PORT_SCAN_THRESHOLD = 10  # Distinct ports from one IP within the window that count as a scan
    PORT_SCAN_WINDOW_SECONDS = 60  # Sliding window for port scan detection
    ALERT_COOLDOWN_SECONDS = 600  # Suppress repeat detections for the same source for this long
    
    # Data retention: threats older than this many days can be purged (0 = keep forever)
    RETENTION_DAYS = int(os.getenv("AUTODEFENDER_RETENTION_DAYS", "90") or 0)
    
    # Suricata integration settings
    SURICATA_ENABLED = os.getenv("SURICATA_ENABLED", "false").lower() == "true"
    SURICATA_RULES_DIR = os.getenv("SURICATA_RULES_DIR", "./suricata_rules")
    AUTO_APPROVE_SURICATA = os.getenv("AUTO_APPROVE_SURICATA", "false").lower() == "true"
    SURICATA_DRY_RUN = os.getenv("SURICATA_DRY_RUN", "false").lower() == "true"
    # How long a drop rule stays in place (0 = permanent until you unblock it)
    BLOCK_DURATION_HOURS = float(os.getenv("AUTODEFENDER_BLOCK_HOURS", "0") or 0)
    # Reload Suricata's rules with suricatasc after every change (needs the unix socket enabled)
    SURICATA_AUTO_RELOAD = os.getenv("SURICATA_AUTO_RELOAD", "false").lower() == "true"
    SURICATA_SOCKET = os.getenv("SURICATA_SOCKET", "")
    
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
        self.AUTO_APPROVE_SURICATA = self.AUTO_APPROVE_SURICATA
        self.SURICATA_DRY_RUN = self.SURICATA_DRY_RUN
        self.BLOCK_DURATION_HOURS = self.BLOCK_DURATION_HOURS
        self.SURICATA_AUTO_RELOAD = self.SURICATA_AUTO_RELOAD
        self.SURICATA_SOCKET = self.SURICATA_SOCKET
        
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
            self.PORT_SCAN_WINDOW_SECONDS = config['detection'].getint('port_scan_window_seconds', self.PORT_SCAN_WINDOW_SECONDS)
            self.ALERT_COOLDOWN_SECONDS = config['detection'].getint('alert_cooldown_seconds', self.ALERT_COOLDOWN_SECONDS)
        
        if 'suricata' in config:
            self.SURICATA_ENABLED = config['suricata'].getboolean('enabled', self.SURICATA_ENABLED)
            self.SURICATA_RULES_DIR = config['suricata'].get('rules_dir', self.SURICATA_RULES_DIR)
            self.AUTO_APPROVE_SURICATA = config['suricata'].getboolean('auto_approve', self.AUTO_APPROVE_SURICATA)
            self.SURICATA_DRY_RUN = config['suricata'].getboolean('dry_run', self.SURICATA_DRY_RUN)
            self.BLOCK_DURATION_HOURS = config['suricata'].getfloat('block_hours', self.BLOCK_DURATION_HOURS)
            self.SURICATA_AUTO_RELOAD = config['suricata'].getboolean('auto_reload', self.SURICATA_AUTO_RELOAD)
            self.SURICATA_SOCKET = config['suricata'].get('socket', self.SURICATA_SOCKET)
    
    @staticmethod
    def get_default() -> 'Config':
        """Get default configuration instance."""
        return Config()

