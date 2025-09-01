import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///netscan.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # SQLite WAL mode and busy timeout configuration to prevent database locking
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {
            "timeout": 30,
            "check_same_thread": False
        },
        "pool_pre_ping": True,
        "pool_recycle": 300
    }
    
    # Network configuration
    NETSCAN_PORT = int(os.environ.get('NETSCAN_PORT', 2530))
    
    # Scan configuration
    SCAN_INTERVAL_MINUTES = int(os.environ.get('SCAN_INTERVAL_MINUTES', 30))
    NETWORK_RANGE = os.environ.get('NETWORK_RANGE', 'auto')  # auto-detect or specify like '192.168.1.0/24'
    
    # OUI database
    OUI_UPDATE_URL = 'http://standards-oui.ieee.org/oui/oui.txt'
    
    # Scanning configuration - disable OS detection by default (requires root privileges)
    ENABLE_OS_DETECTION = os.environ.get('ENABLE_OS_DETECTION', 'false').lower() == 'true'
    # Disable SYN scanning by default (requires root privileges)
    ENABLE_SYN_SCAN = os.environ.get('ENABLE_SYN_SCAN', 'false').lower() == 'true'