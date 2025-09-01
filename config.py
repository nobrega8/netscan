import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///netscan.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Network configuration
    NETSCAN_PORT = int(os.environ.get('NETSCAN_PORT', 2530))
    
    # Scan configuration
    SCAN_INTERVAL_MINUTES = int(os.environ.get('SCAN_INTERVAL_MINUTES', 30))
    NETWORK_RANGE = os.environ.get('NETWORK_RANGE', 'auto')  # auto-detect or specify like '192.168.1.0/24'
    
    # OUI database
    OUI_UPDATE_URL = 'http://standards-oui.ieee.org/oui/oui.txt'
    
    # Scanning configuration
    ENABLE_OS_DETECTION = os.environ.get('ENABLE_OS_DETECTION', 'false').lower() == 'true'