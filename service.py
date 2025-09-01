import os
import sys
import time
import threading
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask

# Add current directory to path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from scanner import NetworkScanner
from config import Config

class NetScanService:
    def __init__(self):
        self.scanner = NetworkScanner()
        self.scheduler = BackgroundScheduler()
        self.app = app
        
    def scan_job(self):
        """Background scanning job"""
        with self.app.app_context():
            try:
                print(f"[{datetime.now()}] Starting network scan...")
                devices = self.scanner.scan_network()
                self.scanner.mark_offline_devices()
                print(f"[{datetime.now()}] Scan completed. Found {len(devices)} devices.")
            except Exception as e:
                print(f"[{datetime.now()}] Scan error: {e}")
    
    def start(self):
        """Start the background scanning service"""
        print("Starting NetScan background service...")
        
        # Initialize database
        with self.app.app_context():
            db.create_all()
            print("Database initialized.")
        
        # Schedule periodic scans
        scan_interval = Config.SCAN_INTERVAL_MINUTES
        print(f"Scheduling network scans every {scan_interval} minutes...")
        
        self.scheduler.add_job(
            func=self.scan_job,
            trigger="interval",
            minutes=scan_interval,
            id='network_scan'
        )
        
        # Run initial scan only if not disabled
        if not Config.DISABLE_STARTUP_SCAN:
            print("Running initial startup scan...")
            threading.Thread(target=self.scan_job, daemon=True).start()
        else:
            print("Startup scan disabled (NETSCAN_DISABLE_STARTUP_SCAN=true)")
        
        # Start scheduler
        self.scheduler.start()
        print("Background service started.")
        
        # Start Flask app
        print(f"Starting web interface on http://0.0.0.0:{Config.NETSCAN_PORT}")
        self.app.run(host='0.0.0.0', port=Config.NETSCAN_PORT, debug=False, threaded=True)
    
    def stop(self):
        """Stop the background service"""
        if self.scheduler.running:
            self.scheduler.shutdown()
        print("Background service stopped.")

if __name__ == '__main__':
    service = NetScanService()
    
    try:
        service.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        service.stop()
    except Exception as e:
        print(f"Service error: {e}")
        service.stop()
        sys.exit(1)