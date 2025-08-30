"""
Database auto-healing utilities for SQLite.
This module provides functions to automatically add missing columns to existing SQLite databases.
"""
import os
import sqlite3
from sqlalchemy import inspect
from flask import current_app

def ensure_sqlite_columns():
    """
    Auto-healing for SQLite databases to add missing columns.
    Only runs for SQLite and when DISABLE_SQLITE_AUTOHEAL is not set.
    """
    from app import db
    
    # Check if auto-healing is disabled
    if os.environ.get('DISABLE_SQLITE_AUTOHEAL', '').lower() in ('1', 'true', 'yes'):
        return
    
    # Skip during migrations
    import sys
    if any(arg in sys.argv for arg in ['db', 'migrate', 'upgrade', 'downgrade']):
        return
    
    # Only run for SQLite databases
    if not db.engine.url.drivername.startswith("sqlite"):
        return
    
    try:
        # Get a raw connection to execute SQLite-specific commands
        conn = db.engine.raw_connection()
        cur = conn.cursor()
        
        # Define expected columns for each table
        expected_columns = {
            "device": {
                "id": "INTEGER",
                "hostname": "VARCHAR(255)",
                "ip_address": "VARCHAR(45)",
                "mac_address": "VARCHAR(17)",
                "brand": "VARCHAR(100)",
                "model": "VARCHAR(100)",
                "icon": "VARCHAR(50)",
                "image_path": "VARCHAR(255)",
                "is_online": "BOOLEAN",
                "last_seen": "DATETIME",
                "first_seen": "DATETIME",
                "open_ports": "TEXT",
                "person_id": "INTEGER",
                "merged_devices": "TEXT",
                "created_at": "DATETIME",
                "updated_at": "DATETIME",
                # Recent additions that might be missing
                "os_info": "VARCHAR(255)",
                "vendor": "VARCHAR(100)",
                "device_type": "VARCHAR(50)",
                "os_family": "VARCHAR(50)",
                "netbios_name": "VARCHAR(100)",
                "workgroup": "VARCHAR(100)",
                "services": "TEXT",
                "category": "VARCHAR(50)",
            },
            "person": {
                "id": "INTEGER",
                "name": "VARCHAR(100)",
                "email": "VARCHAR(100)",
                "image_path": "VARCHAR(255)",
                "created_at": "DATETIME",
            },
            "scan": {
                "id": "INTEGER",
                "device_id": "INTEGER",
                "ip_address": "VARCHAR(45)",
                "is_online": "BOOLEAN",
                "response_time": "FLOAT",
                "open_ports": "TEXT",
                "timestamp": "DATETIME",
            },
            "settings": {
                "id": "INTEGER",
                "key": "VARCHAR(100)",
                "value": "TEXT",
                "created_at": "DATETIME",
                "updated_at": "DATETIME",
            },
            "oui": {
                "id": "INTEGER",
                "prefix": "VARCHAR(8)",
                "manufacturer": "VARCHAR(100)",
                "created_at": "DATETIME",
            }
        }
        
        # Check each table and add missing columns
        for table_name, expected_cols in expected_columns.items():
            try:
                # Check if table exists
                cur.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
                if not cur.fetchone():
                    print(f"[sqlite autoheal] Table {table_name} does not exist, skipping")
                    continue
                
                # Get existing columns
                cur.execute(f"PRAGMA table_info({table_name})")
                existing_columns = {row[1] for row in cur.fetchall()}
                
                # Add missing columns
                for col_name, col_type in expected_cols.items():
                    if col_name not in existing_columns:
                        try:
                            cur.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")
                            print(f"[sqlite autoheal] Added {table_name}.{col_name} ({col_type})")
                        except sqlite3.Error as e:
                            print(f"[sqlite autoheal] Failed to add {table_name}.{col_name}: {e}")
                            
            except sqlite3.Error as e:
                print(f"[sqlite autoheal] Error processing table {table_name}: {e}")
                continue
        
        conn.commit()
        conn.close()
        print("[sqlite autoheal] Auto-healing completed")
        
    except Exception as e:
        print(f"[sqlite autoheal] Auto-healing failed: {e}")

def init_database_with_autoheal():
    """Initialize database with auto-healing"""
    from app import db
    
    # Run auto-healing first
    ensure_sqlite_columns()
    
    # Create tables if they don't exist (fallback for non-migration deployments)
    db.create_all()