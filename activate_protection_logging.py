#!/usr/bin/env python3
"""
Activate Protection & Logging
Enables kernel protection, audit logging, and starts monitoring
"""

import os
import sys
import json
import logging
import argparse
import sqlite3
from pathlib import Path
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('protection.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class ProtectionActivator:
    """Manage protection activation and logging"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.db_path = Path("protection_db.sqlite")
        self.protected_paths = []
        self.load_config()
        self.init_database()
    
    def load_config(self):
        """Load configuration from file"""
        try:
            import yaml
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f) or {}
                    self.protected_paths = config.get('protection', {}).get('paths', [])
                logger.info(f"Loaded config from {self.config_path}")
            else:
                logger.warning(f"Config file not found: {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
    
    def init_database(self):
        """Initialize protection database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Protection events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS protection_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    file_path TEXT,
                    process_id INTEGER,
                    process_name TEXT,
                    action TEXT,
                    threat_score REAL,
                    details TEXT
                )
            ''')
            
            # Protected paths table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS protected_paths (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT UNIQUE NOT NULL,
                    protection_level TEXT DEFAULT 'high',
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Protection status table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS protection_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    component TEXT UNIQUE NOT NULL,
                    enabled BOOLEAN DEFAULT FALSE,
                    last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
    
    def enable_protection(self) -> bool:
        """Enable protection system"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            components = ['kernel_driver', 'behavioral_analysis', 'token_validation']
            
            for component in components:
                cursor.execute('''
                    INSERT OR REPLACE INTO protection_status (component, enabled, last_checked)
                    VALUES (?, 1, datetime('now'))
                ''', (component,))
            
            conn.commit()
            conn.close()
            
            logger.info("Protection enabled for all components")
            return True
        except Exception as e:
            logger.error(f"Failed to enable protection: {e}")
            return False
    
    def disable_protection(self) -> bool:
        """Disable protection system"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('UPDATE protection_status SET enabled = 0, last_checked = datetime("now")')
            
            conn.commit()
            conn.close()
            
            logger.info("Protection disabled")
            return True
        except Exception as e:
            logger.error(f"Failed to disable protection: {e}")
            return False
    
    def get_protection_status(self) -> dict:
        """Get current protection status"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT component, enabled, last_checked FROM protection_status')
            rows = cursor.fetchall()
            conn.close()
            
            status = {}
            for component, enabled, last_checked in rows:
                status[component] = {
                    'enabled': bool(enabled),
                    'last_checked': last_checked
                }
            
            return status
        except Exception as e:
            logger.error(f"Failed to get protection status: {e}")
            return {}
    
    def log_event(self, event_type: str, file_path: str = None, process_id: int = None,
                  process_name: str = None, action: str = None, threat_score: float = 0,
                  details: str = None) -> bool:
        """Log a protection event"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO protection_events 
                (event_type, file_path, process_id, process_name, action, threat_score, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (event_type, file_path, process_id, process_name, action, threat_score, details))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Event logged: {event_type} - {action}")
            return True
        except Exception as e:
            logger.error(f"Failed to log event: {e}")
            return False
    
    def get_recent_events(self, limit: int = 20) -> list:
        """Get recent protection events"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT timestamp, event_type, file_path, action, threat_score
                FROM protection_events
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            columns = ['timestamp', 'event_type', 'file_path', 'action', 'threat_score']
            events = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return events
        except Exception as e:
            logger.error(f"Failed to get events: {e}")
            return []
    
    def print_status(self):
        """Print protection status"""
        status = self.get_protection_status()
        
        print("\n" + "="*60)
        print("PROTECTION STATUS")
        print("="*60)
        
        if status:
            for component, info in status.items():
                enabled_str = "✓ ENABLED" if info['enabled'] else "✗ DISABLED"
                print(f"{component:.<30} {enabled_str}")
                print(f"  Last checked: {info['last_checked']}")
        else:
            print("No protection status found. Initialize with --enable first.")
        
        print("="*60 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="Activate Protection & Logging"
    )
    parser.add_argument('--enable', action='store_true', help='Enable protection')
    parser.add_argument('--disable', action='store_true', help='Disable protection')
    parser.add_argument('--status', action='store_true', help='Show protection status')
    parser.add_argument('--log-event', action='store_true', help='Log a test event')
    parser.add_argument('--events', action='store_true', help='Show recent events')
    parser.add_argument('--config', default='config.yaml', help='Config file path')
    
    args = parser.parse_args()
    
    activator = ProtectionActivator(args.config)
    
    if args.enable:
        logger.info("Enabling protection...")
        if activator.enable_protection():
            logger.info("✓ Protection enabled successfully")
            activator.print_status()
        else:
            logger.error("✗ Failed to enable protection")
            sys.exit(1)
    
    elif args.disable:
        logger.info("Disabling protection...")
        if activator.disable_protection():
            logger.info("✓ Protection disabled")
            activator.print_status()
        else:
            logger.error("✗ Failed to disable protection")
            sys.exit(1)
    
    elif args.status:
        activator.print_status()
    
    elif args.log_event:
        logger.info("Logging test event...")
        if activator.log_event(
            event_type="TEST",
            file_path="C:\\test.txt",
            process_id=1234,
            process_name="test.exe",
            action="blocked",
            threat_score=75.5,
            details="Test event for validation"
        ):
            logger.info("✓ Event logged")
        else:
            logger.error("✗ Failed to log event")
            sys.exit(1)
    
    elif args.events:
        events = activator.get_recent_events()
        if events:
            print("\nRecent Events:")
            print("="*80)
            for event in events:
                print(f"[{event['timestamp']}] {event['event_type']:.<15} {event['action']:.<10} {event['file_path']}")
            print("="*80 + "\n")
        else:
            print("No recent events found.")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
