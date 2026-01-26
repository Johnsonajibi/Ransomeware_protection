#!/usr/bin/env python3
"""
View Audit Logs
Query and export audit logs for compliance, debugging, and monitoring.
"""

import os
import sys
import json
import logging
import argparse
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)

class AuditLogViewer:
    def __init__(self, db_path: str = '.audit_logs/audit.db'):
        self.db_path = Path(db_path)
        self._ensure_db()

    def _ensure_db(self):
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    process_name TEXT,
                    process_id INTEGER,
                    action TEXT,
                    result TEXT,
                    details TEXT,
                    severity TEXT DEFAULT 'info',
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tpm_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation TEXT NOT NULL,
                    pcr_index INTEGER,
                    pcr_value TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f'DB init failed: {e}')

    def get_summary(self) -> Dict:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM audit_events')
            total = cursor.fetchone()[0] or 0
            cursor.execute('SELECT COUNT(*) FROM audit_events WHERE severity = "warning"')
            warnings = cursor.fetchone()[0] or 0
            cursor.execute('SELECT COUNT(*) FROM audit_events WHERE severity = "critical"')
            critical = cursor.fetchone()[0] or 0
            cursor.execute('SELECT COUNT(*) FROM tpm_events')
            tpm_count = cursor.fetchone()[0] or 0
            conn.close()
            return {
                'total_events': total,
                'warnings': warnings,
                'critical': critical,
                'tpm_events': tpm_count
            }
        except Exception as e:
            return {'error': str(e)}

    def get_recent(self, limit: int = 20) -> List[Dict]:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, event_type, process_name, action, result, severity, timestamp
                FROM audit_events ORDER BY id DESC LIMIT ?
            ''', (limit,))
            cols = ['id', 'event_type', 'process', 'action', 'result', 'severity', 'timestamp']
            rows = [dict(zip(cols, r)) for r in cursor.fetchall()]
            conn.close()
            return rows
        except Exception as e:
            return []

    def filter_by_type(self, event_type: str) -> List[Dict]:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, event_type, process_name, action, result, severity, timestamp
                FROM audit_events WHERE event_type = ? ORDER BY id DESC LIMIT 100
            ''', (event_type,))
            cols = ['id', 'event_type', 'process', 'action', 'result', 'severity', 'timestamp']
            rows = [dict(zip(cols, r)) for r in cursor.fetchall()]
            conn.close()
            return rows
        except Exception as e:
            return []

    def filter_by_process(self, process_name: str) -> List[Dict]:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, event_type, process_name, action, result, severity, timestamp
                FROM audit_events WHERE process_name LIKE ? ORDER BY id DESC LIMIT 100
            ''', (f'%{process_name}%',))
            cols = ['id', 'event_type', 'process', 'action', 'result', 'severity', 'timestamp']
            rows = [dict(zip(cols, r)) for r in cursor.fetchall()]
            conn.close()
            return rows
        except Exception as e:
            return []

    def filter_by_time(self, hours: int) -> List[Dict]:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            since = datetime.now() - timedelta(hours=hours)
            cursor.execute('''
                SELECT id, event_type, process_name, action, result, severity, timestamp
                FROM audit_events WHERE timestamp > ? ORDER BY id DESC
            ''', (since.isoformat(),))
            cols = ['id', 'event_type', 'process', 'action', 'result', 'severity', 'timestamp']
            rows = [dict(zip(cols, r)) for r in cursor.fetchall()]
            conn.close()
            return rows
        except Exception as e:
            return []

    def export(self, filepath: str) -> bool:
        try:
            events = self.get_recent(limit=10000)
            with open(filepath, 'w') as f:
                f.write("=== ANTI-RANSOMWARE AUDIT LOG EXPORT ===\n")
                f.write(f"Exported: {datetime.now().isoformat()}\n")
                f.write(f"Total Events: {len(events)}\n\n")
                for evt in events:
                    f.write(f"[{evt['timestamp']}] {evt['event_type']}: {evt['action']} ({evt['result']})\n")
                    f.write(f"  Process: {evt['process']} | Severity: {evt['severity']}\n\n")
            logger.info(f'Exported to {filepath}')
            return True
        except Exception as e:
            logger.error(f'Export failed: {e}')
            return False


def main():
    parser = argparse.ArgumentParser(description='View Audit Logs')
    sub = parser.add_subparsers(dest='command')

    sub.add_parser('summary', help='Show audit summary')
    sub.add_parser('recent', help='Show recent events')
    sub.add_parser('tpm', help='Show TPM events')

    proc = sub.add_parser('process', help='Filter by process name')
    proc.add_argument('process_name', nargs='?')

    export = sub.add_parser('export', help='Export logs to file')
    export.add_argument('filepath', nargs='?', default='audit_report.txt')

    time_cmd = sub.add_parser('time', help='Filter by time range')
    time_cmd.add_argument('--hours', type=int, default=24)

    args = parser.parse_args()
    viewer = AuditLogViewer()

    if args.command == 'summary':
        result = viewer.get_summary()
        print(json.dumps(result, indent=2))
        return 0

    if args.command == 'recent':
        events = viewer.get_recent()
        for evt in events:
            print(f"[{evt['timestamp']}] {evt['event_type']}: {evt['action']}")
        return 0

    if args.command == 'tpm':
        events = viewer.filter_by_type('tpm_operation')
        print(json.dumps(events, indent=2))
        return 0

    if args.command == 'process':
        if not args.process_name:
            print("Process name required")
            return 1
        events = viewer.filter_by_process(args.process_name)
        print(json.dumps(events, indent=2))
        return 0

    if args.command == 'export':
        ok = viewer.export(args.filepath)
        print("Exported" if ok else "Failed")
        return 0 if ok else 1

    if args.command == 'time':
        events = viewer.filter_by_time(args.hours)
        print(json.dumps(events, indent=2))
        return 0

    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())
