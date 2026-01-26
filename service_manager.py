#!/usr/bin/env python3
"""
Service Manager
Install, start, stop, and manage AntiRansomware services.
"""

import os
import sys
import json
import logging
import argparse
import subprocess
import sqlite3
from pathlib import Path
from typing import Dict, List

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('service_manager.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class ServiceManager:
    SERVICES = {
        'AntiRansomwareDriver': 'AntiRansomware Kernel Driver',
        'AntiRansomwareMonitor': 'AntiRansomware Monitor Service',
        'AntiRansomwareSIEM': 'AntiRansomware SIEM Integration Service'
    }

    def __init__(self, db_path: str = 'protection_db.sqlite'):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS service_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_name TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f'DB init failed: {e}')

    def _log_action(self, service: str, action: str, status: str, details: str = None):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO service_history (service_name, action, status, details)
                VALUES (?, ?, ?, ?)
            ''', (service, action, status, details))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f'Log failed: {e}')

    def install(self, service: str, binary_path: str = None) -> bool:
        if service not in self.SERVICES:
            logger.error(f'Unknown service: {service}')
            return False
        try:
            desc = self.SERVICES[service]
            default_path = f'C:\\Program Files\\AntiRansomware\\{service}.exe'
            bin_path = binary_path or default_path
            cmd = ['sc', 'create', service, f'binPath= {bin_path}']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            ok = result.returncode == 0
            self._log_action(service, 'install', 'success' if ok else 'failed', result.stderr or result.stdout)
            logger.info(f'Install {service}: {"ok" if ok else "failed"}')
            return ok
        except Exception as e:
            logger.error(f'Install failed: {e}')
            self._log_action(service, 'install', 'error', str(e))
            return False

    def start(self, service: str) -> bool:
        if service not in self.SERVICES:
            return False
        try:
            result = subprocess.run(['sc', 'start', service], capture_output=True, text=True, timeout=15)
            ok = result.returncode == 0
            self._log_action(service, 'start', 'success' if ok else 'failed', result.stderr or result.stdout)
            logger.info(f'Start {service}: {"ok" if ok else "failed"}')
            return ok
        except Exception as e:
            logger.error(f'Start failed: {e}')
            self._log_action(service, 'start', 'error', str(e))
            return False

    def stop(self, service: str) -> bool:
        if service not in self.SERVICES:
            return False
        try:
            result = subprocess.run(['sc', 'stop', service], capture_output=True, text=True, timeout=15)
            ok = result.returncode == 0
            self._log_action(service, 'stop', 'success' if ok else 'failed', result.stderr or result.stdout)
            logger.info(f'Stop {service}: {"ok" if ok else "failed"}')
            return ok
        except Exception as e:
            logger.error(f'Stop failed: {e}')
            self._log_action(service, 'stop', 'error', str(e))
            return False

    def uninstall(self, service: str) -> bool:
        if service not in self.SERVICES:
            return False
        try:
            result = subprocess.run(['sc', 'delete', service], capture_output=True, text=True, timeout=15)
            ok = result.returncode == 0
            self._log_action(service, 'uninstall', 'success' if ok else 'failed', result.stderr or result.stdout)
            logger.info(f'Uninstall {service}: {"ok" if ok else "failed"}')
            return ok
        except Exception as e:
            logger.error(f'Uninstall failed: {e}')
            self._log_action(service, 'uninstall', 'error', str(e))
            return False

    def status(self, service: str = None) -> Dict:
        services = [service] if service and service in self.SERVICES else list(self.SERVICES.keys())
        result = {}
        for svc in services:
            try:
                res = subprocess.run(['sc', 'query', svc], capture_output=True, text=True, timeout=5)
                result[svc] = 'running' if 'RUNNING' in res.stdout else 'stopped'
            except Exception:
                result[svc] = 'unknown'
        return result

    def history(self, service: str = None, limit: int = 10) -> List[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            if service:
                cursor.execute('''
                    SELECT service_name, action, status, timestamp, details FROM service_history
                    WHERE service_name = ? ORDER BY id DESC LIMIT ?
                ''', (service, limit))
            else:
                cursor.execute('''
                    SELECT service_name, action, status, timestamp, details FROM service_history
                    ORDER BY id DESC LIMIT ?
                ''', (limit,))
            cols = ['service', 'action', 'status', 'timestamp', 'details']
            rows = [dict(zip(cols, r)) for r in cursor.fetchall()]
            conn.close()
            return rows
        except Exception as e:
            logger.error(f'History query failed: {e}')
            return []


def main():
    parser = argparse.ArgumentParser(description='Service Manager')
    sub = parser.add_subparsers(dest='command')

    inst = sub.add_parser('install', help='Install service')
    inst.add_argument('service', choices=['AntiRansomwareDriver', 'AntiRansomwareMonitor', 'AntiRansomwareSIEM'])
    inst.add_argument('--binary')

    start_cmd = sub.add_parser('start', help='Start service')
    start_cmd.add_argument('service', choices=['AntiRansomwareDriver', 'AntiRansomwareMonitor', 'AntiRansomwareSIEM'])

    stop_cmd = sub.add_parser('stop', help='Stop service')
    stop_cmd.add_argument('service', choices=['AntiRansomwareDriver', 'AntiRansomwareMonitor', 'AntiRansomwareSIEM'])

    uninst = sub.add_parser('uninstall', help='Uninstall service')
    uninst.add_argument('service', choices=['AntiRansomwareDriver', 'AntiRansomwareMonitor', 'AntiRansomwareSIEM'])

    stat = sub.add_parser('status', help='Show service status')
    stat.add_argument('--service')

    hist = sub.add_parser('history', help='Service action history')
    hist.add_argument('--service')
    hist.add_argument('--limit', type=int, default=10)

    args = parser.parse_args()
    mgr = ServiceManager()

    if args.command == 'install':
        ok = mgr.install(args.service, args.binary)
        print('Installed' if ok else 'Failed')
        return 0 if ok else 1

    if args.command == 'start':
        ok = mgr.start(args.service)
        print('Started' if ok else 'Failed')
        return 0 if ok else 1

    if args.command == 'stop':
        ok = mgr.stop(args.service)
        print('Stopped' if ok else 'Failed')
        return 0 if ok else 1

    if args.command == 'uninstall':
        ok = mgr.uninstall(args.service)
        print('Uninstalled' if ok else 'Failed')
        return 0 if ok else 1

    if args.command == 'status':
        print(json.dumps(mgr.status(args.service), indent=2))
        return 0

    if args.command == 'history':
        print(json.dumps(mgr.history(args.service, args.limit), indent=2))
        return 0

    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())
