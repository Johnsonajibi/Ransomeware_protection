#!/usr/bin/env python3
"""
Deployment Monitor
Check deployment status, health, and readiness across the system
"""

import os
import sys
import json
import logging
import argparse
import socket
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('deployment.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class DeploymentMonitor:
    """Monitor deployment status and health"""
    
    def __init__(self):
        self.checks = {}
        self.results = {}
    
    def check_service_running(self, service_name: str) -> bool:
        """Check if a Windows service is running"""
        try:
            result = subprocess.run(
                ['sc', 'query', service_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            return 'RUNNING' in result.stdout
        except Exception as e:
            logger.warning(f"Could not check service {service_name}: {e}")
            return False
    
    def check_port_listening(self, port: int) -> bool:
        """Check if a port is listening"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def check_file_exists(self, path: str) -> bool:
        """Check if a file exists"""
        return Path(path).exists()
    
    def check_database_connection(self, db_path: str) -> bool:
        """Check database connectivity"""
        try:
            import sqlite3
            conn = sqlite3.connect(db_path, timeout=5)
            cursor = conn.cursor()
            cursor.execute('SELECT 1')
            conn.close()
            return True
        except Exception as e:
            logger.warning(f"Database check failed: {e}")
            return False
    
    def check_kernel_driver(self) -> bool:
        """Check if kernel driver is loaded"""
        try:
            result = subprocess.run(
                ['sc', 'query', 'AntiRansomwareDriver'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return 'RUNNING' in result.stdout or 'STOPPED' in result.stdout
        except Exception:
            return False
    
    def check_python_dependencies(self) -> Tuple[bool, List[str]]:
        """Check required Python packages"""
        required = ['flask', 'grpc', 'sqlite3', 'yaml', 'psutil']
        missing = []
        
        for package in required:
            try:
                __import__(package)
            except ImportError:
                missing.append(package)
        
        return len(missing) == 0, missing
    
    def run_all_checks(self) -> Dict:
        """Run all deployment checks"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'checks': {},
            'summary': {}
        }
        
        # File checks
        results['checks']['config_file'] = self.check_file_exists('config.yaml')
        results['checks']['admin_config'] = self.check_file_exists('admin_config.json')
        results['checks']['database'] = self.check_file_exists('admin.db')
        
        # Database checks
        results['checks']['database_connection'] = self.check_database_connection('admin.db')
        
        # Service checks
        results['checks']['windows_service'] = self.check_service_running('AntiRansomware')
        
        # Driver checks
        results['checks']['kernel_driver'] = self.check_kernel_driver()
        
        # Port checks
        results['checks']['web_port_8080'] = self.check_port_listening(8080)
        results['checks']['grpc_port_50052'] = self.check_port_listening(50052)
        
        # Dependencies
        deps_ok, missing = self.check_python_dependencies()
        results['checks']['python_dependencies'] = deps_ok
        if not deps_ok:
            results['missing_packages'] = missing
        
        # Summary
        total = len(results['checks'])
        passed = sum(1 for v in results['checks'].values() if v)
        results['summary']['total_checks'] = total
        results['summary']['passed'] = passed
        results['summary']['failed'] = total - passed
        results['summary']['health'] = 'healthy' if passed >= total * 0.8 else 'degraded'
        
        return results
    
    def print_report(self, results: Dict):
        """Print deployment status report"""
        print("\n" + "="*70)
        print("DEPLOYMENT MONITORING REPORT")
        print("="*70)
        print(f"Timestamp: {results['timestamp']}")
        print(f"\nHealth Status: {results['summary']['health'].upper()}")
        print(f"Checks Passed: {results['summary']['passed']}/{results['summary']['total_checks']}")
        
        print("\nDetailed Results:")
        print("-"*70)
        
        for check_name, status in results['checks'].items():
            status_str = "PASS" if status else "FAIL"
            print(f"{check_name:.<40} {status_str}")
        
        if 'missing_packages' in results:
            print(f"\nMissing Python Packages: {', '.join(results['missing_packages'])}")
        
        print("="*70 + "\n")
    
    def check_all(self):
        """Run all checks and display report"""
        results = self.run_all_checks()
        self.print_report(results)
        
        if results['summary']['health'] != 'healthy':
            logger.warning("Deployment health is degraded")
            return 1
        
        logger.info("All deployment checks passed")
        return 0
    
    def check_specific(self, check_name: str):
        """Run a specific check"""
        results = self.run_all_checks()
        
        if check_name in results['checks']:
            status = results['checks'][check_name]
            status_str = "PASS" if status else "FAIL"
            print(f"{check_name}: {status_str}")
            return 0 if status else 1
        else:
            print(f"Unknown check: {check_name}")
            return 1

def main():
    parser = argparse.ArgumentParser(description="Deployment Monitor")
    parser.add_argument('--check-all', action='store_true', help='Run all checks')
    parser.add_argument('--check', metavar='NAME', help='Run specific check')
    parser.add_argument('--continuous', action='store_true', help='Run checks continuously')
    parser.add_argument('--interval', type=int, default=60, help='Check interval in seconds')
    
    args = parser.parse_args()
    
    monitor = DeploymentMonitor()
    
    if args.check_all:
        return monitor.check_all()
    
    elif args.check:
        return monitor.check_specific(args.check)
    
    elif args.continuous:
        import time
        logger.info(f"Starting continuous monitoring (interval: {args.interval}s)")
        try:
            while True:
                monitor.check_all()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped")
            return 0
    
    else:
        parser.print_help()
        return 0

if __name__ == "__main__":
    sys.exit(main())
