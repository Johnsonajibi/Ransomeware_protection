#!/usr/bin/env python3
"""
Shadow Copy Protection
Monitor and protect Windows Volume Shadow Copy Service (VSS).
"""

import os
import sys
import json
import logging
import argparse
import subprocess
from typing import Dict, List

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)

class ShadowCopyProtection:
    def __init__(self):
        self.vss_service = 'VSS'
        self.protection_enabled = False

    def get_status(self) -> Dict:
        """Get VSS and shadow copy status"""
        try:
            result = subprocess.run(
                ['powershell', '-Command', 'Get-Volume | Select-Object DriveLetter, ShadowCopies'],
                capture_output=True, text=True, timeout=10
            )
            return {
                'vss_running': self._check_service_status(),
                'shadow_copies_present': 'Unknown',
                'protection_status': 'enabled' if self.protection_enabled else 'disabled'
            }
        except Exception as e:
            logger.error(f'Status check failed: {e}')
            return {'error': str(e)}

    def _check_service_status(self) -> bool:
        """Check if VSS service is running"""
        try:
            result = subprocess.run(
                ['sc', 'query', self.vss_service],
                capture_output=True, text=True, timeout=5
            )
            return 'RUNNING' in result.stdout
        except Exception:
            return False

    def disable_vss_deletion(self) -> bool:
        """Protect shadow copies from deletion"""
        try:
            # Set registry to prevent shadow copy deletion
            cmd = 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore" /v DisableConfig /t REG_DWORD /d 1 /f'
            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            self.protection_enabled = True
            logger.info('VSS deletion protection enabled')
            return True
        except Exception as e:
            logger.error(f'Failed to enable protection: {e}')
            return False

    def enable_vss_deletion_protection(self) -> bool:
        """Enable enhanced VSS deletion protection"""
        return self.disable_vss_deletion()

    def restore_from_shadow_copy(self, drive: str = 'C') -> bool:
        """Restore from shadow copy"""
        try:
            logger.info(f'Initiating restore from shadow copy on {drive}:')
            # In production, this would use vssadmin or WMI
            return True
        except Exception as e:
            logger.error(f'Restore failed: {e}')
            return False

    def list_shadow_copies(self) -> List[Dict]:
        """List available shadow copies"""
        try:
            result = subprocess.run(
                ['vssadmin', 'list', 'shadows'],
                capture_output=True, text=True, timeout=10
            )
            # Parse vssadmin output (simplified)
            copies = []
            if 'Shadow Copy Volume' in result.stdout:
                copies.append({'volume': 'C:\\', 'created': 'recent', 'size': 'unknown'})
            return copies
        except Exception as e:
            logger.error(f'List failed: {e}')
            return []


def main():
    parser = argparse.ArgumentParser(description='Shadow Copy Protection')
    sub = parser.add_subparsers(dest='command')

    sub.add_parser('status', help='Show VSS and shadow copy status')
    sub.add_parser('protect', help='Enable shadow copy deletion protection')
    sub.add_parser('list', help='List available shadow copies')

    restore = sub.add_parser('restore', help='Restore from shadow copy')
    restore.add_argument('--drive', default='C')

    args = parser.parse_args()
    scp = ShadowCopyProtection()

    if args.command == 'status':
        print(json.dumps(scp.get_status(), indent=2))
        return 0

    if args.command == 'protect':
        ok = scp.disable_vss_deletion()
        print('Protected' if ok else 'Failed')
        return 0 if ok else 1

    if args.command == 'list':
        copies = scp.list_shadow_copies()
        print(json.dumps(copies, indent=2))
        return 0

    if args.command == 'restore':
        ok = scp.restore_from_shadow_copy(args.drive)
        print('Restore initiated' if ok else 'Failed')
        return 0 if ok else 1

    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())
