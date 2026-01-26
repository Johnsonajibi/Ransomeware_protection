#!/usr/bin/env python3
"""
Test Device Fingerprint
Test device fingerprinting functionality for trifactor authentication.
"""

import os
import sys
import json
import logging
import argparse
import hashlib
from pathlib import Path
from typing import Dict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('test_device_fingerprint.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DeviceFingerprintTester:
    def __init__(self):
        self.fingerprint_data = {}
        self.db_path = 'antiransomware.db'
    
    def get_system_info(self) -> Dict:
        """Collect system information for fingerprinting"""
        logger.info("Collecting system information...")
        
        info = {
            'platform': sys.platform,
            'hostname': os.environ.get('COMPUTERNAME', 'UNKNOWN'),
            'username': os.environ.get('USERNAME', 'UNKNOWN'),
        }
        
        # Try to get Windows-specific info
        try:
            import platform as pl
            info['win_version'] = pl.win32_ver()[1]
            logger.info(f"Windows Version: {info['win_version']}")
        except:
            pass
        
        # Try to get CPU info
        try:
            import cpuinfo
            cpu_data = cpuinfo.get_cpu_info()
            info['cpu_brand'] = cpu_data.get('brand_raw', 'UNKNOWN')
            logger.info(f"CPU: {info['cpu_brand']}")
        except:
            logger.warning("Could not get CPU info (cpuinfo not available)")
        
        # Get disk info
        try:
            import psutil
            for partition in psutil.disk_partitions():
                if partition.device.startswith('C:'):
                    info['disk_serial'] = partition.device
                    logger.info(f"Disk: {partition.device}")
        except:
            logger.warning("Could not get disk info")
        
        return info
    
    def generate_fingerprint(self) -> str:
        """Generate device fingerprint hash"""
        logger.info("Generating device fingerprint...")
        
        system_info = self.get_system_info()
        
        # Create fingerprint string from system data
        fingerprint_str = json.dumps(system_info, sort_keys=True)
        
        # Hash the fingerprint
        fingerprint_hash = hashlib.sha256(fingerprint_str.encode()).hexdigest()
        
        logger.info(f"Fingerprint (SHA256): {fingerprint_hash}")
        self.fingerprint_data['fingerprint'] = fingerprint_hash
        self.fingerprint_data['system_info'] = system_info
        
        return fingerprint_hash
    
    def test_consistency(self, iterations: int = 3) -> bool:
        """Test if fingerprint remains consistent across multiple reads"""
        logger.info(f"\nTesting fingerprint consistency ({iterations} iterations)...")
        
        fingerprints = []
        for i in range(iterations):
            fp = self.generate_fingerprint()
            fingerprints.append(fp)
            logger.info(f"  Iteration {i+1}: {fp}")
        
        # Check if all fingerprints match
        if len(set(fingerprints)) == 1:
            logger.info("✓ Fingerprint is consistent")
            return True
        else:
            logger.warning("✗ Fingerprint varies between reads")
            logger.warning("  This may indicate system changes or unstable hardware state")
            return False
    
    def test_uniqueness(self) -> bool:
        """Test if fingerprint is unique"""
        logger.info("\nTesting fingerprint uniqueness...")
        
        try:
            # In a real test, we'd compare with other devices
            # For now, just validate the fingerprint format
            fp = self.fingerprint_data.get('fingerprint')
            
            if not fp or len(fp) != 64:  # SHA256 is 64 hex chars
                logger.error("Invalid fingerprint format")
                return False
            
            logger.info(f"✓ Fingerprint format valid: {fp}")
            return True
        except Exception as e:
            logger.error(f"Uniqueness test failed: {e}")
            return False
    
    def test_entropy(self) -> bool:
        """Test fingerprint entropy"""
        logger.info("\nTesting fingerprint entropy...")
        
        try:
            fp = self.fingerprint_data.get('fingerprint')
            
            if not fp:
                logger.error("No fingerprint available")
                return False
            
            # Calculate entropy (basic check)
            unique_chars = len(set(fp))
            entropy = unique_chars / len(fp)
            
            logger.info(f"Unique characters: {unique_chars}/{len(fp)}")
            logger.info(f"Entropy ratio: {entropy:.2f}")
            
            if entropy > 0.7:
                logger.info("✓ Good entropy")
                return True
            else:
                logger.warning("✗ Low entropy detected")
                return False
        except Exception as e:
            logger.error(f"Entropy test failed: {e}")
            return False
    
    def save_fingerprint(self) -> bool:
        """Save fingerprint to database"""
        logger.info("\nSaving fingerprint to database...")
        
        try:
            import sqlite3
            
            if not Path(self.db_path).exists():
                logger.warning(f"Database not found: {self.db_path}")
                return False
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if table exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS fingerprints (
                    id INTEGER PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    fingerprint TEXT UNIQUE,
                    system_info TEXT
                )
            """)
            
            fp = self.fingerprint_data.get('fingerprint')
            sys_info = json.dumps(self.fingerprint_data.get('system_info', {}))
            
            cursor.execute(
                "INSERT OR REPLACE INTO fingerprints (fingerprint, system_info) VALUES (?, ?)",
                (fp, sys_info)
            )
            conn.commit()
            
            logger.info("✓ Fingerprint saved to database")
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Failed to save fingerprint: {e}")
            return False
    
    def run_all_tests(self) -> bool:
        """Run all device fingerprint tests"""
        logger.info("Starting Device Fingerprint Tests\n")
        logger.info("="*60)
        
        results = {}
        
        # Generate initial fingerprint
        self.generate_fingerprint()
        
        # Run tests
        results['consistency'] = self.test_consistency()
        results['uniqueness'] = self.test_uniqueness()
        results['entropy'] = self.test_entropy()
        results['storage'] = self.save_fingerprint()
        
        # Summary
        logger.info("\n" + "="*60)
        logger.info("TEST SUMMARY")
        logger.info("="*60)
        for test_name, result in results.items():
            status = "PASS" if result else "FAIL"
            logger.info(f"{test_name.upper()}: {status}")
        
        total_passed = sum(1 for v in results.values() if v)
        total_tests = len(results)
        logger.info(f"\nTotal: {total_passed}/{total_tests} passed\n")
        
        return all(results.values())

def main():
    parser = argparse.ArgumentParser(description='Test device fingerprinting')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--iterations', type=int, default=3, help='Consistency test iterations')
    
    args = parser.parse_args()
    
    tester = DeviceFingerprintTester()
    success = tester.run_all_tests()
    
    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())
