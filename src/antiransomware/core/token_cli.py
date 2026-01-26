#!/usr/bin/env python3
"""
AR Token Management
Manage access tokens, device fingerprints, and token-based security
"""

import os
import sys
import json
import logging
import argparse
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ar_token.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class ARTokenManager:
    """Manage anti-ransomware tokens"""
    
    def __init__(self, db_path: str = "admin.db"):
        self.db_path = Path(db_path)
        self.init_database()
    
    def init_database(self):
        """Initialize token database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id TEXT UNIQUE NOT NULL,
                    process_id INTEGER,
                    process_name TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    status TEXT DEFAULT 'active',
                    hardware_signature TEXT,
                    tpm_verified BOOLEAN DEFAULT FALSE
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS token_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id TEXT,
                    action TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database init failed: {e}")
    
    def generate_token(self, process_name: str, process_id: int = None, 
                      ttl_hours: int = 24) -> str:
        """Generate a new access token"""
        try:
            token_data = {
                'process': process_name,
                'pid': process_id or os.getpid(),
                'created': datetime.now().isoformat(),
                'expires': (datetime.now() + timedelta(hours=ttl_hours)).isoformat()
            }
            
            token_str = json.dumps(token_data)
            token_hash = hashlib.sha256(token_str.encode()).hexdigest()
            token_id = f"tok_{token_hash[:16]}"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            expires = datetime.now() + timedelta(hours=ttl_hours)
            cursor.execute('''
                INSERT INTO tokens (token_id, process_name, process_id, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (token_id, process_name, process_id, expires))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Generated token: {token_id} for {process_name}")
            return token_id
        except Exception as e:
            logger.error(f"Token generation failed: {e}")
            return None
    
    def revoke_token(self, token_id: str) -> bool:
        """Revoke a token"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'UPDATE tokens SET status = ? WHERE token_id = ?',
                ('revoked', token_id)
            )
            
            cursor.execute(
                'INSERT INTO token_audit (token_id, action, details) VALUES (?, ?, ?)',
                (token_id, 'revoked', 'Token revoked via CLI')
            )
            
            conn.commit()
            conn.close()
            
            logger.info(f"Revoked token: {token_id}")
            return True
        except Exception as e:
            logger.error(f"Token revocation failed: {e}")
            return False
    
    def revoke_process_tokens(self, process_name: str) -> int:
        """Revoke all tokens for a process"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT token_id FROM tokens WHERE process_name = ? AND status = ?',
                (process_name, 'active')
            )
            
            tokens = cursor.fetchall()
            count = 0
            
            for (token_id,) in tokens:
                cursor.execute(
                    'UPDATE tokens SET status = ? WHERE token_id = ?',
                    ('revoked', token_id)
                )
                count += 1
            
            conn.commit()
            conn.close()
            
            logger.info(f"Revoked {count} token(s) for process: {process_name}")
            return count
        except Exception as e:
            logger.error(f"Process token revocation failed: {e}")
            return 0
    
    def revoke_before_date(self, date_str: str) -> int:
        """Revoke tokens created before a date"""
        try:
            date_obj = datetime.fromisoformat(date_str)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT token_id FROM tokens WHERE created_at < ? AND status = ?',
                (date_obj, 'active')
            )
            
            tokens = cursor.fetchall()
            count = 0
            
            for (token_id,) in tokens:
                cursor.execute(
                    'UPDATE tokens SET status = ? WHERE token_id = ?',
                    ('revoked', token_id)
                )
                count += 1
            
            conn.commit()
            conn.close()
            
            logger.info(f"Revoked {count} token(s) created before {date_str}")
            return count
        except Exception as e:
            logger.error(f"Date-based revocation failed: {e}")
            return 0
    
    def list_tokens(self, status_filter: str = None) -> List[Dict]:
        """List tokens with optional status filter"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if status_filter:
                cursor.execute(
                    'SELECT token_id, process_name, status, created_at, expires_at FROM tokens WHERE status = ? ORDER BY created_at DESC',
                    (status_filter,)
                )
            else:
                cursor.execute(
                    'SELECT token_id, process_name, status, created_at, expires_at FROM tokens ORDER BY created_at DESC'
                )
            
            columns = ['token_id', 'process_name', 'status', 'created_at', 'expires_at']
            tokens = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return tokens
        except Exception as e:
            logger.error(f"Token listing failed: {e}")
            return []
    
    def check_failures(self, since: str = None) -> List[Dict]:
        """Check token validation failures"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if since:
                since_dt = datetime.now() - timedelta(hours=1)
                cursor.execute('''
                    SELECT token_id, action, timestamp, details FROM token_audit
                    WHERE action = 'validation_failure' AND timestamp > ?
                    ORDER BY timestamp DESC
                ''', (since_dt,))
            else:
                cursor.execute('''
                    SELECT token_id, action, timestamp, details FROM token_audit
                    WHERE action = 'validation_failure'
                    ORDER BY timestamp DESC LIMIT 20
                ''')
            
            columns = ['token_id', 'action', 'timestamp', 'details']
            failures = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return failures
        except Exception as e:
            logger.error(f"Failure check failed: {e}")
            return []
    
    def debug_token(self, token_id: str) -> Dict:
        """Debug a specific token"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT * FROM tokens WHERE token_id = ?',
                (token_id,)
            )
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return {'error': 'Token not found'}
            
            columns = ['id', 'token_id', 'process_id', 'process_name', 'created_at', 
                      'expires_at', 'status', 'hardware_signature', 'tpm_verified']
            token_info = dict(zip(columns, row))
            
            return token_info
        except Exception as e:
            logger.error(f"Token debug failed: {e}")
            return {'error': str(e)}
    
    def print_tokens(self, tokens: List[Dict]):
        """Print token list in table format"""
        if not tokens:
            print("No tokens found.")
            return
        
        print("\n" + "="*100)
        print(f"{'TOKEN ID':<20} {'PROCESS':<25} {'STATUS':<10} {'CREATED':<20} {'EXPIRES':<20}")
        print("="*100)
        
        for token in tokens:
            created = token['created_at'].split('T')[0] if token['created_at'] else 'N/A'
            expires = token['expires_at'].split('T')[0] if token['expires_at'] else 'N/A'
            print(f"{token['token_id']:<20} {token['process_name']:<25} {token['status']:<10} {created:<20} {expires:<20}")
        
        print("="*100 + "\n")

def main():
    parser = argparse.ArgumentParser(description="AR Token Manager")
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # List command
    list_cmd = subparsers.add_parser('list', help='List tokens')
    list_cmd.add_argument('--status', choices=['active', 'revoked', 'expired'], help='Filter by status')
    
    # Generate command
    gen_cmd = subparsers.add_parser('generate', help='Generate new token')
    gen_cmd.add_argument('--process', required=True, help='Process name')
    gen_cmd.add_argument('--pid', type=int, help='Process ID')
    gen_cmd.add_argument('--ttl', type=int, default=24, help='Time to live in hours')
    
    # Revoke command
    rev_cmd = subparsers.add_parser('revoke', help='Revoke token')
    rev_cmd.add_argument('--token-id', help='Token ID to revoke')
    rev_cmd.add_argument('--process', help='Revoke all tokens for process')
    rev_cmd.add_argument('--before', help='Revoke tokens before date (ISO format)')
    
    # Audit command
    audit_cmd = subparsers.add_parser('audit-tokens', help='Audit tokens')
    
    # Check failures command
    fail_cmd = subparsers.add_parser('check-failures', help='Check validation failures')
    fail_cmd.add_argument('--since', help='Since time (e.g., 1 hour ago)')
    
    # Debug command
    debug_cmd = subparsers.add_parser('debug-token', help='Debug specific token')
    debug_cmd.add_argument('--token-id', required=True, help='Token ID to debug')
    
    args = parser.parse_args()
    
    manager = ARTokenManager()
    
    if args.command == 'list':
        tokens = manager.list_tokens(args.status)
        manager.print_tokens(tokens)
    
    elif args.command == 'generate':
        token_id = manager.generate_token(args.process, args.pid, args.ttl)
        if token_id:
            print(f"Generated token: {token_id}")
        else:
            print("Failed to generate token")
            return 1
    
    elif args.command == 'revoke':
        if args.token_id:
            if manager.revoke_token(args.token_id):
                print(f"Revoked token: {args.token_id}")
            else:
                return 1
        elif args.process:
            count = manager.revoke_process_tokens(args.process)
            print(f"Revoked {count} token(s) for {args.process}")
        elif args.before:
            count = manager.revoke_before_date(args.before)
            print(f"Revoked {count} token(s) before {args.before}")
        else:
            print("Specify --token-id, --process, or --before")
            return 1
    
    elif args.command == 'check-failures':
        failures = manager.check_failures(args.since)
        if failures:
            print(f"Found {len(failures)} validation failure(s)")
            for fail in failures[:10]:
                print(f"  {fail['token_id']}: {fail['details']}")
        else:
            print("No validation failures found")
    
    elif args.command == 'debug-token':
        info = manager.debug_token(args.token_id)
        print(json.dumps(info, indent=2, default=str))
    
    elif args.command == 'audit-tokens':
        tokens = manager.list_tokens()
        manager.print_tokens(tokens)
    
    else:
        parser.print_help()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
