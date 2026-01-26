#!/usr/bin/env python3
"""
Token-Gated Access CLI
Protect/unprotect folders and files with token gating requirements.
"""

import os
import sys
import json
import logging
import argparse
import sqlite3
from pathlib import Path
from typing import Dict, List

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('token_gated_access.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class TokenGate:
    def __init__(self, db_path: str = 'protection_db.sqlite'):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protected_paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                protection_level TEXT DEFAULT 'high',
                enabled BOOLEAN DEFAULT TRUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                description TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS token_gate_requirements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                require_usb BOOLEAN DEFAULT FALSE,
                require_tpm BOOLEAN DEFAULT TRUE,
                require_fingerprint BOOLEAN DEFAULT TRUE,
                notes TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def protect(self, path: str, require_usb: bool = False, require_tpm: bool = True, 
                require_fingerprint: bool = True, notes: str = None) -> bool:
        try:
            abspath = str(Path(path).absolute())
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO protected_paths (path, protection_level, enabled, description)
                VALUES (?, 'high', 1, ?)
            ''', (abspath, notes))
            cursor.execute('''
                INSERT OR REPLACE INTO token_gate_requirements (path, require_usb, require_tpm, require_fingerprint, notes, updated_at)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
            ''', (abspath, int(require_usb), int(require_tpm), int(require_fingerprint), notes))
            conn.commit()
            conn.close()
            logger.info(f'Protected path: {abspath} (USB={require_usb}, TPM={require_tpm}, FP={require_fingerprint})')
            return True
        except Exception as e:
            logger.error(f'Protect failed: {e}')
            return False

    def unprotect(self, path: str) -> bool:
        try:
            abspath = str(Path(path).absolute())
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM protected_paths WHERE path = ?', (abspath,))
            cursor.execute('DELETE FROM token_gate_requirements WHERE path = ?', (abspath,))
            conn.commit()
            conn.close()
            logger.info(f'Unprotected path: {abspath}')
            return True
        except Exception as e:
            logger.error(f'Unprotect failed: {e}')
            return False

    def list(self) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT p.path, p.protection_level, p.enabled, r.require_usb, r.require_tpm, r.require_fingerprint, r.updated_at
            FROM protected_paths p LEFT JOIN token_gate_requirements r ON p.path = r.path
            ORDER BY p.created_at DESC
        ''')
        cols = ['path','level','enabled','require_usb','require_tpm','require_fingerprint','updated_at']
        rows = [dict(zip(cols, row)) for row in cursor.fetchall()]
        conn.close()
        return rows

    def print_list(self, rows: List[Dict]):
        if not rows:
            print('No protected paths.')
            return
        print('\n' + '='*100)
        print(f"{'PATH':<55} {'LEVEL':<8} {'USB':<5} {'TPM':<5} {'FP':<5} {'ENABLED':<8}")
        print('='*100)
        for r in rows:
            print(f"{r['path']:<55} {r['level']:<8} {('yes' if r['require_usb'] else 'no'):<5} {('yes' if r['require_tpm'] else 'no'):<5} {('yes' if r['require_fingerprint'] else 'no'):<5} {('yes' if r['enabled'] else 'no'):<8}")
        print('='*100 + '\n')


def main():
    parser = argparse.ArgumentParser(description='Token-Gated Access CLI')
    sub = parser.add_subparsers(dest='command')

    prot = sub.add_parser('protect', help='Protect a path')
    prot.add_argument('path', help='Folder or file path')
    prot.add_argument('--require-usb', action='store_true')
    prot.add_argument('--no-tpm', action='store_true')
    prot.add_argument('--no-fingerprint', action='store_true')
    prot.add_argument('--notes')

    unp = sub.add_parser('unprotect', help='Unprotect a path')
    unp.add_argument('path', help='Folder or file path')

    lst = sub.add_parser('list', help='List protected paths')

    args = parser.parse_args()
    tg = TokenGate()

    if args.command == 'protect':
        ok = tg.protect(
            args.path,
            require_usb=bool(args.require_usb),
            require_tpm=not bool(args.no_tpm),
            require_fingerprint=not bool(args.no_fingerprint),
            notes=args.notes
        )
        print('Protected' if ok else 'Failed')
        return 0 if ok else 1

    if args.command == 'unprotect':
        ok = tg.unprotect(args.path)
        print('Unprotected' if ok else 'Failed')
        return 0 if ok else 1

    if args.command == 'list':
        tg.print_list(tg.list())
        return 0

    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())
