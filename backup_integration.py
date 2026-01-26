#!/usr/bin/env python3
"""
Backup Integration
Backup and restore configuration, policies, and databases
"""

import os
import sys
import json
import logging
import argparse
import shutil
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('backup.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class BackupManager:
    """Manage backups of configuration, policies, and data"""
    
    def __init__(self, backup_dir: str = "backups/", db_path: str = "admin.db"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(db_path)
        
        # Files to backup
        self.config_files = [
            "config.yaml",
            "admin_config.json",
            "policy.yaml",
            "config.json"
        ]
        
        self.db_files = [
            "admin.db",
            "protection_db.sqlite"
        ]
        
        logger.info(f"BackupManager initialized with backup dir: {self.backup_dir}")
    
    def create_full_backup(self, description: str = None) -> bool:
        """Create a full backup of all configuration and databases"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"backup_{timestamp}"
            backup_path = self.backup_dir / backup_name
            backup_path.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Creating full backup: {backup_name}")
            
            # Backup config files
            configs_dir = backup_path / "configs"
            configs_dir.mkdir(exist_ok=True)
            
            for config_file in self.config_files:
                src = Path(config_file)
                if src.exists():
                    dst = configs_dir / config_file
                    shutil.copy2(src, dst)
                    logger.info(f"  ✓ Backed up: {config_file}")
            
            # Backup databases
            dbs_dir = backup_path / "databases"
            dbs_dir.mkdir(exist_ok=True)
            
            for db_file in self.db_files:
                src = Path(db_file)
                if src.exists():
                    dst = dbs_dir / db_file
                    shutil.copy2(src, dst)
                    logger.info(f"  ✓ Backed up: {db_file}")
            
            # Create manifest
            manifest = {
                "timestamp": timestamp,
                "description": description or "Full backup",
                "configs": [f for f in self.config_files if Path(f).exists()],
                "databases": [f for f in self.db_files if Path(f).exists()]
            }
            
            manifest_path = backup_path / "manifest.json"
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f, indent=2)
            
            logger.info(f"✓ Full backup completed: {backup_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create full backup: {e}")
            return False
    
    def backup_database(self, db_file: str = "admin.db") -> bool:
        """Backup a single database file"""
        try:
            src = Path(db_file)
            if not src.exists():
                logger.warning(f"Database not found: {db_file}")
                return False
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dst = self.backup_dir / f"{src.stem}_{timestamp}.db"
            
            shutil.copy2(src, dst)
            logger.info(f"Database backed up: {db_file} -> {dst.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to backup database: {e}")
            return False
    
    def backup_config_file(self, config_file: str) -> bool:
        """Backup a single configuration file"""
        try:
            src = Path(config_file)
            if not src.exists():
                logger.warning(f"Config file not found: {config_file}")
                return False
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dst = self.backup_dir / f"{src.stem}_{timestamp}{src.suffix}"
            
            shutil.copy2(src, dst)
            logger.info(f"Config backed up: {config_file} -> {dst.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to backup config: {e}")
            return False
    
    def list_backups(self) -> List[Dict]:
        """List all available backups"""
        try:
            backups = []
            
            for backup_dir in sorted(self.backup_dir.iterdir(), reverse=True):
                if not backup_dir.is_dir():
                    continue
                
                manifest_path = backup_dir / "manifest.json"
                if manifest_path.exists():
                    with open(manifest_path, 'r') as f:
                        manifest = json.load(f)
                    
                    backup_size = sum(
                        f.stat().st_size 
                        for f in backup_dir.rglob('*') 
                        if f.is_file()
                    )
                    
                    backups.append({
                        'name': backup_dir.name,
                        'timestamp': manifest.get('timestamp'),
                        'description': manifest.get('description'),
                        'size_mb': round(backup_size / 1024 / 1024, 2),
                        'configs': len(manifest.get('configs', [])),
                        'databases': len(manifest.get('databases', []))
                    })
            
            return backups
        except Exception as e:
            logger.error(f"Failed to list backups: {e}")
            return []
    
    def restore_backup(self, backup_name: str, confirm: bool = False) -> bool:
        """Restore from a backup"""
        try:
            backup_path = self.backup_dir / backup_name
            
            if not backup_path.exists():
                logger.error(f"Backup not found: {backup_name}")
                return False
            
            if not confirm:
                logger.warning("⚠️  Restore will overwrite current files. Use --confirm to proceed.")
                return False
            
            logger.info(f"Restoring from backup: {backup_name}")
            
            # Restore configs
            configs_dir = backup_path / "configs"
            if configs_dir.exists():
                for config_file in configs_dir.iterdir():
                    dst = Path(config_file.name)
                    shutil.copy2(config_file, dst)
                    logger.info(f"  ✓ Restored: {config_file.name}")
            
            # Restore databases
            dbs_dir = backup_path / "databases"
            if dbs_dir.exists():
                for db_file in dbs_dir.iterdir():
                    dst = Path(db_file.name)
                    shutil.copy2(db_file, dst)
                    logger.info(f"  ✓ Restored: {db_file.name}")
            
            logger.info(f"✓ Backup restored: {backup_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to restore backup: {e}")
            return False
    
    def cleanup_old_backups(self, keep_count: int = 5) -> bool:
        """Remove old backups, keeping only the most recent ones"""
        try:
            backups = sorted(self.backup_dir.iterdir(), key=lambda x: x.name, reverse=True)
            
            if len(backups) <= keep_count:
                logger.info(f"Backup count ({len(backups)}) is within limit ({keep_count})")
                return True
            
            to_delete = backups[keep_count:]
            deleted = 0
            
            for backup_dir in to_delete:
                if backup_dir.is_dir():
                    shutil.rmtree(backup_dir)
                    logger.info(f"Deleted old backup: {backup_dir.name}")
                    deleted += 1
            
            logger.info(f"✓ Cleaned up {deleted} old backup(s)")
            return True
        except Exception as e:
            logger.error(f"Failed to cleanup old backups: {e}")
            return False
    
    def print_backups(self):
        """Print list of available backups"""
        backups = self.list_backups()
        
        if not backups:
            print("No backups found.")
            return
        
        print("\n" + "="*110)
        print(f"{'BACKUP NAME':<30} {'TIMESTAMP':<20} {'SIZE':<12} {'CONFIGS':<10} {'DATABASES':<12}")
        print("="*110)
        
        for backup in backups:
            print(f"{backup['name']:<30} {backup['timestamp']:<20} {backup['size_mb']:<12.2f}MB {backup['configs']:<10} {backup['databases']:<12}")
        
        print("="*110 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="Backup Integration"
    )
    parser.add_argument('--backup', action='store_true', help='Create full backup')
    parser.add_argument('--backup-db', metavar='FILE', help='Backup specific database')
    parser.add_argument('--backup-config', metavar='FILE', help='Backup specific config file')
    parser.add_argument('--list', action='store_true', help='List available backups')
    parser.add_argument('--restore', metavar='NAME', help='Restore from backup')
    parser.add_argument('--confirm', action='store_true', help='Confirm restore operation')
    parser.add_argument('--cleanup', action='store_true', help='Cleanup old backups')
    parser.add_argument('--keep', type=int, default=5, help='Number of backups to keep')
    parser.add_argument('--description', help='Description for backup')
    parser.add_argument('--backup-dir', default='backups/', help='Backup directory')
    parser.add_argument('--db', default='admin.db', help='Admin database path')
    
    args = parser.parse_args()
    
    manager = BackupManager(args.backup_dir, args.db)
    
    if args.backup:
        logger.info("Creating full backup...")
        if manager.create_full_backup(args.description):
            print("✓ Full backup created successfully")
            manager.print_backups()
        else:
            print("✗ Failed to create backup")
            sys.exit(1)
    
    elif args.backup_db:
        logger.info(f"Backing up database: {args.backup_db}")
        if manager.backup_database(args.backup_db):
            print(f"✓ Database backed up: {args.backup_db}")
        else:
            print(f"✗ Failed to backup database")
            sys.exit(1)
    
    elif args.backup_config:
        logger.info(f"Backing up config: {args.backup_config}")
        if manager.backup_config_file(args.backup_config):
            print(f"✓ Config backed up: {args.backup_config}")
        else:
            print(f"✗ Failed to backup config")
            sys.exit(1)
    
    elif args.list:
        manager.print_backups()
    
    elif args.restore:
        if manager.restore_backup(args.restore, args.confirm):
            print(f"✓ Backup restored: {args.restore}")
        else:
            if not args.confirm:
                print(f"Use --confirm to restore")
            else:
                print(f"✗ Failed to restore backup")
            sys.exit(1)
    
    elif args.cleanup:
        logger.info(f"Cleaning up old backups (keep {args.keep})...")
        if manager.cleanup_old_backups(args.keep):
            print(f"✓ Old backups cleaned up (keeping {args.keep})")
        else:
            print("✗ Failed to cleanup backups")
            sys.exit(1)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
