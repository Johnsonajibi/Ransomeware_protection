#!/usr/bin/env python3
"""
Email Alerting
Configure and send email alerts for security events
"""

import os
import sys
import json
import logging
import argparse
import smtplib
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('email_alerts.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class EmailAlerting:
    """Email alerting system for security events"""
    
    def __init__(self, config_path: str = "admin_config.json"):
        self.config_path = Path(config_path)
        self.config = self.load_config()
        self.init_database()
    
    def load_config(self) -> Dict:
        """Load email configuration"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    return json.load(f).get('email', {})
            return {}
        except Exception as e:
            logger.error(f"Config load failed: {e}")
            return {}
    
    def init_database(self):
        """Initialize email alerts database"""
        try:
            conn = sqlite3.connect("admin.db")
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    smtp_server TEXT,
                    smtp_port INTEGER,
                    sender_email TEXT,
                    sender_password TEXT,
                    use_tls BOOLEAN DEFAULT TRUE
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_recipients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    alert_level TEXT DEFAULT 'medium',
                    enabled BOOLEAN DEFAULT TRUE,
                    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sent_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient TEXT,
                    subject TEXT,
                    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'sent'
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database init failed: {e}")
    
    def configure_smtp(self, smtp_server: str, smtp_port: int, 
                      sender_email: str, sender_password: str, 
                      use_tls: bool = True) -> bool:
        """Configure SMTP settings"""
        try:
            self.config['smtp_server'] = smtp_server
            self.config['smtp_port'] = smtp_port
            self.config['sender_email'] = sender_email
            self.config['sender_password'] = sender_password
            self.config['use_tls'] = use_tls
            
            self.save_config()
            logger.info("SMTP configured")
            return True
        except Exception as e:
            logger.error(f"SMTP config failed: {e}")
            return False
    
    def add_recipient(self, email: str, alert_level: str = 'medium') -> bool:
        """Add email recipient"""
        try:
            if not email or '@' not in email:
                logger.error(f"Invalid email: {email}")
                return False
            
            conn = sqlite3.connect("admin.db")
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO email_recipients (email, alert_level)
                VALUES (?, ?)
            ''', (email, alert_level))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Added recipient: {email}")
            return True
        except Exception as e:
            logger.error(f"Recipient add failed: {e}")
            return False
    
    def remove_recipient(self, email: str) -> bool:
        """Remove email recipient"""
        try:
            conn = sqlite3.connect("admin.db")
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM email_recipients WHERE email = ?', (email,))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Removed recipient: {email}")
            return True
        except Exception as e:
            logger.error(f"Recipient remove failed: {e}")
            return False
    
    def list_recipients(self) -> List[Dict]:
        """List email recipients"""
        try:
            conn = sqlite3.connect("admin.db")
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT email, alert_level, enabled FROM email_recipients
                ORDER BY added_at DESC
            ''')
            
            columns = ['email', 'alert_level', 'enabled']
            recipients = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return recipients
        except Exception as e:
            logger.error(f"Recipient list failed: {e}")
            return []
    
    def send_alert(self, subject: str, body: str, 
                  severity: str = 'medium', recipients: List[str] = None) -> int:
        """Send email alert"""
        try:
            if not self.config.get('smtp_server'):
                logger.error("SMTP not configured")
                return 0
            
            if not recipients:
                recipients = self.get_active_recipients(severity)
            
            if not recipients:
                logger.warning("No active recipients found")
                return 0
            
            server = smtplib.SMTP(
                self.config['smtp_server'],
                self.config['smtp_port']
            )
            
            if self.config.get('use_tls'):
                server.starttls()
            
            sender = self.config['sender_email']
            password = self.config['sender_password']
            
            server.login(sender, password)
            
            sent_count = 0
            for recipient in recipients:
                try:
                    msg = MIMEMultipart()
                    msg['From'] = sender
                    msg['To'] = recipient
                    msg['Subject'] = f"[{severity.upper()}] {subject}"
                    
                    msg.attach(MIMEText(body, 'plain'))
                    
                    server.send_message(msg)
                    sent_count += 1
                    
                    self.log_sent_alert(recipient, subject, 'sent')
                    logger.info(f"Alert sent to {recipient}")
                except Exception as e:
                    logger.error(f"Failed to send to {recipient}: {e}")
                    self.log_sent_alert(recipient, subject, 'failed')
            
            server.quit()
            return sent_count
        except Exception as e:
            logger.error(f"Alert send failed: {e}")
            return 0
    
    def get_active_recipients(self, severity: str) -> List[str]:
        """Get active recipients for severity level"""
        try:
            conn = sqlite3.connect("admin.db")
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT email FROM email_recipients 
                WHERE enabled = 1 AND alert_level <= ?
            ''', (severity,))
            
            emails = [row[0] for row in cursor.fetchall()]
            conn.close()
            return emails
        except Exception as e:
            logger.error(f"Active recipients query failed: {e}")
            return []
    
    def log_sent_alert(self, recipient: str, subject: str, status: str = 'sent'):
        """Log sent alert"""
        try:
            conn = sqlite3.connect("admin.db")
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO sent_alerts (recipient, subject, status)
                VALUES (?, ?, ?)
            ''', (recipient, subject, status))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Alert logging failed: {e}")
    
    def save_config(self):
        """Save configuration to file"""
        try:
            full_config = {}
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    full_config = json.load(f)
            
            full_config['email'] = self.config
            
            with open(self.config_path, 'w') as f:
                json.dump(full_config, f, indent=2)
        except Exception as e:
            logger.error(f"Config save failed: {e}")
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test SMTP connection"""
        try:
            if not self.config.get('smtp_server'):
                return False, "SMTP not configured"
            
            server = smtplib.SMTP(
                self.config['smtp_server'],
                self.config['smtp_port'],
                timeout=5
            )
            
            if self.config.get('use_tls'):
                server.starttls()
            
            server.login(
                self.config['sender_email'],
                self.config['sender_password']
            )
            
            server.quit()
            return True, "Connection successful"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description="Email Alerting")
    parser.add_argument('--configure', action='store_true', help='Configure SMTP')
    parser.add_argument('--smtp-server', help='SMTP server address')
    parser.add_argument('--smtp-port', type=int, help='SMTP port')
    parser.add_argument('--sender-email', help='Sender email address')
    parser.add_argument('--sender-password', help='Sender password')
    parser.add_argument('--add-recipient', metavar='EMAIL', help='Add recipient')
    parser.add_argument('--remove-recipient', metavar='EMAIL', help='Remove recipient')
    parser.add_argument('--list-recipients', action='store_true', help='List recipients')
    parser.add_argument('--send', metavar='SUBJECT', help='Send test alert')
    parser.add_argument('--severity', choices=['low', 'medium', 'high', 'critical'], 
                       default='medium', help='Alert severity')
    parser.add_argument('--test', action='store_true', help='Test SMTP connection')
    
    args = parser.parse_args()
    
    alerting = EmailAlerting()
    
    if args.configure:
        if all([args.smtp_server, args.smtp_port, args.sender_email, args.sender_password]):
            if alerting.configure_smtp(args.smtp_server, args.smtp_port, 
                                       args.sender_email, args.sender_password):
                print("SMTP configured successfully")
            else:
                print("Failed to configure SMTP")
                return 1
        else:
            print("Missing required SMTP parameters")
            return 1
    
    elif args.add_recipient:
        if alerting.add_recipient(args.add_recipient, args.severity):
            print(f"Added recipient: {args.add_recipient}")
        else:
            return 1
    
    elif args.remove_recipient:
        if alerting.remove_recipient(args.remove_recipient):
            print(f"Removed recipient: {args.remove_recipient}")
        else:
            return 1
    
    elif args.list_recipients:
        recipients = alerting.list_recipients()
        if recipients:
            print("\n" + "="*70)
            print(f"{'EMAIL':<40} {'LEVEL':<15} {'ENABLED':<15}")
            print("="*70)
            for r in recipients:
                enabled = "Yes" if r['enabled'] else "No"
                print(f"{r['email']:<40} {r['alert_level']:<15} {enabled:<15}")
            print("="*70 + "\n")
        else:
            print("No recipients configured")
    
    elif args.send:
        count = alerting.send_alert(args.send, "Test alert message", args.severity)
        print(f"Alert sent to {count} recipient(s)")
    
    elif args.test:
        success, msg = alerting.test_connection()
        if success:
            print(f"Success: {msg}")
        else:
            print(f"Failed: {msg}")
            return 1
    
    else:
        parser.print_help()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
