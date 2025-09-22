#!/usr/bin/env python3
"""
Anti-Ransomware Admin Dashboard
gRPC server, SIEM integration, fleet management, and web interface
"""

import os
import sys
import json
import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import grpc
from concurrent import futures
import sqlite3
import threading

# Web framework
from flask import Flask, render_template, request, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import requests

# SIEM integration
import syslog
from elasticsearch import Elasticsearch

# Import our modules
from policy_engine import PolicyEngine, Policy, PathRule, Quota, ProcessRule, TimeWindow
from ar_token import TokenVerifier, ARToken
from broker import TokenBroker

# gRPC proto (would be generated)
import admin_pb2
import admin_pb2_grpc

class User(UserMixin):
    def __init__(self, username: str, role: str = "admin"):
        self.id = username
        self.username = username
        self.role = role

class DatabaseManager:
    """SQLite database for storing events, tokens, and admin data"""
    
    def __init__(self, db_path: str = "admin.db"):
        self.db_path = db_path
        self.connection = None
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                file_path TEXT,
                process_id INTEGER,
                process_name TEXT,
                user_id TEXT,
                result TEXT,
                reason TEXT,
                token_id TEXT,
                host_id TEXT
            )
        ''')
        
        # Tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_id TEXT UNIQUE NOT NULL,
                file_path TEXT,
                process_id INTEGER,
                user_id TEXT,
                expiry DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                revoked BOOLEAN DEFAULT FALSE,
                host_id TEXT
            )
        ''')
        
        # Dongles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dongles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_number TEXT UNIQUE NOT NULL,
                public_key TEXT,
                registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME,
                active BOOLEAN DEFAULT TRUE,
                user_id TEXT,
                host_id TEXT
            )
        ''')
        
        # Hosts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id TEXT UNIQUE NOT NULL,
                hostname TEXT,
                os_type TEXT,
                os_version TEXT,
                agent_version TEXT,
                last_checkin DATETIME,
                policy_version TEXT,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_event(self, event_type: str, file_path: str = None, process_id: int = None,
                  process_name: str = None, user_id: str = None, result: str = None,
                  reason: str = None, token_id: str = None, host_id: str = None):
        """Log an event to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO events (event_type, file_path, process_id, process_name, 
                               user_id, result, reason, token_id, host_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (event_type, file_path, process_id, process_name, user_id, result, reason, token_id, host_id))
        
        conn.commit()
        conn.close()
    
    def get_events(self, limit: int = 100, offset: int = 0, filter_type: str = None) -> List[Dict]:
        """Get events from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM events"
        params = []
        
        if filter_type:
            query += " WHERE event_type = ?"
            params.append(filter_type)
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        events = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return events
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get dashboard statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total events today
        cursor.execute("SELECT COUNT(*) FROM events WHERE DATE(timestamp) = DATE('now')")
        stats['events_today'] = cursor.fetchone()[0]
        
        # Denied access attempts today
        cursor.execute("SELECT COUNT(*) FROM events WHERE result = 'denied' AND DATE(timestamp) = DATE('now')")
        stats['denied_today'] = cursor.fetchone()[0]
        
        # Active tokens
        cursor.execute("SELECT COUNT(*) FROM tokens WHERE expiry > datetime('now') AND revoked = FALSE")
        stats['active_tokens'] = cursor.fetchone()[0]
        
        # Active dongles
        cursor.execute("SELECT COUNT(*) FROM dongles WHERE active = TRUE")
        stats['active_dongles'] = cursor.fetchone()[0]
        
        # Active hosts
        cursor.execute("SELECT COUNT(*) FROM hosts WHERE status = 'active'")
        stats['active_hosts'] = cursor.fetchone()[0]
        
        conn.close()
        return stats

class SIEMIntegration:
    """SIEM integration for logging and alerting"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.elasticsearch_client = None
        self.setup_integrations()
    
    def setup_integrations(self):
        """Set up SIEM integrations"""
        # Elasticsearch
        if self.config.get('elasticsearch', {}).get('enabled', False):
            try:
                self.elasticsearch_client = Elasticsearch(
                    [self.config['elasticsearch']['url']],
                    http_auth=(
                        self.config['elasticsearch'].get('username'),
                        self.config['elasticsearch'].get('password')
                    )
                )
            except Exception as e:
                logging.error(f"Failed to connect to Elasticsearch: {e}")
        
        # Syslog
        if self.config.get('syslog', {}).get('enabled', False):
            syslog.openlog("anti-ransomware", syslog.LOG_PID, syslog.LOG_LOCAL0)
    
    def send_event(self, event: Dict[str, Any]):
        """Send event to configured SIEM systems"""
        # Send to Elasticsearch
        if self.elasticsearch_client:
            try:
                self.elasticsearch_client.index(
                    index=f"anti-ransomware-{datetime.now().strftime('%Y-%m')}",
                    body=event
                )
            except Exception as e:
                logging.error(f"Failed to send event to Elasticsearch: {e}")
        
        # Send to syslog
        if self.config.get('syslog', {}).get('enabled', False):
            syslog_msg = f"Anti-Ransomware: {event.get('event_type', 'unknown')} - {event.get('result', 'unknown')}"
            syslog.syslog(syslog.LOG_INFO, syslog_msg)
        
        # Send webhook
        if self.config.get('webhook', {}).get('enabled', False):
            try:
                requests.post(
                    self.config['webhook']['url'],
                    json=event,
                    headers=self.config['webhook'].get('headers', {}),
                    timeout=10
                )
            except Exception as e:
                logging.error(f"Failed to send webhook: {e}")

class AdminService(admin_pb2_grpc.AdminServiceServicer):
    """gRPC admin service"""
    
    def __init__(self, db_manager: DatabaseManager, policy_engine: PolicyEngine, 
                 siem: SIEMIntegration):
        self.db = db_manager
        self.policy = policy_engine
        self.siem = siem
    
    def GetDashboardStats(self, request, context):
        """Get dashboard statistics"""
        try:
            stats = self.db.get_statistics()
            return admin_pb2.DashboardStatsResponse(
                events_today=stats['events_today'],
                denied_today=stats['denied_today'],
                active_tokens=stats['active_tokens'],
                active_dongles=stats['active_dongles'],
                active_hosts=stats['active_hosts']
            )
        except Exception as e:
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            return admin_pb2.DashboardStatsResponse()
    
    def GetEvents(self, request, context):
        """Get events with pagination"""
        try:
            events = self.db.get_events(
                limit=request.limit or 100,
                offset=request.offset or 0,
                filter_type=request.filter_type if request.filter_type else None
            )
            
            event_protos = []
            for event in events:
                event_proto = admin_pb2.Event(
                    id=event['id'],
                    timestamp=event['timestamp'],
                    event_type=event['event_type'],
                    file_path=event['file_path'] or '',
                    process_id=event['process_id'] or 0,
                    process_name=event['process_name'] or '',
                    user_id=event['user_id'] or '',
                    result=event['result'] or '',
                    reason=event['reason'] or '',
                    token_id=event['token_id'] or '',
                    host_id=event['host_id'] or ''
                )
                event_protos.append(event_proto)
            
            return admin_pb2.GetEventsResponse(events=event_protos)
            
        except Exception as e:
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            return admin_pb2.GetEventsResponse()
    
    def UpdatePolicy(self, request, context):
        """Update policy configuration"""
        try:
            # TODO: Implement policy update from proto
            return admin_pb2.UpdatePolicyResponse(success=True)
        except Exception as e:
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            return admin_pb2.UpdatePolicyResponse(success=False, error=str(e))

# Flask web application
def create_web_app(db_manager: DatabaseManager, policy_engine: PolicyEngine, 
                   siem: SIEMIntegration) -> Flask:
    """Create Flask web application"""
    
    app = Flask(__name__)
    app.secret_key = os.urandom(24)
    
    # Login manager
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    
    @login_manager.user_loader
    def load_user(username):
        # Simple user loading (in production, use proper user management)
        return User(username)
    
    @app.route('/')
    @login_required
    def dashboard():
        """Main dashboard"""
        stats = db_manager.get_statistics()
        recent_events = db_manager.get_events(limit=10)
        return render_template('dashboard.html', stats=stats, events=recent_events)
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Login page"""
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            
            # Simple authentication (use proper auth in production)
            if username == 'admin' and password == 'admin123':
                user = User(username)
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                return render_template('login.html', error='Invalid credentials')
        
        return render_template('login.html')
    
    @app.route('/logout')
    @login_required
    def logout():
        """Logout"""
        logout_user()
        return redirect(url_for('login'))
    
    @app.route('/api/events')
    @login_required
    def api_events():
        """API endpoint for events"""
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        filter_type = request.args.get('type')
        
        events = db_manager.get_events(limit, offset, filter_type)
        return jsonify(events)
    
    @app.route('/api/stats')
    @login_required
    def api_stats():
        """API endpoint for statistics"""
        return jsonify(db_manager.get_statistics())
    
    @app.route('/api/policy', methods=['GET', 'POST'])
    @login_required
    def api_policy():
        """API endpoint for policy management"""
        if request.method == 'GET':
            return jsonify(policy_engine.get_policy_summary())
        
        elif request.method == 'POST':
            # Update policy
            policy_data = request.json
            # TODO: Implement policy update
            return jsonify({'success': True})
    
    @app.route('/policy')
    @login_required
    def policy_page():
        """Policy management page"""
        summary = policy_engine.get_policy_summary()
        return render_template('policy.html', policy=summary)
    
    @app.route('/events')
    @login_required
    def events_page():
        """Events page"""
        return render_template('events.html')
    
    @app.route('/dongles')
    @login_required
    def dongles_page():
        """Dongles management page"""
        # TODO: Get dongle information
        dongles = []
        return render_template('dongles.html', dongles=dongles)
    
    return app

class AdminDashboard:
    """Main admin dashboard service"""
    
    def __init__(self, config_file: str = "admin_config.json"):
        self.config = self.load_config(config_file)
        self.db = DatabaseManager(self.config.get('database', {}).get('path', 'admin.db'))
        self.policy = PolicyEngine(self.config.get('policy', {}).get('file', 'policy.yaml'))
        self.siem = SIEMIntegration(self.config.get('siem', {}))
        
        # gRPC server
        self.grpc_server = None
        self.web_app = create_web_app(self.db, self.policy, self.siem)
    
    def load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Create default config
            default_config = {
                'database': {'path': 'admin.db'},
                'policy': {'file': 'policy.yaml'},
                'grpc': {'port': 50052},
                'web': {'port': 8080, 'host': '127.0.0.1'},
                'siem': {
                    'elasticsearch': {'enabled': False, 'url': 'http://localhost:9200'},
                    'syslog': {'enabled': True},
                    'webhook': {'enabled': False, 'url': ''}
                }
            }
            
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            return default_config
    
    def start_grpc_server(self):
        """Start gRPC server"""
        self.grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        admin_pb2_grpc.add_AdminServiceServicer_to_server(
            AdminService(self.db, self.policy, self.siem),
            self.grpc_server
        )
        
        port = self.config.get('grpc', {}).get('port', 50052)
        listen_addr = f'[::]:{port}'
        self.grpc_server.add_insecure_port(listen_addr)
        self.grpc_server.start()
        
        logging.info(f"Admin gRPC server started on {listen_addr}")
    
    def start_web_server(self):
        """Start web server"""
        host = self.config.get('web', {}).get('host', '127.0.0.1')
        port = self.config.get('web', {}).get('port', 8080)
        
        logging.info(f"Admin web server starting on {host}:{port}")
        self.web_app.run(host=host, port=port, debug=False)
    
    def start(self):
        """Start admin dashboard"""
        logging.info("Starting Anti-Ransomware Admin Dashboard")
        
        # Start gRPC server in background
        grpc_thread = threading.Thread(target=self.start_grpc_server)
        grpc_thread.daemon = True
        grpc_thread.start()
        
        # Start web server (blocking)
        self.start_web_server()
    
    def stop(self):
        """Stop admin dashboard"""
        if self.grpc_server:
            self.grpc_server.stop(0)

def setup_logging():
    """Set up logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('admin.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

if __name__ == "__main__":
    setup_logging()
    
    dashboard = AdminDashboard()
    
    try:
        dashboard.start()
    except KeyboardInterrupt:
        logging.info("Shutting down admin dashboard...")
        dashboard.stop()
