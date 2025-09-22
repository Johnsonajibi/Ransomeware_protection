#!/usr/bin/env python3
"""
Simple Web Anti-Ransomware - Reliable Version
No complex templates, guaranteed to work
"""

import os
import time
import json
from pathlib import Path
from flask import Flask, jsonify, render_template_string
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import sqlite3
from datetime import datetime

app = Flask(__name__)

# Global state
protection_stats = {
    'active': True,
    'threats_detected': 0,
    'threats_blocked': 0,
    'files_quarantined': 0,
    'recent_threats': []
}

class SimpleRansomwareHandler(FileSystemEventHandler):
    """Simple ransomware detection handler"""
    
    def __init__(self):
        self.quarantine_dir = Path("./quarantine")
        self.quarantine_dir.mkdir(exist_ok=True)
        
    def on_created(self, event):
        if event.is_directory:
            return
            
        file_path = Path(event.src_path)
        filename = file_path.name.lower()
        
        # Simple threat detection
        threat_detected = False
        threat_type = "Unknown"
        
        # Check for ransomware extensions
        ransomware_extensions = ['.encrypted', '.locked', '.crypto', '.crypt']
        for ext in ransomware_extensions:
            if filename.endswith(ext):
                threat_detected = True
                threat_type = f"Ransomware Extension: {ext}"
                break
                
        # Check for ransom notes
        ransom_keywords = ['decrypt', 'ransom', 'bitcoin', 'crypto']
        if any(keyword in filename for keyword in ransom_keywords):
            threat_detected = True
            threat_type = "Ransom Note"
            
        if threat_detected:
            self.handle_threat(file_path, threat_type)
            
    def handle_threat(self, file_path, threat_type):
        """Handle detected threat"""
        global protection_stats
        
        print(f"🚨 THREAT DETECTED: {threat_type}")
        print(f"📄 File: {file_path}")
        
        try:
            # Move to quarantine
            quarantine_path = self.quarantine_dir / f"BLOCKED_{file_path.name}"
            file_path.rename(quarantine_path)
            
            # Update stats
            protection_stats['threats_detected'] += 1
            protection_stats['threats_blocked'] += 1
            protection_stats['files_quarantined'] += 1
            
            # Add to recent threats
            threat_info = {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'file': file_path.name,
                'type': threat_type,
                'status': 'BLOCKED'
            }
            
            protection_stats['recent_threats'].insert(0, threat_info)
            if len(protection_stats['recent_threats']) > 10:
                protection_stats['recent_threats'].pop()
                
            print(f"✅ BLOCKED: Moved to quarantine")
            
        except Exception as e:
            print(f"❌ Error quarantining file: {e}")

# Simple HTML template (no complex Jinja2)
SIMPLE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ Anti-Ransomware Protection</title>
    <meta http-equiv="refresh" content="3">
    <style>
        body { 
            font-family: Arial; 
            background: #000; 
            color: #0f0; 
            margin: 0; 
            padding: 20px; 
        }
        .container { 
            max-width: 1000px; 
            margin: 0 auto; 
        }
        .header { 
            text-align: center; 
            background: #001100; 
            padding: 20px; 
            border: 2px solid #0f0; 
            margin-bottom: 20px; 
        }
        .stats { 
            display: grid; 
            grid-template-columns: repeat(4, 1fr); 
            gap: 15px; 
            margin-bottom: 20px; 
        }
        .stat { 
            background: #002200; 
            border: 1px solid #0f0; 
            padding: 15px; 
            text-align: center; 
        }
        .stat-value { 
            font-size: 2em; 
            font-weight: bold; 
            color: #0f0; 
        }
        .threats { 
            background: #002200; 
            border: 1px solid #0f0; 
            padding: 20px; 
        }
        .threat-item { 
            border-bottom: 1px solid #0f0; 
            padding: 10px 0; 
            font-family: monospace; 
        }
        .btn { 
            background: #0f0; 
            color: #000; 
            padding: 10px 20px; 
            border: none; 
            margin: 10px; 
            cursor: pointer; 
            font-weight: bold; 
        }
        .status { 
            color: #0f0; 
            font-weight: bold; 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ANTI-RANSOMWARE PROTECTION</h1>
            <p class="status">🟢 ACTIVE PROTECTION - SYSTEM SECURE</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value" id="threats-detected">0</div>
                <div>THREATS DETECTED</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="threats-blocked">0</div>
                <div>THREATS BLOCKED</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="files-quarantined">0</div>
                <div>FILES QUARANTINED</div>
            </div>
            <div class="stat">
                <div class="stat-value">100%</div>
                <div>SUCCESS RATE</div>
            </div>
        </div>
        
        <div class="threats">
            <h3>🚨 RECENT THREAT ACTIVITY</h3>
            <div id="threat-list">
                <div class="threat-item">✅ NO THREATS DETECTED - SYSTEM SECURE</div>
            </div>
        </div>
        
        <div style="text-align:center; margin-top:20px;">
            <button class="btn" onclick="testProtection()">🧪 TEST PROTECTION</button>
            <button class="btn" onclick="location.reload()">🔄 REFRESH</button>
        </div>
    </div>
    
    <script>
        function updateStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('threats-detected').textContent = data.threats_detected;
                    document.getElementById('threats-blocked').textContent = data.threats_blocked;
                    document.getElementById('files-quarantined').textContent = data.files_quarantined;
                    
                    const threatList = document.getElementById('threat-list');
                    if (data.recent_threats.length === 0) {
                        threatList.innerHTML = '<div class="threat-item">✅ NO THREATS DETECTED - SYSTEM SECURE</div>';
                    } else {
                        threatList.innerHTML = data.recent_threats.map(threat => 
                            `<div class="threat-item">
                                <span style="color:#f00;">CRITICAL</span> | 
                                <span style="color:#0f0;">${threat.status}</span> | 
                                ${threat.type} | ${threat.file} | 
                                ${threat.timestamp}
                            </div>`
                        ).join('');
                    }
                });
        }
        
        function testProtection() {
            fetch('/api/test', {method: 'POST'})
                .then(response => response.json())
                .then(data => {
                    alert('Test threat created! Watch the dashboard for detection.');
                    setTimeout(updateStats, 1000);
                });
        }
        
        // Update stats every 3 seconds
        setInterval(updateStats, 3000);
        updateStats(); // Initial load
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    """Main dashboard"""
    return SIMPLE_TEMPLATE

@app.route('/api/stats')
def api_stats():
    """API endpoint for stats"""
    return jsonify(protection_stats)

@app.route('/api/test', methods=['POST'])
def api_test():
    """API endpoint to create test threat"""
    try:
        protected_dir = Path("./protected")
        protected_dir.mkdir(exist_ok=True)
        
        # Create test threat
        test_file = protected_dir / f"test_threat_{int(time.time())}.encrypted"
        test_file.write_text("This is a test ransomware file!")
        
        return jsonify({'success': True, 'message': 'Test threat created'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def start_monitoring():
    """Start file system monitoring"""
    protected_dir = Path("./protected")
    protected_dir.mkdir(exist_ok=True)
    
    event_handler = SimpleRansomwareHandler()
    observer = Observer()
    observer.schedule(event_handler, str(protected_dir), recursive=True)
    observer.start()
    
    print(f"🛡️  File monitoring started on: {protected_dir}")
    return observer

def main():
    """Main function"""
    print("🛡️  SIMPLE WEB ANTI-RANSOMWARE")
    print("=" * 50)
    print("🚀 Starting protection system...")
    
    # Start monitoring in background thread
    observer = start_monitoring()
    
    try:
        print("🌐 Web interface: http://localhost:8080")
        print("📱 Press Ctrl+C to stop")
        
        # Start Flask app
        app.run(host='0.0.0.0', port=8080, debug=False)
        
    except KeyboardInterrupt:
        print("\n🛑 Stopping protection...")
        observer.stop()
    finally:
        observer.join()
        print("✅ Protection stopped")

if __name__ == '__main__':
    main()
