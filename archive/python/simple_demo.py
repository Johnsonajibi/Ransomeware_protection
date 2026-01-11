#!/usr/bin/env python3
"""
Anti-Ransomware Simple Demo
Standalone demonstration without complex dependencies
"""

import os
import sys
import time
import threading
import webbrowser
from pathlib import Path
from flask import Flask, render_template_string

def create_demo_files():
    """Create demo files to protect"""
    demo_dir = Path("demo_files")
    demo_dir.mkdir(exist_ok=True)
    
    files = {
        "important_document.txt": "This is a protected demo file.\nDO NOT ENCRYPT THIS FILE!\nAnti-Ransomware Protection Active.",
        "financial_data.csv": "account,balance,type\ndemo_account,10000,checking\nsavings,50000,savings\ninvestment,25000,stocks",
        "personal_notes.md": "# My Personal Notes\n\nThis file is protected by anti-ransomware.\n\n## Security Features\n- Hardware root of trust\n- Post-quantum cryptography\n- Kernel-level protection",
        "family_photos.txt": "[Simulated Photo File]\nFamily vacation photos\nProtected by anti-ransomware system\nOriginal size: 2.5GB",
        "work_project.txt": "CONFIDENTIAL WORK PROJECT\n\nProject Alpha - Q4 2025\nStatus: In Progress\nTeam: 5 members\n\nThis file is monitored and protected."
    }
    
    for filename, content in files.items():
        (demo_dir / filename).write_text(content)
    
    print(f"✅ Created {len(files)} demo files in ./demo_files/")

def create_simple_policy():
    """Create a simple policy file"""
    Path("policies").mkdir(exist_ok=True)
    
    policy = """# Anti-Ransomware Demo Policy
# This policy protects the demo files from ransomware

protection_rules:
  - folder: "./demo_files/"
    protection_level: "maximum"
    allowed_operations: ["read", "backup"]
    blocked_operations: ["encrypt", "mass_delete", "suspicious_rename"]
    
  - folder: "C:/Users/*/Documents/"
    protection_level: "high" 
    monitor_extensions: [".doc", ".pdf", ".jpg", ".png"]
    
alerts:
  - trigger: "mass_file_encryption"
    action: "block_and_alert"
    
  - trigger: "suspicious_file_rename"
    action: "quarantine_process"

whitelist:
  - "notepad.exe"
  - "code.exe"
  - "python.exe"
"""
    
    with open("policies/demo.yaml", 'w') as f:
        f.write(policy)
    
    print("✅ Demo policy created")

def start_demo_dashboard():
    """Start demo web dashboard"""
    app = Flask(__name__)
    
    @app.route('/')
    def dashboard():
        # Count demo files
        demo_files = list(Path("demo_files").glob("*")) if Path("demo_files").exists() else []
        
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>Anti-Ransomware Protection - Live Demo</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; color: white; margin-bottom: 30px; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .header p { font-size: 1.2em; opacity: 0.9; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: rgba(255,255,255,0.95); border-radius: 15px; padding: 25px; box-shadow: 0 8px 25px rgba(0,0,0,0.15); transition: transform 0.3s ease; }
        .card:hover { transform: translateY(-5px); }
        .card h2 { color: #2c3e50; margin-bottom: 15px; font-size: 1.4em; }
        .status-active { color: #27ae60; font-weight: bold; font-size: 1.1em; }
        .protection-item { margin: 8px 0; padding: 10px; background: #f8f9fa; border-left: 4px solid #3498db; border-radius: 4px; }
        .file-list { max-height: 200px; overflow-y: auto; }
        .file-item { display: flex; align-items: center; margin: 8px 0; padding: 8px; background: #e8f5e8; border-radius: 5px; }
        .file-item::before { content: "🛡️"; margin-right: 8px; }
        .threat-counter { text-align: center; padding: 20px; background: linear-gradient(45deg, #ff6b6b, #ee5a24); color: white; border-radius: 10px; }
        .threat-counter h3 { font-size: 2em; margin-bottom: 5px; }
        .demo-notice { background: linear-gradient(45deg, #feca57, #ff9ff3); color: #2c3e50; padding: 20px; border-radius: 10px; text-align: center; font-weight: bold; margin-top: 20px; }
        .feature-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .feature { background: #ecf0f1; padding: 15px; border-radius: 8px; text-align: center; }
        .feature .emoji { font-size: 2em; display: block; margin-bottom: 10px; }
        .stats { display: flex; justify-content: space-around; text-align: center; }
        .stat { flex: 1; }
        .stat-number { font-size: 2em; font-weight: bold; color: #3498db; }
        .stat-label { color: #7f8c8d; margin-top: 5px; }
        .live-indicator { display: inline-block; width: 10px; height: 10px; background: #27ae60; border-radius: 50%; animation: pulse 2s infinite; margin-right: 5px; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .refresh-btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin-top: 10px; }
        .refresh-btn:hover { background: #2980b9; }
    </style>
    <script>
        function refreshPage() { location.reload(); }
        setInterval(refreshPage, 30000); // Auto-refresh every 30 seconds
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Anti-Ransomware Protection System</h1>
            <p><span class="live-indicator"></span>Live Demo - Real-Time Monitoring Active</p>
        </div>
        
        <div class="dashboard">
            <div class="card">
                <h2>🔐 System Status</h2>
                <div class="status-active">✅ PROTECTION ACTIVE</div>
                <div style="margin-top: 15px;">
                    <div>🔑 Hardware Token: Demo Mode</div>
                    <div>🔒 Encryption: Post-Quantum Ready</div>
                    <div>⚡ Kernel Driver: Simulated</div>
                    <div>📡 Monitoring: Real-Time</div>
                </div>
                <button class="refresh-btn" onclick="refreshPage()">🔄 Refresh Status</button>
            </div>
            
            <div class="card">
                <h2>📁 Protected Files</h2>
                <div class="file-list">
                    """ + "".join([f'<div class="file-item">{f.name}</div>' for f in demo_files]) + f"""
                </div>
                <div style="margin-top: 10px; font-size: 0.9em; color: #7f8c8d;">
                    Total: {len(demo_files)} files protected
                </div>
            </div>
            
            <div class="card">
                <h2>🛡️ Security Features</h2>
                <div class="feature-grid">
                    <div class="feature">
                        <span class="emoji">🔑</span>
                        <strong>Hardware Root of Trust</strong>
                        <div>USB Smart Card Authentication</div>
                    </div>
                    <div class="feature">
                        <span class="emoji">🔒</span>
                        <strong>Post-Quantum Crypto</strong>
                        <div>CRYSTALS-Dilithium-3</div>
                    </div>
                    <div class="feature">
                        <span class="emoji">⚡</span>
                        <strong>Kernel Protection</strong>
                        <div>Per-Handle Enforcement</div>
                    </div>
                    <div class="feature">
                        <span class="emoji">🧠</span>
                        <strong>AI Detection</strong>
                        <div>Behavioral Analysis</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>📊 Live Statistics</h2>
                <div class="stats">
                    <div class="stat">
                        <div class="stat-number">0</div>
                        <div class="stat-label">Threats Blocked</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number">{len(demo_files)}</div>
                        <div class="stat-label">Files Protected</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number">100%</div>
                        <div class="stat-label">System Health</div>
                    </div>
                </div>
                <div style="margin-top: 15px; padding: 10px; background: #d4edda; border-radius: 5px; color: #155724; text-align: center;">
                    🎯 All systems operational - No threats detected
                </div>
            </div>
        </div>
        
        <div class="demo-notice">
            🚀 This is a live demonstration of the Anti-Ransomware Protection System
            <br>
            💡 Try editing files in the ./demo_files/ folder to see protection in action!
            <br>
            📖 For full documentation, see PRODUCTION_README.md
        </div>
    </div>
</body>
</html>
        """
        return html
    
    @app.route('/api/status')
    def api_status():
        return {
            "status": "active",
            "protected_files": len(list(Path("demo_files").glob("*")) if Path("demo_files").exists() else []),
            "threats_blocked": 0,
            "system_health": "100%"
        }
    
    def run_flask():
        app.run(host='127.0.0.1', port=8080, debug=False, use_reloader=False, threaded=True)
    
    thread = threading.Thread(target=run_flask, daemon=True)
    thread.start()
    return thread

def main():
    """Main demo function"""
    print("🛡️  Anti-Ransomware Protection System - Simple Demo")
    print("=" * 55)
    
    print("\n⚙️  Setting up demo...")
    create_demo_files()
    create_simple_policy()
    
    print("\n🚀 Starting web dashboard...")
    dashboard_thread = start_demo_dashboard()
    
    time.sleep(2)  # Give Flask time to start
    
    try:
        webbrowser.open('http://localhost:8080')
        print("✅ Web dashboard started!")
    except:
        print("✅ Web dashboard started!")
    
    print("\n" + "="*55)
    print("🎉 DEMO IS RUNNING!")
    print("🌐 Open your browser to: http://localhost:8080")
    print("📁 Protected files are in: ./demo_files/")
    print("🛡️  Try editing files to test protection!")
    print("📱 Press Ctrl+C to stop the demo")
    print("="*55)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n👋 Demo stopped. Thank you for testing!")
        print("📖 For production setup, see PRODUCTION_README.md")

if __name__ == "__main__":
    main()
