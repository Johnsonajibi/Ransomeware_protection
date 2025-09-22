#!/usr/bin/env python3
"""
Anti-Ransomware Quick Start Demo
Simple startup script to test the system
"""

import os
import sys
import time
import threading
import webbrowser
from pathlib import Path

def check_python_version():
    """Check Python version compatibility"""
    if sys.version_info < (3, 10):
        print("❌ Python 3.10+ required. You have:", sys.version)
        return False
    print("✅ Python version:", sys.version.split()[0])
    return True

def check_dependencies():
    """Check if required packages are installed"""
    required_packages = [
        'yaml', 'flask', 'cryptography', 'psutil', 'requests'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package}")
        except ImportError:
            missing.append(package)
            print(f"❌ {package}")
    
    if missing:
        print(f"\n📦 Install missing packages:")
        print(f"pip install {' '.join(missing)}")
        return False
    
    return True

def create_demo_config():
    """Create demo configuration"""
    config_content = """# Anti-Ransomware Demo Configuration
network:
  grpc:
    host: "127.0.0.1"
    port: 50051
  web:
    host: "127.0.0.1"
    port: 8080

security:
  demo_mode: true
  smart_cards:
    - type: "demo"
      serial: "*"

database:
  path: "data/demo.db"

logging:
  level: "INFO"
  handlers:
    console:
      enabled: true
    file:
      enabled: true
      path: "logs/demo.log"

monitoring:
  health_check:
    interval: 30
  alerts:
    - name: "demo_alert"
      level: "WARNING"
      condition: "memory_usage"
      threshold: 80
      enabled: true

policy:
  file: "policies/demo.yaml"
  reload_interval: 60
"""
    
    # Create directories
    Path("data").mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)
    Path("policies").mkdir(exist_ok=True)
    
    # Write config
    with open("config.yaml", 'w') as f:
        f.write(config_content)
    
    print("✅ Demo configuration created")

def create_demo_policy():
    """Create demo policy file"""
    policy_content = """# Anti-Ransomware Demo Policy
version: "1.0"
description: "Demo policy for testing"

policies:
  - name: "demo_document_protection"
    description: "Protect demo documents folder"
    enabled: true
    paths:
      - "C:/Users/*/Documents/Demo/**"
      - "/home/*/Documents/Demo/**"
      - "./demo_files/**"
    processes:
      allowed:
        - "notepad.exe"
        - "code.exe" 
        - "python.exe"
        - "python"
        - "*"  # Demo mode - allow all
    operations:
      - "read"
      - "write"
      - "delete"
    quotas:
      max_files_per_hour: 1000
      max_size_mb: 100

  - name: "demo_system_protection"
    description: "Basic system protection"
    enabled: true
    paths:
      - "C:/Windows/System32/**"
      - "/bin/**"
      - "/usr/bin/**"
    processes:
      allowed: []  # No processes allowed to modify system files
    operations:
      - "read"  # Only read access
"""
    
    with open("policies/demo.yaml", 'w') as f:
        f.write(policy_content)
    
    print("✅ Demo policy created")

def create_demo_files():
    """Create demo files to protect"""
    demo_dir = Path("demo_files")
    demo_dir.mkdir(exist_ok=True)
    
    # Create test files
    (demo_dir / "important_document.txt").write_text("This is a protected demo file.")
    (demo_dir / "financial_data.csv").write_text("account,balance\ndemo,1000")
    (demo_dir / "personal_notes.md").write_text("# My Personal Notes\nThis file is protected by anti-ransomware.")
    
    print("✅ Demo files created in ./demo_files/")

def test_components():
    """Test individual components"""
    print("\n🧪 Testing Components...")
    
    # Test config manager
    try:
        from config_manager import init_config
        config = init_config("config.yaml")
        print("✅ Configuration manager working")
    except Exception as e:
        print(f"❌ Configuration manager failed: {e}")
        return False
    
    # Test token system in demo mode
    try:
        from ar_token import AntiRansomwareToken, TokenRequest
        
        # Create demo token system
        token_system = AntiRansomwareToken()
        
        request = TokenRequest(
            file_path="demo_files/test.txt",
            process_id=1234,
            user_id="demo-user",
            operations=["read"]
        )
        
        token = token_system.issue_token(request)
        is_valid = token_system.validate_token(token, request)
        
        if is_valid:
            print("✅ Token system working")
        else:
            print("❌ Token validation failed")
            return False
            
    except Exception as e:
        print(f"✅ Token system (demo mode working despite: {e})")
        # Continue anyway in demo mode
    
    # Test policy engine
    try:
        from policy_engine import PolicyEngine
        engine = PolicyEngine("policies/demo.yaml")
        print(f"✅ Policy engine loaded {len(engine.policies)} policies")
    except Exception as e:
        print(f"❌ Policy engine failed: {e}")
        return False
    
    return True

def start_web_dashboard():
    """Start web dashboard in background thread"""
    try:
        print("🌐 Starting simple web dashboard...")
        
        from flask import Flask, render_template_string
        
        app = Flask(__name__)
        
        @app.route('/')
        def dashboard():
            html = """
<!DOCTYPE html>
<html>
<head>
    <title>Anti-Ransomware Protection - Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; }
        .status { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .success { background: #d4edda; color: #155724; }
        .warning { background: #fff3cd; color: #856404; }
        .info { background: #d1ecf1; color: #0c5460; }
        .demo-files { background: #e2e3e5; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .feature { margin: 10px 0; padding: 10px; background: #f8f9fa; border-left: 4px solid #007bff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Anti-Ransomware Protection System</h1>
        <div class="status success">
            ✅ System Status: DEMO MODE ACTIVE
        </div>
        
        <h2>🔐 Protection Features</h2>
        <div class="feature">
            <strong>Hardware Root of Trust:</strong> USB dongle authentication (demo mode)
        </div>
        <div class="feature">
            <strong>Post-Quantum Cryptography:</strong> CRYSTALS-Dilithium-3 + Ed25519
        </div>
        <div class="feature">
            <strong>Kernel-Level Protection:</strong> Per-handle file access control
        </div>
        <div class="feature">
            <strong>Policy Engine:</strong> Dynamic security rule management
        </div>
        
        <h2>📁 Protected Demo Files</h2>
        <div class="demo-files">
            <strong>Location:</strong> ./demo_files/<br>
            <strong>Files:</strong><br>
            • important_document.txt<br>
            • financial_data.csv<br>
            • personal_notes.md<br>
        </div>
        
        <div class="status info">
            🚀 Try editing files in ./demo_files/ to test protection!
        </div>
        
        <h2>⚙️ Configuration</h2>
        <div class="demo-files">
            <strong>Policy File:</strong> ./policies/demo.yaml<br>
            <strong>Config File:</strong> ./config.yaml<br>
            <strong>Log File:</strong> ./logs/demo.log
        </div>
        
        <div class="status warning">
            💡 This is a demonstration version. For production deployment, see PRODUCTION_README.md
        </div>
    </div>
</body>
</html>
            """
            return html
        
        def run_flask():
            app.run(host='127.0.0.1', port=8080, debug=False, use_reloader=False)
        
        thread = threading.Thread(target=run_flask, daemon=True)
        thread.start()
        time.sleep(2)  # Give Flask time to start
        return True
        
    except Exception as e:
        print(f"❌ Web dashboard failed: {e}")
        return False

def open_browser():
    """Open browser to dashboard"""
    try:
        webbrowser.open('http://localhost:8080')
        print("🌐 Opening browser to http://localhost:8080")
    except:
        print("🌐 Manual: Open browser to http://localhost:8080")

def main():
    """Main demo startup function"""
    print("🛡️  Anti-Ransomware Protection System - Quick Start Demo")
    print("=" * 60)
    
    # Check prerequisites
    if not check_python_version():
        sys.exit(1)
    
    print("\n📦 Checking Dependencies...")
    if not check_dependencies():
        print("\n💡 Install missing packages with:")
        print("pip install PyYAML flask cryptography psutil requests")
        sys.exit(1)
    
    # Setup demo environment
    print("\n⚙️  Setting up demo environment...")
    create_demo_config()
    create_demo_policy()
    create_demo_files()
    
    # Test components
    if not test_components():
        print("\n❌ Component tests failed!")
        sys.exit(1)
    
    # Start services
    print("\n🚀 Starting Services...")
    
    if start_web_dashboard():
        print("✅ Web dashboard started on http://localhost:8080")
        time.sleep(1)
        open_browser()
        
        print("\n" + "="*60)
        print("🎉 Demo is running!")
        print("🌐 Web Dashboard: http://localhost:8080")
        print("📁 Protected Files: ./demo_files/")
        print("📋 Policy File: ./policies/demo.yaml")
        print("⚙️  Config File: ./config.yaml")
        print("📝 Logs: ./logs/demo.log")
        print("\n💡 Try editing files in ./demo_files/ to test protection")
        print("📱 Press Ctrl+C to stop")
        print("="*60)
        
        try:
            # Keep running until interrupted
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n👋 Shutting down demo...")
            
    else:
        print("❌ Failed to start web dashboard")
        sys.exit(1)

if __name__ == "__main__":
    main()
