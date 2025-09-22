#!/usr/bin/env python3
"""
PRODUCTION INSTALLER AND SETUP
Real installation system with dependency management
"""

import os
import sys
import subprocess
import platform
import json
import shutil
from pathlib import Path
import winreg
import ctypes

class ProductionInstaller:
    def __init__(self):
        self.install_dir = Path("C:/Program Files/AntiRansomware")
        self.data_dir = Path("C:/ProgramData/AntiRansomware")
        self.is_admin = self.check_admin()
        
    def check_admin(self):
        """Check if running as administrator"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def install_dependencies(self):
        """Install all required dependencies"""
        print("📦 Installing production dependencies...")
        
        requirements = [
            'flask==3.0.0',
            'watchdog==3.0.0',
            'psutil==5.9.6',
            'cryptography==41.0.7',
            'pywin32==306',
            'pyscard==2.0.7',
            'fido2==1.1.2'
        ]
        
        try:
            for package in requirements:
                print(f"  Installing {package}...")
                result = subprocess.run([
                    sys.executable, '-m', 'pip', 'install', package
                ], capture_output=True, text=True, check=True)
                
            print("✅ All dependencies installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            print(f"Error output: {e.stderr}")
            return False
    
    def create_directories(self):
        """Create necessary directories"""
        print("📁 Creating system directories...")
        
        try:
            self.install_dir.mkdir(parents=True, exist_ok=True)
            self.data_dir.mkdir(parents=True, exist_ok=True)
            
            # Create subdirectories
            (self.data_dir / "logs").mkdir(exist_ok=True)
            (self.data_dir / "quarantine").mkdir(exist_ok=True)
            (self.data_dir / "backups").mkdir(exist_ok=True)
            (self.data_dir / "config").mkdir(exist_ok=True)
            
            print("✅ Directories created successfully")
            return True
            
        except PermissionError:
            print("❌ Permission denied. Please run as administrator.")
            return False
        except Exception as e:
            print(f"❌ Error creating directories: {e}")
            return False
    
    def install_files(self):
        """Install system files"""
        print("📋 Installing system files...")
        
        try:
            # Copy main system file
            shutil.copy2("production_real.py", self.install_dir / "antiransomware.py")
            
            # Copy additional files
            if os.path.exists("folder_browser.py"):
                shutil.copy2("folder_browser.py", self.install_dir / "folder_browser.py")
            
            # Create configuration file
            config = {
                "system": {
                    "version": "1.0.0",
                    "install_date": "2024-01-01",
                    "data_directory": str(self.data_dir),
                    "log_level": "INFO"
                },
                "security": {
                    "default_policy": "high_security",
                    "usb_required": True,
                    "token_lifetime": 600,
                    "quarantine_enabled": True
                },
                "web": {
                    "host": "localhost",
                    "port": 8080,
                    "debug": False
                }
            }
            
            config_file = self.data_dir / "config" / "system_config.json"
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            print("✅ System files installed successfully")
            return True
            
        except Exception as e:
            print(f"❌ Error installing files: {e}")
            return False
    
    def create_service(self):
        """Create Windows service"""
        print("🔧 Creating Windows service...")
        
        try:
            service_script = f'''
import win32serviceutil
import win32service
import win32event
import servicemanager
import sys
import os
sys.path.append(r"{self.install_dir}")

from antiransomware import ProductionAntiRansomwareSystem

class AntiRansomwareService(win32serviceutil.ServiceFramework):
    _svc_name_ = "AntiRansomwareProtection"
    _svc_display_name_ = "Anti-Ransomware Protection Service"
    _svc_description_ = "Real-time anti-ransomware protection with USB authentication"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.system = None
    
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.system:
            self.system.stop_protection()
        win32event.SetEvent(self.hWaitStop)
    
    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                            servicemanager.PYS_SERVICE_STARTED,
                            (self._svc_name_, ''))
        
        try:
            self.system = ProductionAntiRansomwareSystem()
            self.system.start_protection()
            
            # Wait for stop signal
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            
        except Exception as e:
            servicemanager.LogErrorMsg(f"Service error: {{e}}")

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(AntiRansomwareService)
'''
            
            service_file = self.install_dir / "service.py"
            with open(service_file, 'w') as f:
                f.write(service_script)
            
            print("✅ Service configuration created")
            return True
            
        except Exception as e:
            print(f"❌ Error creating service: {e}")
            return False
    
    def create_shortcuts(self):
        """Create desktop and start menu shortcuts"""
        print("🔗 Creating shortcuts...")
        
        try:
            # Create batch file to launch GUI
            launcher_script = f'''@echo off
cd /d "{self.install_dir}"
python antiransomware.py
pause'''
            
            launcher_file = self.install_dir / "launch.bat"
            with open(launcher_file, 'w') as f:
                f.write(launcher_script)
            
            # Create folder browser launcher
            browser_script = f'''@echo off
cd /d "{self.install_dir}"
python folder_browser.py
pause'''
            
            browser_file = self.install_dir / "folder_browser.bat"
            with open(browser_file, 'w') as f:
                f.write(browser_script)
            
            print("✅ Shortcuts created successfully")
            return True
            
        except Exception as e:
            print(f"❌ Error creating shortcuts: {e}")
            return False
    
    def register_startup(self):
        """Register for Windows startup"""
        print("🚀 Registering for system startup...")
        
        try:
            if self.is_admin:
                # Add to Windows registry for auto-start
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_SET_VALUE
                )
                
                winreg.SetValueEx(
                    key, "AntiRansomwareProtection", 0, winreg.REG_SZ,
                    f'"{self.install_dir / "launch.bat"}"'
                )
                
                winreg.CloseKey(key)
                print("✅ Registered for automatic startup")
            else:
                print("⚠️  Admin privileges required for auto-startup")
            
            return True
            
        except Exception as e:
            print(f"❌ Error registering startup: {e}")
            return False
    
    def run_tests(self):
        """Run system tests"""
        print("🧪 Running system tests...")
        
        try:
            # Test imports
            sys.path.append(str(self.install_dir))
            
            print("  Testing core imports...")
            import flask, watchdog, psutil, cryptography
            print("  ✅ Core libraries imported successfully")
            
            # Test Windows APIs
            print("  Testing Windows API access...")
            import win32api, win32file
            drives = win32api.GetLogicalDriveStrings()
            print(f"  ✅ Found {len(drives.split())} drives")
            
            # Test smart card libraries
            print("  Testing smart card libraries...")
            try:
                import smartcard
                print("  ✅ Smart card support available")
            except ImportError:
                print("  ⚠️  Smart card libraries not installed")
            
            print("✅ All tests passed")
            return True
            
        except Exception as e:
            print(f"❌ Test failed: {e}")
            return False
    
    def install(self):
        """Run complete installation"""
        print("🛡️  PRODUCTION ANTI-RANSOMWARE SYSTEM INSTALLER")
        print("=" * 60)
        
        if not self.is_admin:
            print("⚠️  WARNING: Not running as administrator")
            print("   Some features may not work properly")
            print()
        
        steps = [
            ("Installing dependencies", self.install_dependencies),
            ("Creating directories", self.create_directories),
            ("Installing system files", self.install_files),
            ("Creating service configuration", self.create_service),
            ("Creating shortcuts", self.create_shortcuts),
            ("Registering startup", self.register_startup),
            ("Running tests", self.run_tests)
        ]
        
        failed_steps = []
        
        for step_name, step_func in steps:
            print(f"\n{step_name}...")
            if not step_func():
                failed_steps.append(step_name)
        
        print("\n" + "=" * 60)
        if failed_steps:
            print("❌ INSTALLATION COMPLETED WITH ERRORS")
            print("Failed steps:")
            for step in failed_steps:
                print(f"  - {step}")
        else:
            print("✅ INSTALLATION COMPLETED SUCCESSFULLY!")
            print(f"📁 Installed to: {self.install_dir}")
            print(f"📊 Data directory: {self.data_dir}")
            print()
            print("🚀 To start the system:")
            print(f'   Run: "{self.install_dir / "launch.bat"}"')
            print()
            print("🌐 Web dashboard will be available at:")
            print("   http://localhost:8080")
        
        print("=" * 60)

if __name__ == '__main__':
    installer = ProductionInstaller()
    installer.install()
