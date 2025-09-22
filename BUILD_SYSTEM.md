# Anti-Ransomware Build System

## Windows Build (Visual Studio)

### Driver Build (driver_windows.c)
```makefile
# Windows Makefile for kernel driver
TARGETNAME=AntiRansomwareDriver
TARGETTYPE=MINIPORT
SOURCES=driver_windows.c

!INCLUDE $(NTMAKEENV)\makefile.def

# Build with WDK
build:
	msbuild AntiRansomwareDriver.vcxproj /p:Configuration=Release /p:Platform=x64
```

### User-space Build
```batch
@echo off
echo Building Anti-Ransomware for Windows...

REM Install Python dependencies
pip install -r requirements.txt

REM Build gRPC stubs
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. broker.proto admin.proto

REM Create executable
pyinstaller --onefile --name=AntiRansomwareBroker broker.py
pyinstaller --onefile --name=AntiRansomwareAdmin admin_dashboard.py

echo Build complete!
```

## Linux Build

### Kernel Module Build
```makefile
# Linux Makefile for LSM module
obj-m := anti_ransomware.o
anti_ransomware-objs := driver_linux.o

KVERSION := $(shell uname -r)
KDIR := /lib/modules/$(KVERSION)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a
```

### User-space Build
```bash
#!/bin/bash
echo "Building Anti-Ransomware for Linux..."

# Install dependencies
pip3 install -r requirements.txt

# Build gRPC stubs
python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. broker.proto admin.proto

# Create executables
pyinstaller --onefile --name=anti-ransomware-broker broker.py
pyinstaller --onefile --name=anti-ransomware-admin admin_dashboard.py

# Create systemd service files
sudo cp anti-ransomware-broker.service /etc/systemd/system/
sudo cp anti-ransomware-admin.service /etc/systemd/system/
sudo systemctl daemon-reload

echo "Build complete!"
```

## macOS Build

### System Extension Build
```bash
#!/bin/bash
echo "Building Anti-Ransomware for macOS..."

# Build Swift system extension
xcodebuild -project AntiRansomware.xcodeproj -scheme AntiRansomwareExtension -configuration Release

# Build user-space components
pip3 install -r requirements.txt
python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. broker.proto admin.proto

# Create app bundle
pyinstaller --onefile --windowed --name=AntiRansomwareBroker broker.py
pyinstaller --onefile --windowed --name=AntiRansomwareAdmin admin_dashboard.py

# Code sign (requires developer certificate)
codesign --force --verify --verbose --sign "Developer ID Application" dist/AntiRansomwareBroker
codesign --force --verify --verbose --sign "Developer ID Application" dist/AntiRansomwareAdmin

# Create installer package
productbuild --component AntiRansomware.app /Applications AntiRansomware.pkg

echo "Build complete!"
```

## Cross-Platform Build Script

```python
#!/usr/bin/env python3
"""
Cross-platform build script for Anti-Ransomware
"""

import os
import sys
import platform
import subprocess
from pathlib import Path

def run_command(cmd, check=True):
    """Run command and handle errors"""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, check=check)
    return result.returncode == 0

def build_grpc_stubs():
    """Build gRPC protocol buffer stubs"""
    print("Building gRPC stubs...")
    return run_command("python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. broker.proto admin.proto")

def install_dependencies():
    """Install Python dependencies"""
    print("Installing Python dependencies...")
    return run_command("pip install -r requirements.txt")

def build_windows():
    """Build Windows components"""
    print("Building for Windows...")
    
    # Build kernel driver (requires WDK)
    if Path("C:/Program Files (x86)/Windows Kits/10").exists():
        print("Building kernel driver...")
        run_command("msbuild driver_windows.vcxproj /p:Configuration=Release /p:Platform=x64", check=False)
    
    # Build user-space
    run_command("pyinstaller --onefile --name=AntiRansomwareBroker broker.py")
    run_command("pyinstaller --onefile --name=AntiRansomwareAdmin admin_dashboard.py")
    
    return True

def build_linux():
    """Build Linux components"""
    print("Building for Linux...")
    
    # Build kernel module
    print("Building kernel module...")
    run_command("make -f Makefile.linux")
    
    # Build user-space
    run_command("pyinstaller --onefile --name=anti-ransomware-broker broker.py")
    run_command("pyinstaller --onefile --name=anti-ransomware-admin admin_dashboard.py")
    
    return True

def build_macos():
    """Build macOS components"""
    print("Building for macOS...")
    
    # Build system extension (requires Xcode)
    if Path("/Applications/Xcode.app").exists():
        print("Building system extension...")
        run_command("xcodebuild -project AntiRansomware.xcodeproj -scheme AntiRansomwareExtension -configuration Release", check=False)
    
    # Build user-space
    run_command("pyinstaller --onefile --windowed --name=AntiRansomwareBroker broker.py")
    run_command("pyinstaller --onefile --windowed --name=AntiRansomwareAdmin admin_dashboard.py")
    
    return True

def main():
    system = platform.system().lower()
    print(f"Building Anti-Ransomware for {system}")
    
    # Common steps
    if not install_dependencies():
        print("Failed to install dependencies")
        return 1
    
    if not build_grpc_stubs():
        print("Failed to build gRPC stubs")
        return 1
    
    # Platform-specific builds
    if system == "windows":
        success = build_windows()
    elif system == "linux":
        success = build_linux()
    elif system == "darwin":
        success = build_macos()
    else:
        print(f"Unsupported platform: {system}")
        return 1
    
    if success:
        print("Build completed successfully!")
        return 0
    else:
        print("Build failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
```

## Dependencies (requirements.txt)

```
# Core dependencies
grpcio>=1.50.0
grpcio-tools>=1.50.0
protobuf>=4.0.0
pyyaml>=6.0
cryptography>=3.4.0
pynacl>=1.5.0
psutil>=5.8.0

# Web interface
flask>=2.0.0
flask-login>=0.6.0

# Database
sqlite3

# Smart card (optional)
pyscard>=2.0.0

# Build tools
pyinstaller>=5.0.0

# SIEM integration (optional)
elasticsearch>=8.0.0
requests>=2.28.0
```

## Deployment Scripts

### Windows Deployment
```batch
@echo off
echo Installing Anti-Ransomware for Windows...

REM Install driver (requires admin)
rundll32.exe setupapi,InstallHinfSection DefaultInstall 132 driver_windows.inf

REM Install service
sc create AntiRansomwareBroker binpath="C:\Program Files\AntiRansomware\AntiRansomwareBroker.exe" start=auto
sc create AntiRansomwareAdmin binpath="C:\Program Files\AntiRansomware\AntiRansomwareAdmin.exe" start=manual

REM Start services
sc start AntiRansomwareBroker

echo Installation complete!
```

### Linux Deployment
```bash
#!/bin/bash
echo "Installing Anti-Ransomware for Linux..."

# Install kernel module
sudo insmod anti_ransomware.ko
echo "anti_ransomware" | sudo tee -a /etc/modules

# Install binaries
sudo cp anti-ransomware-broker /usr/local/bin/
sudo cp anti-ransomware-admin /usr/local/bin/
sudo chmod +x /usr/local/bin/anti-ransomware-*

# Install systemd services
sudo systemctl enable anti-ransomware-broker
sudo systemctl start anti-ransomware-broker

echo "Installation complete!"
```

### macOS Deployment
```bash
#!/bin/bash
echo "Installing Anti-Ransomware for macOS..."

# Install system extension (requires user approval)
sudo cp -R AntiRansomware.app /Applications/

# Load system extension
sudo systemextensionsctl developer on
sudo systemextensionsctl load com.antiransomware.extension

# Install LaunchDaemons
sudo cp com.antiransomware.broker.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.antiransomware.broker.plist

echo "Installation complete! Please approve system extension in System Preferences."
```

## Testing Scripts

### Unit Tests
```python
#!/usr/bin/env python3
import unittest
from ar_token import *
from policy_engine import *

class TestTokenSystem(unittest.TestCase):
    def test_token_creation(self):
        token = create_token("test_file", 1234, "user", TokenOps.READ | TokenOps.WRITE)
        self.assertIsInstance(token, ARToken)
        self.assertEqual(token.payload.file_id, "test_file")
    
    def test_token_signing(self):
        signer = TokenSigner()
        signer.generate_ed25519_keys()
        token = create_token("test_file", 1234, "user", TokenOps.READ)
        signed_token = signer.sign_token(token)
        self.assertIsNotNone(signed_token.ed25519_signature)

class TestPolicyEngine(unittest.TestCase):
    def test_policy_loading(self):
        engine = PolicyEngine("test_policy.yaml")
        self.assertIsInstance(engine.policy, Policy)
    
    def test_access_check(self):
        engine = PolicyEngine()
        allowed, rule, reason = engine.check_access("/protected/test.txt", 1234, "user")
        self.assertIsInstance(allowed, bool)

if __name__ == "__main__":
    unittest.main()
```

This comprehensive build system provides:
1. Platform-specific build scripts for Windows, Linux, and macOS
2. Cross-platform Python build script
3. Dependency management
4. Deployment scripts for each platform
5. Unit testing framework
6. Both kernel and user-space component builds
7. Service/daemon installation
8. Code signing for macOS

The build system handles the complexities of multi-platform development while maintaining a consistent interface across all supported operating systems.
