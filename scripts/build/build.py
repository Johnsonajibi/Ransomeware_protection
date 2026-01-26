#!/usr/bin/env python3
"""
Cross-platform build script for Anti-Ransomware
"""

import os
import sys
import platform
import subprocess
import shlex
from pathlib import Path

def run_command(cmd, check=True):
    """Run command and handle errors"""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, check=check)
    return result.returncode == 0

def build_grpc_stubs():
    """Build gRPC protocol buffer stubs"""
    print("Building gRPC stubs...")
    # Create proto files first
    create_proto_files()
    return run_command("python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. broker.proto admin.proto")

def create_proto_files():
    """Create gRPC proto files"""
    broker_proto = '''
syntax = "proto3";

package broker;

service TokenBroker {
  rpc RequestToken(TokenRequest) returns (TokenResponse);
  rpc VerifyToken(TokenVerifyRequest) returns (TokenVerifyResponse);
}

message TokenRequest {
  string file_path = 1;
  int32 pid = 2;
  string user_id = 3;
  string process_name = 4;
}

message TokenResponse {
  bool success = 1;
  bytes token = 2;
  int64 expiry = 3;
  string error = 4;
}

message TokenVerifyRequest {
  bytes token = 1;
  string file_path = 2;
  int32 pid = 3;
}

message TokenVerifyResponse {
  bool valid = 1;
  string reason = 2;
}
'''

    admin_proto = '''
syntax = "proto3";

package admin;

service AdminService {
  rpc GetDashboardStats(DashboardStatsRequest) returns (DashboardStatsResponse);
  rpc GetEvents(GetEventsRequest) returns (GetEventsResponse);
  rpc UpdatePolicy(UpdatePolicyRequest) returns (UpdatePolicyResponse);
}

message DashboardStatsRequest {}

message DashboardStatsResponse {
  int32 events_today = 1;
  int32 denied_today = 2;
  int32 active_tokens = 3;
  int32 active_dongles = 4;
  int32 active_hosts = 5;
}

message GetEventsRequest {
  int32 limit = 1;
  int32 offset = 2;
  string filter_type = 3;
}

message Event {
  int64 id = 1;
  string timestamp = 2;
  string event_type = 3;
  string file_path = 4;
  int32 process_id = 5;
  string process_name = 6;
  string user_id = 7;
  string result = 8;
  string reason = 9;
  string token_id = 10;
  string host_id = 11;
}

message GetEventsResponse {
  repeated Event events = 1;
}

message UpdatePolicyRequest {
  string policy_data = 1;
}

message UpdatePolicyResponse {
  bool success = 1;
  string error = 2;
}
'''
    
    with open('broker.proto', 'w') as f:
        f.write(broker_proto)
    
    with open('admin.proto', 'w') as f:
        f.write(admin_proto)

def install_dependencies():
    """Install Python dependencies"""
    print("Installing Python dependencies...")
    requirements = '''grpcio>=1.50.0
grpcio-tools>=1.50.0
protobuf>=4.0.0
pyyaml>=6.0
cryptography>=3.4.0
pynacl>=1.5.0
psutil>=5.8.0
flask>=2.0.0
flask-login>=0.6.0
requests>=2.28.0
pyinstaller>=5.0.0'''
    
    with open('requirements.txt', 'w') as f:
        f.write(requirements)
    
    return run_command("pip install -r requirements.txt")

def build_windows():
    """Build Windows components"""
    print("Building for Windows...")
    
    # Create Windows-specific files
    create_windows_files()
    
    # Build user-space
    run_command("pyinstaller --onefile --name=AntiRansomwareBroker broker.py")
    run_command("pyinstaller --onefile --name=AntiRansomwareAdmin admin_dashboard.py")
    
    return True

def create_windows_files():
    """Create Windows-specific build files"""
    # Create driver INF file
    inf_content = '''[Version]
Signature="$WINDOWS NT$"
Class=System
ClassGuid={4D36E97D-E325-11CE-BFC1-08002BE10318}
Provider=%ProviderName%
DriverVer=01/01/2025,1.0.0.0

[DestinationDirs]
DefaultDestDir = 12

[DefaultInstall]
OptionDesc = %ServiceDesc%
CopyFiles = Drivers_Dir

[Drivers_Dir]
driver_windows.sys

[Strings]
ProviderName = "Anti-Ransomware"
ServiceDesc = "Anti-Ransomware Filter Driver"'''
    
    with open('driver_windows.inf', 'w') as f:
        f.write(inf_content)

def build_linux():
    """Build Linux components"""
    print("Building for Linux...")
    
    # Create Linux-specific files
    create_linux_files()
    
    # Build user-space
    run_command("pyinstaller --onefile --name=anti-ransomware-broker broker.py")
    run_command("pyinstaller --onefile --name=anti-ransomware-admin admin_dashboard.py")
    
    return True

def create_linux_files():
    """Create Linux-specific build files"""
    # Create Makefile
    makefile_content = '''obj-m := anti_ransomware.o
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
	depmod -a'''
    
    with open('Makefile.linux', 'w') as f:
        f.write(makefile_content)
    
    # Create systemd service
    service_content = '''[Unit]
Description=Anti-Ransomware Broker
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/anti-ransomware-broker
Restart=always
User=root

[Install]
WantedBy=multi-user.target'''
    
    with open('anti-ransomware-broker.service', 'w') as f:
        f.write(service_content)

def build_macos():
    """Build macOS components"""
    print("Building for macOS...")
    
    # Create macOS-specific files
    create_macos_files()
    
    # Build user-space
    run_command("pyinstaller --onefile --windowed --name=AntiRansomwareBroker broker.py")
    run_command("pyinstaller --onefile --windowed --name=AntiRansomwareAdmin admin_dashboard.py")
    
    return True

def create_macos_files():
    """Create macOS-specific build files"""
    # Create LaunchDaemon plist
    plist_content = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.antiransomware.broker</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/anti-ransomware-broker</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>'''
    
    with open('com.antiransomware.broker.plist', 'w') as f:
        f.write(plist_content)

def create_test_policy():
    """Create example policy file"""
    policy_content = '''version: "1.0"
global_settings:
  default_quota:
    files_per_min: 10
    bytes_per_min: 1048576
  token_lifetime: 300
  require_dongle: true
  audit_level: "full"

rules:
  - path_pattern: "/protected/*"
    quota:
      files_per_min: 10
      bytes_per_min: 1048576
      entropy_bypass: false
      interactive_consent: true
    process_rules:
      - name: "notepad.exe"
        allow: true
      - name: "powershell.exe"
        deny_if_parent: "winword.exe"
        allow: false
    time_windows:
      - start_time: "09:00"
        end_time: "17:00"
        days: ["monday", "tuesday", "wednesday", "thursday", "friday"]'''
    
    with open('policy.yaml', 'w') as f:
        f.write(policy_content)

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
    
    # Create test policy
    create_test_policy()
    
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
        print("\nNext steps:")
        if system == "windows":
            print("1. Build kernel driver with Visual Studio/WDK")
            print("2. Run dist/AntiRansomwareBroker.exe as administrator")
            print("3. Run dist/AntiRansomwareAdmin.exe for web interface")
        elif system == "linux":
            print("1. Build kernel module: make -f Makefile.linux")
            print("2. Install module: sudo insmod anti_ransomware.ko")
            print("3. Run dist/anti-ransomware-broker as root")
            print("4. Run dist/anti-ransomware-admin for web interface")
        elif system == "darwin":
            print("1. Build system extension with Xcode")
            print("2. Load system extension: sudo systemextensionsctl load ...")
            print("3. Run dist/AntiRansomwareBroker")
            print("4. Run dist/AntiRansomwareAdmin for web interface")
        return 0
    else:
        print("Build failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
