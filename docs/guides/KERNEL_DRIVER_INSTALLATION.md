# Kernel Driver Installation Guide

## ⚠️ CURRENT STATUS: DRIVERS NOT INSTALLED

The kernel drivers are **source code only** and must be built/installed manually.

---

## Windows Minifilter Driver

### Prerequisites
1. **Windows Driver Kit (WDK)** - Download from Microsoft
2. **Visual Studio 2019/2022** with C++ Desktop Development workload
3. **Administrator privileges**
4. **Test signing enabled** (for development) or **EV certificate** (production)

### Build Steps

#### Option 1: Visual Studio (Recommended)
```powershell
# 1. Install WDK from Microsoft
# Download: https://docs.microsoft.com/windows-hardware/drivers/download-the-wdk

# 2. Open Developer Command Prompt for VS 2022
# Navigate to project directory
cd C:\Users\ajibi\Music\Anti-Ransomeware

# 3. Build driver
msbuild RealAntiRansomwareDriver.sln /p:Configuration=Release /p:Platform=x64

# Output: build\x64\Release\RealAntiRansomwareDriver.sys
```

#### Option 2: WDK Build Environment
```cmd
# 1. Open WDK Build Environment (x64 Checked Build)
# 2. Navigate to driver directory
cd C:\Users\ajibi\Music\Anti-Ransomeware

# 3. Build with nmake
nmake /f makefile

# Output: objchk_win10_amd64\RealAntiRansomwareDriver.sys
```

### Enable Test Signing (Development Only)
```powershell
# Run as Administrator
bcdedit /set testsigning on
# Reboot required
shutdown /r /t 0
```

### Sign Driver (Required)
```powershell
# Development (self-signed certificate)
MakeCert -r -pe -ss PrivateCertStore -n "CN=RealAntiRansomware" RealTest.cer
SignTool sign /s PrivateCertStore /n RealAntiRansomware /t http://timestamp.digicert.com RealAntiRansomwareDriver.sys

# Production (requires EV certificate from CA)
SignTool sign /f "C:\Certs\EVCert.pfx" /p "password" /tr http://timestamp.digicert.com /td sha256 /fd sha256 RealAntiRansomwareDriver.sys
```

### Install Driver
```powershell
# Run as Administrator

# 1. Copy driver to system directory
copy RealAntiRansomwareDriver.sys C:\Windows\System32\drivers\

# 2. Install using pnputil
pnputil /add-driver RealAntiRansomwareDriver.inf /install

# 3. Start the filter driver
fltmc load RealAntiRansomware

# 4. Create and start service
sc create RealAntiRansomware type= filesys start= auto binPath= "C:\Windows\System32\drivers\RealAntiRansomwareDriver.sys"
sc start RealAntiRansomware

# 5. Verify installation
fltmc filters | findstr RealAntiRansomware
sc query RealAntiRansomware
```

### Uninstall Driver
```powershell
# Run as Administrator
fltmc unload RealAntiRansomware
sc stop RealAntiRansomware
sc delete RealAntiRansomware
pnputil /delete-driver RealAntiRansomwareDriver.inf /uninstall
del C:\Windows\System32\drivers\RealAntiRansomwareDriver.sys
```

---

## Linux LSM Module

### Prerequisites
1. **Linux kernel headers** matching your running kernel
2. **GCC compiler** and build tools
3. **Root/sudo privileges**
4. **Kernel configured with LSM support** (CONFIG_SECURITY=y)

### Build Steps
```bash
# 1. Install build dependencies
sudo apt install build-essential linux-headers-$(uname -r)  # Debian/Ubuntu
sudo yum install kernel-devel kernel-headers gcc make       # RHEL/CentOS

# 2. Create Makefile for Linux driver
cat > driver_linux_Makefile << 'EOF'
obj-m += antiransomware_lsm.o
antiransomware_lsm-objs := driver_linux.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install
	depmod -a
EOF

# 3. Build module
make -f driver_linux_Makefile

# Output: antiransomware_lsm.ko
```

### Register LSM
```bash
# 1. Load module
sudo insmod antiransomware_lsm.ko

# 2. Verify loaded
lsmod | grep antiransomware
dmesg | tail -20  # Check for load messages

# 3. Enable LSM in kernel boot params
sudo nano /etc/default/grub
# Add to GRUB_CMDLINE_LINUX: lsm=lockdown,yama,apparmor,antiransomware
sudo update-grub
sudo reboot

# 4. Make permanent (load on boot)
sudo cp antiransomware_lsm.ko /lib/modules/$(uname -r)/kernel/security/
sudo depmod -a
echo "antiransomware_lsm" | sudo tee -a /etc/modules-load.d/antiransomware.conf
```

### Configure Protected Paths
```bash
# Write paths to LSM interface
echo "/home/*/Documents" | sudo tee /sys/kernel/security/anti_ransomware/protected_paths
echo "/var/data" | sudo tee -a /sys/kernel/security/anti_ransomware/protected_paths

# Load public key for token verification
sudo cat broker_public_key.bin > /sys/kernel/security/anti_ransomware/public_key
```

### Uninstall
```bash
sudo rmmod antiransomware_lsm
sudo rm /lib/modules/$(uname -r)/kernel/security/antiransomware_lsm.ko
sudo sed -i '/antiransomware_lsm/d' /etc/modules-load.d/antiransomware.conf
sudo depmod -a
```

---

## macOS EndpointSecurity Agent

### Prerequisites
1. **Xcode 13+** with Swift 5.5+
2. **Apple Developer account** (paid, $99/year)
3. **Developer ID Application certificate**
4. **Notarization** credentials
5. **System Integrity Protection (SIP)** compatible code

### Build Steps
```bash
# 1. Open Xcode and create new macOS App target
# File -> New -> Project -> macOS -> App

# 2. Add EndpointSecurity entitlement
# In Xcode: Signing & Capabilities -> + Capability -> System Extension
# Add com.apple.developer.endpoint-security.client entitlement

# 3. Build release binary
xcodebuild -project AntiRansomware.xcodeproj -scheme AntiRansomware -configuration Release build

# Output: build/Release/AntiRansomware.app
```

### Sign and Notarize
```bash
# 1. Sign with Developer ID
codesign --force --sign "Developer ID Application: Your Name (TEAM_ID)" \
  --entitlements AntiRansomware.entitlements \
  --options runtime \
  build/Release/AntiRansomware.app

# 2. Create ZIP for notarization
ditto -c -k --keepParent build/Release/AntiRansomware.app AntiRansomware.zip

# 3. Submit for notarization
xcrun notarytool submit AntiRansomware.zip \
  --apple-id "your@email.com" \
  --team-id "TEAM_ID" \
  --password "app-specific-password" \
  --wait

# 4. Staple notarization ticket
xcrun stapler staple build/Release/AntiRansomware.app
```

### Install Agent
```bash
# 1. Copy to Applications
sudo cp -R build/Release/AntiRansomware.app /Applications/

# 2. Grant Full Disk Access
# System Preferences -> Security & Privacy -> Privacy -> Full Disk Access
# Add AntiRansomware.app

# 3. Create LaunchDaemon plist
sudo tee /Library/LaunchDaemons/com.real.antiransomware.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.real.antiransomware</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/AntiRansomware.app/Contents/MacOS/AntiRansomware</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# 4. Load LaunchDaemon
sudo launchctl load /Library/LaunchDaemons/com.real.antiransomware.plist
sudo launchctl start com.real.antiransomware

# 5. Verify running
launchctl list | grep antiransomware
```

### Uninstall
```bash
sudo launchctl unload /Library/LaunchDaemons/com.real.antiransomware.plist
sudo rm /Library/LaunchDaemons/com.real.antiransomware.plist
sudo rm -rf /Applications/AntiRansomware.app
```

---

## Quick Status Check

Run this to see if any drivers are active:

### Windows
```powershell
fltmc filters | findstr -i "ransomware\|anti"
sc query | findstr -i "ransomware\|anti"
```

### Linux
```bash
lsmod | grep -i ransomware
cat /sys/kernel/security/lsm
```

### macOS
```bash
launchctl list | grep -i ransomware
ps aux | grep -i antiransomware
```

---

## ⚠️ Production Deployment Checklist

### Before Deploying to Production:

- [ ] **Windows**: Driver signed with EV certificate from DigiCert/GlobalSign
- [ ] **Windows**: WHQL certification passed (Microsoft Hardware Lab)
- [ ] **Windows**: Test signed drivers DISABLED (bcdedit /set testsigning off)
- [ ] **Linux**: Kernel module signed with MOK or trusted key
- [ ] **Linux**: Secure Boot compatibility verified
- [ ] **macOS**: App notarized and stapled by Apple
- [ ] **macOS**: Full Disk Access granted by user
- [ ] **All**: Driver stability tested (no kernel panics/BSODs)
- [ ] **All**: Performance impact measured (<5% overhead)
- [ ] **All**: Token broker running and accessible
- [ ] **All**: Public key loaded into driver
- [ ] **All**: Protected paths configured
- [ ] **All**: Logging/monitoring enabled
- [ ] **All**: Rollback plan documented

---

## Support

**Current Status**: Drivers are **source code only** and require manual compilation and installation.

**Estimated Build Time**:
- Windows: 2-4 hours (including WDK setup, signing)
- Linux: 30-60 minutes (kernel headers, build)
- macOS: 3-6 hours (Xcode, notarization, FDAaccess)

**Alternative**: For immediate testing, the user-mode broker and policy engine work without kernel drivers, but provide **limited protection** (bypassable by malware).
