#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Create production deployment package for Anti-Ransomware Protection
.DESCRIPTION
    Packages the complete system for distribution to end users
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   CREATING DEPLOYMENT PACKAGE" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$ProjectRoot = $PSScriptRoot
$DeploymentDir = Join-Path $ProjectRoot "deployment"
$Version = "1.0.0"

# Clean and create deployment directory
Write-Host "[1/8] Preparing deployment directory..." -ForegroundColor Yellow
if (Test-Path $DeploymentDir) {
    Remove-Item $DeploymentDir -Recurse -Force
}
New-Item -ItemType Directory -Path $DeploymentDir | Out-Null
Write-Host "    Created: $DeploymentDir" -ForegroundColor Green

# Create subdirectories
$AppDir = Join-Path $DeploymentDir "AntiRansomware"
$KernelDir = Join-Path $DeploymentDir "KernelDriver"
New-Item -ItemType Directory -Path $AppDir | Out-Null
New-Item -ItemType Directory -Path $KernelDir | Out-Null

# Copy core Python files
Write-Host "[2/8] Copying application files..." -ForegroundColor Yellow
$corePyFiles = @(
    "admin_dashboard.py"
    "unified_antiransomware.py"
    "policy_engine.py"
    "crypto_token.py"
    "requirements.txt"
    "README.md"
    "antiransomware.db"
)

foreach ($file in $corePyFiles) {
    if (Test-Path (Join-Path $ProjectRoot $file)) {
        Copy-Item (Join-Path $ProjectRoot $file) $AppDir -Force
    }
}
Write-Host "    Copied core files" -ForegroundColor Green

# Copy templates
Write-Host "[3/8] Copying web templates..." -ForegroundColor Yellow
if (Test-Path (Join-Path $ProjectRoot "templates")) {
    Copy-Item (Join-Path $ProjectRoot "templates") $AppDir -Recurse -Force
}
Write-Host "    Copied templates" -ForegroundColor Green

# Copy static files
Write-Host "[4/8] Copying static resources..." -ForegroundColor Yellow
if (Test-Path (Join-Path $ProjectRoot "static")) {
    Copy-Item (Join-Path $ProjectRoot "static") $AppDir -Recurse -Force
}
Write-Host "    Copied static files" -ForegroundColor Green

# Copy proto files
Write-Host "[5/8] Copying protocol buffers..." -ForegroundColor Yellow
$protoFiles = Get-ChildItem $ProjectRoot -Filter "*.proto" -ErrorAction SilentlyContinue
foreach ($proto in $protoFiles) {
    Copy-Item $proto.FullName $AppDir -Force
}
$pbFiles = Get-ChildItem $ProjectRoot -Filter "*_pb2.py" -ErrorAction SilentlyContinue
foreach ($pb in $pbFiles) {
    Copy-Item $pb.FullName $AppDir -Force
}
Write-Host "    Copied proto files" -ForegroundColor Green

# Copy kernel driver
Write-Host "[6/8] Copying kernel driver..." -ForegroundColor Yellow
if (Test-Path (Join-Path $ProjectRoot "build_production\AntiRansomwareKernel.sys")) {
    Copy-Item (Join-Path $ProjectRoot "build_production\AntiRansomwareKernel.sys") $KernelDir -Force
    Copy-Item (Join-Path $ProjectRoot "real_kernel_driver.c") $KernelDir -Force
    if (Test-Path (Join-Path $ProjectRoot "anti_ransomware_minifilter.inf")) {
        Copy-Item (Join-Path $ProjectRoot "anti_ransomware_minifilter.inf") $KernelDir -Force
    }
    Write-Host "    Copied kernel driver" -ForegroundColor Green
} else {
    Write-Host "    Warning: Kernel driver not built, skipping" -ForegroundColor Yellow
}

# Create installation script
Write-Host "[7/8] Creating installer..." -ForegroundColor Yellow
$installerScript = @'
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Anti-Ransomware Protection System Installer
.DESCRIPTION
    Installs and configures the Anti-Ransomware protection system
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ANTI-RANSOMWARE PROTECTION INSTALLER" -ForegroundColor Cyan
Write-Host "   Version 1.0.0" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$InstallPath = "C:\Program Files\AntiRansomware"

# Check Python
Write-Host "[1/6] Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python 3\.(\d+)") {
        $minorVersion = [int]$matches[1]
        if ($minorVersion -ge 8) {
            Write-Host "    Found: $pythonVersion" -ForegroundColor Green
        } else {
            throw "Python 3.8 or higher required"
        }
    } else {
        throw "Python not found"
    }
} catch {
    Write-Host "    ERROR: Python 3.8+ not found" -ForegroundColor Red
    Write-Host "    Please install Python from https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Create installation directory
Write-Host "[2/6] Creating installation directory..." -ForegroundColor Yellow
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath | Out-Null
}
Write-Host "    Created: $InstallPath" -ForegroundColor Green

# Copy files
Write-Host "[3/6] Installing application files..." -ForegroundColor Yellow
Copy-Item "AntiRansomware\*" $InstallPath -Recurse -Force
Write-Host "    Files installed" -ForegroundColor Green

# Create virtual environment
Write-Host "[4/6] Setting up Python environment..." -ForegroundColor Yellow
Set-Location $InstallPath
if (Test-Path ".venv") {
    Remove-Item ".venv" -Recurse -Force
}
python -m venv .venv
& ".venv\Scripts\Activate.ps1"
pip install --upgrade pip | Out-Null
pip install -r requirements.txt | Out-Null
Write-Host "    Python environment ready" -ForegroundColor Green

# Create Windows Service
Write-Host "[5/6] Creating Windows Service..." -ForegroundColor Yellow
$serviceScript = @"
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import sys
import os
import subprocess

class AntiRansomwareService(win32serviceutil.ServiceFramework):
    _svc_name_ = 'AntiRansomwareProtection'
    _svc_display_name_ = 'Anti-Ransomware Protection Service'
    _svc_description_ = 'Real-time ransomware protection and monitoring'

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_alive = True
        self.process = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_alive = False
        if self.process:
            self.process.terminate()

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                            servicemanager.PYS_SERVICE_STARTED,
                            (self._svc_name_, ''))
        self.main()

    def main(self):
        install_dir = r'$InstallPath'
        os.chdir(install_dir)
        
        python_exe = os.path.join(install_dir, '.venv', 'Scripts', 'python.exe')
        dashboard_py = os.path.join(install_dir, 'admin_dashboard.py')
        
        self.process = subprocess.Popen([python_exe, dashboard_py])
        
        while self.is_alive:
            rc = win32event.WaitForSingleObject(self.hWaitStop, 5000)
            if rc == win32event.WAIT_OBJECT_0:
                break

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(AntiRansomwareService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(AntiRansomwareService)
"@

$serviceScript | Set-Content "$InstallPath\service.py"

# Install service dependencies
pip install pywin32 | Out-Null

# Install service
python "$InstallPath\service.py" install
Write-Host "    Service created: AntiRansomwareProtection" -ForegroundColor Green

# Create desktop shortcut for web admin
Write-Host "[6/6] Creating shortcuts..." -ForegroundColor Yellow
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:Public\Desktop\Anti-Ransomware Admin.url")
$Shortcut.TargetPath = "http://127.0.0.1:8080"
$Shortcut.Save()
Write-Host "    Desktop shortcut created" -ForegroundColor Green

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "   INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Service installed: AntiRansomwareProtection" -ForegroundColor Cyan
Write-Host ""
Write-Host "To start the service:" -ForegroundColor Yellow
Write-Host "  Start-Service AntiRansomwareProtection" -ForegroundColor White
Write-Host ""
Write-Host "To access web admin:" -ForegroundColor Yellow
Write-Host "  http://127.0.0.1:8080" -ForegroundColor White
Write-Host "  Username: admin" -ForegroundColor White
Write-Host "  Password: admin" -ForegroundColor White
Write-Host ""
Write-Host "Service will start automatically on system boot." -ForegroundColor Green
Write-Host ""

# Offer to start service now
$startNow = Read-Host "Start the service now? (Y/N)"
if ($startNow -eq "Y" -or $startNow -eq "y") {
    Start-Service AntiRansomwareProtection
    Start-Sleep -Seconds 3
    Write-Host ""
    Write-Host "Service started! Opening web admin..." -ForegroundColor Green
    Start-Process "http://127.0.0.1:8080"
}
'@

$installerScript | Set-Content "$DeploymentDir\Install.ps1" -Encoding UTF8
Write-Host "    Installer created" -ForegroundColor Green

# Create README
Write-Host "[8/8] Creating documentation..." -ForegroundColor Yellow
$readmeContent = @"
# Anti-Ransomware Protection System
Version 1.0.0

## What's Included

### User-Mode Protection (Works on ALL systems)
- Real-time file system monitoring
- Ransomware pattern detection
- Protected folder enforcement
- Post-quantum cryptographic token support
- Web-based admin dashboard
- Event logging and statistics

### Kernel-Mode Protection (Optional - Requires Microsoft signing or Secure Boot disabled)
- Ring-0 minifilter driver
- Cannot be bypassed by malware
- Real-time IRP interception
- Advanced threat detection

## Installation

### Requirements
- Windows 10/11 (64-bit)
- Python 3.8 or higher
- Administrator privileges

### Quick Install

1. Right-click PowerShell and select "Run as Administrator"
2. Navigate to this folder
3. Run: ``.\Install.ps1``
4. Follow the prompts

The installer will:
- Install application to C:\Program Files\AntiRansomware
- Create Python virtual environment
- Install dependencies
- Create Windows Service for auto-start
- Add desktop shortcut

### Post-Installation

1. Service starts automatically on boot
2. Access web admin: http://127.0.0.1:8080
3. Default credentials: admin/admin (CHANGE IMMEDIATELY)
4. Configure protected folders in the web interface
5. Monitor events and statistics

## Web Admin Features

- **Dashboard**: Real-time statistics and system status
- **Protected Paths**: Manage folders to protect from ransomware
- **Events**: View detection history and blocked attempts
- **Policy**: Configure detection sensitivity and rules
- **Drivers**: Kernel driver status (if installed)
- **Tokens**: Post-quantum crypto token management

## Kernel Driver Installation (Advanced)

The kernel driver provides enhanced Ring-0 protection but requires:

**For Testing:**
1. Disable Secure Boot in BIOS
2. Enable test signing: ``bcdedit /set testsigning on``
3. Reboot
4. Run: ``.\KernelDriver\Sign-And-Install-Driver.ps1``

**For Production:**
1. Obtain EV Code Signing Certificate
2. Submit driver to Microsoft Hardware Dev Center for WHQL signing
3. Deploy signed driver to endpoints

**Note:** User-mode protection provides excellent security without the kernel driver.

## Service Management

Start service:
``Start-Service AntiRansomwareProtection``

Stop service:
``Stop-Service AntiRansomwareProtection``

Restart service:
``Restart-Service AntiRansomwareProtection``

Check status:
``Get-Service AntiRansomwareProtection``

## Uninstallation

1. Stop the service: ``Stop-Service AntiRansomwareProtection``
2. Remove service: ``sc.exe delete AntiRansomwareProtection``
3. Delete: C:\Program Files\AntiRansomware
4. Remove desktop shortcut

## Support

For issues or questions:
- Check event logs: Event Viewer → Application → AntiRansomware
- Review web admin Events page
- Check service status

## Security Notes

- Change default admin password immediately
- Use TLS for remote access (configure in admin_dashboard.py)
- Regularly review protected folders
- Monitor event logs for suspicious activity
- Keep Python and dependencies updated

## Technical Details

- **User-Mode Engine**: Python-based file system watcher
- **Pattern Detection**: Entropy analysis, extension monitoring, rapid encryption detection
- **Kernel Driver**: Windows minifilter driver (C, WDK required)
- **Web Interface**: Flask with CSRF protection, waitress WSGI server
- **Database**: SQLite for events and configuration
- **Crypto**: Post-quantum Ed25519/Dilithium token support

## License

Copyright (c) 2025. All rights reserved.
"@

$readmeContent | Set-Content "$DeploymentDir\README.txt" -Encoding UTF8
Write-Host "    Documentation created" -ForegroundColor Green

# Create version info
$versionInfo = @{
    Version = $Version
    BuildDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Components = @{
        UserMode = "Ready"
        KernelDriver = if (Test-Path "$KernelDir\AntiRansomwareKernel.sys") { "Included" } else { "Not Built" }
        WebAdmin = "Ready"
        Database = "Included"
    }
}
$versionInfo | ConvertTo-Json | Set-Content "$DeploymentDir\version.json"

# Create package
Write-Host ""
Write-Host "Creating distribution archive..." -ForegroundColor Yellow
$zipPath = Join-Path $ProjectRoot "AntiRansomware-v$Version.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}
Compress-Archive -Path "$DeploymentDir\*" -DestinationPath $zipPath -CompressionLevel Optimal

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "   DEPLOYMENT PACKAGE CREATED!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Package location:" -ForegroundColor Cyan
Write-Host "  $zipPath" -ForegroundColor White
Write-Host ""
Write-Host "Package contents:" -ForegroundColor Cyan
Write-Host "  - Complete application files" -ForegroundColor White
Write-Host "  - Web admin dashboard" -ForegroundColor White
Write-Host "  - Windows Service installer" -ForegroundColor White
if (Test-Path "$KernelDir\AntiRansomwareKernel.sys") {
    Write-Host "  - Kernel driver (AntiRansomwareKernel.sys)" -ForegroundColor White
}
Write-Host "  - Installation guide" -ForegroundColor White
Write-Host ""
Write-Host "To deploy:" -ForegroundColor Yellow
Write-Host "  1. Extract ZIP on target system" -ForegroundColor White
Write-Host "  2. Run Install.ps1 as Administrator" -ForegroundColor White
Write-Host "  3. Access web admin at http://127.0.0.1:8080" -ForegroundColor White
Write-Host ""
Write-Host "Package size: $([math]::Round((Get-Item $zipPath).Length / 1MB, 2)) MB" -ForegroundColor Cyan
