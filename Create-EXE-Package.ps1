<#
.SYNOPSIS
    Package Anti-Ransomware as standalone EXE installer
.DESCRIPTION
    Creates a single executable installer with all dependencies embedded
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   CREATING EXE INSTALLER PACKAGE" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$ProjectRoot = $PSScriptRoot
$DistDir = Join-Path $ProjectRoot "dist"

# Activate venv
Write-Host "[1/6] Activating Python environment..." -ForegroundColor Yellow
& "$ProjectRoot\.venv\Scripts\Activate.ps1"

# Install PyInstaller
Write-Host "[2/6] Installing PyInstaller..." -ForegroundColor Yellow
pip install pyinstaller | Out-Null
Write-Host "    PyInstaller ready" -ForegroundColor Green

# Create spec file for admin dashboard
Write-Host "[3/6] Creating PyInstaller spec..." -ForegroundColor Yellow
$specContent = @"
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['admin_dashboard.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('templates', 'templates'),
        ('static', 'static'),
        ('antiransomware.db', '.'),
        ('*.proto', '.'),
        ('*_pb2.py', '.'),
    ],
    hiddenimports=[
        'flask',
        'flask_wtf',
        'waitress',
        'cryptography',
        'pynacl',
        'watchdog',
        'google.protobuf',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='AntiRansomware',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    version='version_info.txt'
)
"@

$specContent | Set-Content "$ProjectRoot\antiransomware.spec" -Encoding UTF8

# Create version info
$versionInfo = @"
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'Anti-Ransomware Protection'),
        StringStruct(u'FileDescription', u'Anti-Ransomware Protection System'),
        StringStruct(u'FileVersion', u'1.0.0.0'),
        StringStruct(u'InternalName', u'AntiRansomware'),
        StringStruct(u'LegalCopyright', u'Copyright (c) 2025'),
        StringStruct(u'OriginalFilename', u'AntiRansomware.exe'),
        StringStruct(u'ProductName', u'Anti-Ransomware Protection'),
        StringStruct(u'ProductVersion', u'1.0.0.0')])
      ]
    ),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"@

$versionInfo | Set-Content "$ProjectRoot\version_info.txt" -Encoding UTF8
Write-Host "    Spec file created" -ForegroundColor Green

# Build EXE
Write-Host "[4/6] Building executable (this may take several minutes)..." -ForegroundColor Yellow
$buildOutput = & pyinstaller --clean --noconfirm "$ProjectRoot\antiransomware.spec" 2>&1
$buildOutput | Out-Host

if ($LASTEXITCODE -ne 0) {
    Write-Host "`nBuild failed with exit code $LASTEXITCODE" -ForegroundColor Red
    throw "PyInstaller failed"
}

if (-not (Test-Path "$DistDir\AntiRansomware.exe")) {
    Write-Host "`nBuild Output:" -ForegroundColor Red
    $buildOutput | Out-Host
    throw "EXE build failed"
}

$exeSize = [math]::Round((Get-Item "$DistDir\AntiRansomware.exe").Length / 1MB, 2)
Write-Host "    EXE created: $exeSize MB" -ForegroundColor Green

# Create installer wrapper script
Write-Host "[5/6] Creating installer wrapper..." -ForegroundColor Yellow
$installerWrapper = @'
#Requires -RunAsAdministrator

param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Start,
    [switch]$Stop
)

$InstallPath = "C:\Program Files\AntiRansomware"
$ServiceName = "AntiRansomwareProtection"

function Install-AntiRansomware {
    Write-Host "Installing Anti-Ransomware Protection..." -ForegroundColor Cyan
    
    # Create directory
    if (-not (Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath | Out-Null
    }
    
    # Copy executable
    Copy-Item "AntiRansomware.exe" $InstallPath -Force
    
    # Create Windows Service using NSSM or sc.exe
    $exePath = Join-Path $InstallPath "AntiRansomware.exe"
    
    # Using sc.exe to create service
    sc.exe create $ServiceName binPath= $exePath start= auto DisplayName= "Anti-Ransomware Protection" | Out-Null
    sc.exe description $ServiceName "Real-time ransomware protection and monitoring" | Out-Null
    
    Write-Host "Installation complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "To start the service: Start-Service $ServiceName" -ForegroundColor Yellow
    Write-Host "Web Admin: http://127.0.0.1:8080 (admin/admin)" -ForegroundColor Yellow
}

function Uninstall-AntiRansomware {
    Write-Host "Uninstalling Anti-Ransomware Protection..." -ForegroundColor Cyan
    
    # Stop service
    Stop-Service $ServiceName -ErrorAction SilentlyContinue
    
    # Delete service
    sc.exe delete $ServiceName | Out-Null
    
    # Remove files
    if (Test-Path $InstallPath) {
        Remove-Item $InstallPath -Recurse -Force
    }
    
    Write-Host "Uninstallation complete!" -ForegroundColor Green
}

function Start-AntiRansomwareService {
    Start-Service $ServiceName
    Write-Host "Service started!" -ForegroundColor Green
    Write-Host "Web Admin: http://127.0.0.1:8080" -ForegroundColor Cyan
    Start-Sleep -Seconds 2
    Start-Process "http://127.0.0.1:8080"
}

function Stop-AntiRansomwareService {
    Stop-Service $ServiceName
    Write-Host "Service stopped!" -ForegroundColor Green
}

# Main menu
if ($Install) {
    Install-AntiRansomware
    $startNow = Read-Host "Start service now? (Y/N)"
    if ($startNow -eq "Y") {
        Start-AntiRansomwareService
    }
} elseif ($Uninstall) {
    Uninstall-AntiRansomware
} elseif ($Start) {
    Start-AntiRansomwareService
} elseif ($Stop) {
    Stop-AntiRansomwareService
} else {
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "   ANTI-RANSOMWARE PROTECTION INSTALLER" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\Installer.ps1 -Install      Install as Windows Service"
    Write-Host "  .\Installer.ps1 -Uninstall    Remove service and files"
    Write-Host "  .\Installer.ps1 -Start        Start the service"
    Write-Host "  .\Installer.ps1 -Stop         Stop the service"
    Write-Host ""
    Write-Host "Or run directly: .\AntiRansomware.exe" -ForegroundColor Cyan
}
'@

$installerWrapper | Set-Content "$DistDir\Installer.ps1" -Encoding UTF8
Write-Host "    Installer wrapper created" -ForegroundColor Green

# Copy kernel driver
if (Test-Path "$ProjectRoot\build_production\AntiRansomwareKernel.sys") {
    Copy-Item "$ProjectRoot\build_production\AntiRansomwareKernel.sys" $DistDir -Force
    Write-Host "    Kernel driver included" -ForegroundColor Green
}

# Create README
Write-Host "[6/6] Creating documentation..." -ForegroundColor Yellow
$readmeContent = @"
# Anti-Ransomware Protection System - Standalone Installer
Version 1.0.0

## Quick Installation

### Option 1: Install as Windows Service (Recommended)
1. Right-click PowerShell → Run as Administrator
2. Navigate to this folder
3. Run: .\Installer.ps1 -Install
4. Access web admin: http://127.0.0.1:8080
5. Login: admin/admin (CHANGE IMMEDIATELY)

### Option 2: Run Directly
1. Right-click PowerShell → Run as Administrator  
2. Run: .\AntiRansomware.exe
3. Access web admin: http://127.0.0.1:8080

## Features
- Real-time ransomware detection
- Protected folder monitoring
- Web-based admin dashboard
- Event logging and statistics
- Post-quantum crypto token support

## Management Commands

Install service:
.\Installer.ps1 -Install

Start service:
.\Installer.ps1 -Start

Stop service:
.\Installer.ps1 -Stop

Uninstall:
.\Installer.ps1 -Uninstall

## Web Admin Access
URL: http://127.0.0.1:8080
Default credentials: admin/admin

## What's Included
- AntiRansomware.exe (Standalone executable, ~$exeSize MB)
- Installer.ps1 (Service installation script)
- AntiRansomwareKernel.sys (Optional kernel driver)

## System Requirements
- Windows 10/11 (64-bit)
- Administrator privileges
- No Python installation needed (embedded)

## Kernel Driver (Advanced)
For enhanced Ring-0 protection:
1. Disable Secure Boot in BIOS
2. Enable test signing: bcdedit /set testsigning on
3. Reboot
4. Install kernel driver separately

OR get Microsoft WHQL signing for production use.

## Support
Check Event Viewer → Application → AntiRansomware for logs
Visit web admin Events page for detection history

## Security Notes
- Change default password immediately
- Configure protected folders in web admin
- Monitor events regularly
- Service runs with SYSTEM privileges

Copyright (c) 2025. All rights reserved.
"@

$readmeContent | Set-Content "$DistDir\README.txt" -Encoding UTF8
Write-Host "    Documentation created" -ForegroundColor Green

# Create final distribution package
Write-Host ""
Write-Host "Creating distribution package..." -ForegroundColor Yellow
$packageName = "AntiRansomware-Installer-v1.0.0"
$packageDir = Join-Path $ProjectRoot $packageName

if (Test-Path $packageDir) {
    Remove-Item $packageDir -Recurse -Force
}
New-Item -ItemType Directory -Path $packageDir | Out-Null

# Copy distribution files
Copy-Item "$DistDir\AntiRansomware.exe" $packageDir -Force
Copy-Item "$DistDir\Installer.ps1" $packageDir -Force
Copy-Item "$DistDir\README.txt" $packageDir -Force
if (Test-Path "$DistDir\AntiRansomwareKernel.sys") {
    Copy-Item "$DistDir\AntiRansomwareKernel.sys" $packageDir -Force
}

# Create ZIP
$zipPath = "$ProjectRoot\$packageName.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}
Compress-Archive -Path "$packageDir\*" -DestinationPath $zipPath -CompressionLevel Optimal

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "   EXE INSTALLER PACKAGE CREATED!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Package location:" -ForegroundColor Cyan
Write-Host "  $zipPath" -ForegroundColor White
Write-Host ""
Write-Host "Package contents:" -ForegroundColor Cyan
Write-Host "  - AntiRansomware.exe ($exeSize MB - all dependencies embedded)" -ForegroundColor White
Write-Host "  - Installer.ps1 (Windows Service installer)" -ForegroundColor White
Write-Host "  - README.txt (Complete documentation)" -ForegroundColor White
if (Test-Path "$packageDir\AntiRansomwareKernel.sys") {
    Write-Host "  - AntiRansomwareKernel.sys (Optional kernel driver)" -ForegroundColor White
}
Write-Host ""
Write-Host "Distribution ready!" -ForegroundColor Green
Write-Host ""
Write-Host "To test locally:" -ForegroundColor Yellow
Write-Host "  cd $packageDir" -ForegroundColor White
Write-Host "  .\Installer.ps1 -Install" -ForegroundColor White
Write-Host ""
Write-Host "Package size: $([math]::Round((Get-Item $zipPath).Length / 1MB, 2)) MB" -ForegroundColor Cyan
