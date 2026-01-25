# Build Anti-Ransomware Installer
# Requires NSIS (Nullsoft Scriptable Install System)

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("online", "offline", "both")]
    [string]$Type = "both"
)

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Anti-Ransomware Installer Builder" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Build Type: $Type" -ForegroundColor Yellow
Write-Host ""

# Check if NSIS is installed
$nsisPath = "C:\Program Files (x86)\NSIS\makensis.exe"
if (-not (Test-Path $nsisPath)) {
    Write-Host "[ERROR] NSIS not found at $nsisPath" -ForegroundColor Red
    Write-Host "Please download and install NSIS from https://nsis.sourceforge.io/Download" -ForegroundColor Yellow
    exit 1
}

Write-Host "[OK] NSIS found" -ForegroundColor Green

# Create LICENSE.txt if it doesn't exist
if (-not (Test-Path "LICENSE.txt")) {
    Write-Host "[INFO] Creating LICENSE.txt..." -ForegroundColor Yellow
    @"
MIT License

Copyright (c) 2026 Anti-Ransomware Security

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"@ | Out-File -FilePath "LICENSE.txt" -Encoding UTF8
}

# Validate required files
$requiredFiles = @(
    "desktop_app.py",
    "unified_antiransomware.py",
    "config_manager.py",
    "requirements.txt",
    "installer.nsi"
)

$optionalFiles = @(
    "ml_detector.py",
    "attack_simulation.py"
)

$missingRequired = @()
foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) {
        $missingRequired += $file
    }
}

if ($missingRequired.Count -gt 0) {
    Write-Host "[ERROR] Required files not found:" -ForegroundColor Red
    foreach ($file in $missingRequired) {
        Write-Host "  - $file" -ForegroundColor Red
    }
    exit 1
}

Write-Host "[OK] All required files present" -ForegroundColor Green
Write-Host ""

# Check if offline build is requested and vendor directory exists
if ($Type -eq "offline" -or $Type -eq "both") {
    if (-not (Test-Path "vendor")) {
        Write-Host "[WARNING] Offline build requested but 'vendor' directory not found!" -ForegroundColor Yellow
        Write-Host "[INFO] Run .\download_dependencies.ps1 first to create offline installer." -ForegroundColor Yellow
        Write-Host ""
        
        if ($Type -eq "offline") {
            Write-Host "[ERROR] Cannot build offline installer without vendor directory" -ForegroundColor Red
            exit 1
        } else {
            Write-Host "[INFO] Skipping offline build, building online only..." -ForegroundColor Yellow
            Write-Host ""
            $Type = "online"
        }
    } else {
        $vendorFiles = (Get-ChildItem -Path "vendor" -File).Count
        $vendorSize = (Get-ChildItem -Path "vendor" -File | Measure-Object -Property Length -Sum).Sum / 1MB
        Write-Host "[OK] Vendor directory found: $vendorFiles files ($([math]::Round($vendorSize, 2)) MB)" -ForegroundColor Green
    }
}

# Build online installer
if ($Type -eq "online" -or $Type -eq "both") {
    Write-Host "[1/4] Compiling ONLINE installer..." -ForegroundColor Cyan
    & $nsisPath installer.nsi

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Online installer compiled successfully!" -ForegroundColor Green
        Write-Host ""
        
        # Generate checksums
        Write-Host "[2/4] Generating checksums for online installer..." -ForegroundColor Cyan
        $installerFile = "AntiRansomware-Setup-1.0.0.exe"
        
        if (Test-Path $installerFile) {
            $sha256 = (Get-FileHash -Path $installerFile -Algorithm SHA256).Hash
            $md5 = (Get-FileHash -Path $installerFile -Algorithm MD5).Hash
            $fileSize = (Get-Item $installerFile).Length / 1MB
            
            Write-Host "  SHA256: $sha256" -ForegroundColor White
            Write-Host "  MD5:    $md5" -ForegroundColor White
            Write-Host "  Size:   $([math]::Round($fileSize, 2)) MB" -ForegroundColor White
            Write-Host ""
            
            # Save checksums to file
            @"
Anti-Ransomware Protection Platform - ONLINE Installer Checksums
Version: 1.0.0
Build Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Size: $([math]::Round($fileSize, 2)) MB

SHA256: $sha256
MD5:    $md5

Installation Requirements:
- Windows 10/11 (64-bit)
- Python 3.11+ installed
- Internet connection (for pip install)
- Administrator privileges
"@ | Out-File -FilePath "checksums_online.txt" -Encoding UTF8
            
            Write-Host "[OK] Online installer build complete!" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        Write-Host "[ERROR] Online installer compilation failed with exit code $LASTEXITCODE" -ForegroundColor Red
        exit 1
    }
}

# Build offline installer
if ($Type -eq "offline" -or $Type -eq "both") {
    Write-Host "[3/4] Compiling OFFLINE installer..." -ForegroundColor Cyan
    & $nsisPath installer_offline.nsi

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Offline installer compiled successfully!" -ForegroundColor Green
        Write-Host ""
        
        # Generate checksums
        Write-Host "[4/4] Generating checksums for offline installer..." -ForegroundColor Cyan
        $installerFile = "AntiRansomware-Setup-1.0.0-offline.exe"
        
        if (Test-Path $installerFile) {
            $sha256 = (Get-FileHash -Path $installerFile -Algorithm SHA256).Hash
            $md5 = (Get-FileHash -Path $installerFile -Algorithm MD5).Hash
            $fileSize = (Get-Item $installerFile).Length / 1MB
            
            Write-Host "  SHA256: $sha256" -ForegroundColor White
            Write-Host "  MD5:    $md5" -ForegroundColor White
            Write-Host "  Size:   $([math]::Round($fileSize, 2)) MB" -ForegroundColor White
            Write-Host ""
            
            # Save checksums to file
            @"
Anti-Ransomware Protection Platform - OFFLINE Installer Checksums
Version: 1.0.0
Build Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Size: $([math]::Round($fileSize, 2)) MB

SHA256: $sha256
MD5:    $md5

Installation Requirements:
- Windows 10/11 (64-bit)
- Python 3.11+ installed
- NO internet connection required
- Administrator privileges

Note: All Python dependencies are bundled in this installer.
"@ | Out-File -FilePath "checksums_offline.txt" -Encoding UTF8
            
            Write-Host "[OK] Offline installer build complete!" -ForegroundColor Green
            Write-Host ""
        }
    } else {
        Write-Host "[ERROR] Offline installer compilation failed with exit code $LASTEXITCODE" -ForegroundColor Red
        exit 1
    }
}

# Summary
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "BUILD SUMMARY" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

if ($Type -eq "online" -or $Type -eq "both") {
    if (Test-Path "AntiRansomware-Setup-1.0.0.exe") {
        $size = (Get-Item "AntiRansomware-Setup-1.0.0.exe").Length / 1MB
        Write-Host "Online Installer:  AntiRansomware-Setup-1.0.0.exe ($([math]::Round($size, 2)) MB)" -ForegroundColor Green
        Write-Host "  - Requires internet during installation" -ForegroundColor Yellow
        Write-Host "  - Downloads dependencies from PyPI" -ForegroundColor Yellow
        Write-Host "  - Checksums: checksums_online.txt" -ForegroundColor White
        Write-Host ""
    }
}

if ($Type -eq "offline" -or $Type -eq "both") {
    if (Test-Path "AntiRansomware-Setup-1.0.0-offline.exe") {
        $size = (Get-Item "AntiRansomware-Setup-1.0.0-offline.exe").Length / 1MB
        Write-Host "Offline Installer: AntiRansomware-Setup-1.0.0-offline.exe ($([math]::Round($size, 2)) MB)" -ForegroundColor Green
        Write-Host "  - NO internet required" -ForegroundColor Yellow
        Write-Host "  - All dependencies bundled" -ForegroundColor Yellow
        Write-Host "  - Checksums: checksums_offline.txt" -ForegroundColor White
        Write-Host ""
    }
}

Write-Host "[OK] All builds complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Test installers in clean Windows VM" -ForegroundColor White
Write-Host "2. Verify all components install correctly" -ForegroundColor White
Write-Host "3. (Optional) Code-sign executables for production" -ForegroundColor White
Write-Host ""
