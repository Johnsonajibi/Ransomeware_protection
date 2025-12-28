# Run Anti-Ransomware with Administrator Privileges
# This enables TPM access for MAXIMUM security level

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Anti-Ransomware - Admin Mode" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "[OK] Running with Administrator privileges" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "[ERROR] Not running as Administrator!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please run PowerShell as Administrator:" -ForegroundColor Yellow
    Write-Host "1. Right-click PowerShell" -ForegroundColor Yellow
    Write-Host "2. Select 'Run as administrator'" -ForegroundColor Yellow
    Write-Host "3. Run this script again" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Navigate to script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Activate virtual environment
Write-Host "Activating Python virtual environment..." -ForegroundColor Cyan
& ".\.venv\Scripts\Activate.ps1"

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Virtual environment not found" -ForegroundColor Red
    Write-Host "Run: python -m venv .venv" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Checking TPM Status" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check TPM using PowerShell cmdlet
try {
    $tpm = Get-Tpm
    Write-Host "TPM Information:" -ForegroundColor Green
    Write-Host "  TpmPresent:   $($tpm.TpmPresent)" -ForegroundColor White
    Write-Host "  TpmReady:     $($tpm.TpmReady)" -ForegroundColor White
    Write-Host "  TpmEnabled:   $($tpm.TpmEnabled)" -ForegroundColor White
    Write-Host "  TpmActivated: $($tpm.TpmActivated)" -ForegroundColor White
    Write-Host "  TpmOwned:     $($tpm.TpmOwned)" -ForegroundColor White
    Write-Host ""
    
    if ($tpm.TpmPresent -and $tpm.TpmReady) {
        Write-Host "[OK] TPM is available and ready!" -ForegroundColor Green
    } elseif ($tpm.TpmPresent -and -not $tpm.TpmReady) {
        Write-Host "[WARNING] TPM present but not ready. Initialize with: Initialize-Tpm" -ForegroundColor Yellow
    } else {
        Write-Host "[WARNING] TPM not present or disabled in BIOS" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "[ERROR] Could not access TPM: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Testing TPM Access (Python)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

python test_tpm.py

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Running Tri-Factor Authentication Demo" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

python trifactor_auth_manager.py

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Demo Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Read-Host "Press Enter to exit"
