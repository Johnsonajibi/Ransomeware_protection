#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Uninstalls the Anti-Ransomware kernel driver
.DESCRIPTION
    Safely removes all components of the anti-ransomware system
#>

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  ANTI-RANSOMWARE UNINSTALLATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$ServiceName = "AntiRansomwareKernel"
$DriverPath = Join-Path $env:SystemRoot "System32\drivers\AntiRansomwareKernel.sys"

# Stop and remove service
Write-Host "[1/3] Stopping and removing service..." -ForegroundColor Yellow
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($service) {
    if ($service.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    
    sc.exe delete $ServiceName
    Write-Host "✓ Service removed" -ForegroundColor Green
} else {
    Write-Host "✓ Service not found (already removed)" -ForegroundColor Green
}

# Remove driver file
Write-Host "[2/3] Removing driver file..." -ForegroundColor Yellow
if (Test-Path $DriverPath) {
    Remove-Item -Path $DriverPath -Force
    Write-Host "✓ Driver file removed" -ForegroundColor Green
} else {
    Write-Host "✓ Driver file not found (already removed)" -ForegroundColor Green
}

# Remove desktop shortcut
Write-Host "[3/3] Removing shortcuts..." -ForegroundColor Yellow
$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktopPath "Anti-Ransomware Protection.lnk"

if (Test-Path $shortcutPath) {
    Remove-Item -Path $shortcutPath -Force
    Write-Host "✓ Shortcut removed" -ForegroundColor Green
} else {
    Write-Host "✓ Shortcut not found" -ForegroundColor Green
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  UNINSTALLATION COMPLETED" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "The Anti-Ransomware driver has been removed." -ForegroundColor White
Write-Host "A system reboot is recommended." -ForegroundColor Yellow
Write-Host ""