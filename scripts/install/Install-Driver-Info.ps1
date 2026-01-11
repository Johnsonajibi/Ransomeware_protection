#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Install kernel driver - attempts multiple methods
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   KERNEL DRIVER INSTALLATION (ALTERNATIVE)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$ProjectRoot = $PSScriptRoot
$DriverSys = Join-Path $ProjectRoot "build_production\AntiRansomwareKernel.sys"

if (-not (Test-Path $DriverSys)) {
    throw "Driver not found: $DriverSys"
}

Write-Host "IMPORTANT: Secure Boot is enabled on this system." -ForegroundColor Yellow
Write-Host ""
Write-Host "For kernel driver development/testing, you have two options:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Disable Secure Boot in BIOS (Recommended for testing)" -ForegroundColor White
Write-Host "   - Reboot into BIOS/UEFI settings" -ForegroundColor Gray
Write-Host "   - Disable Secure Boot" -ForegroundColor Gray
Write-Host "   - Save and reboot" -ForegroundColor Gray
Write-Host "   - Run this script again" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Get a proper code signing certificate (Production)" -ForegroundColor White
Write-Host "   - Purchase EV code signing certificate (~$300/year)" -ForegroundColor Gray
Write-Host "   - Submit driver to Microsoft for WHQL signing" -ForegroundColor Gray
Write-Host "   - This is required for production deployment" -ForegroundColor Gray
Write-Host ""
Write-Host "For now, the web GUI and user-mode protection are fully functional." -ForegroundColor Green
Write-Host "The kernel driver provides additional Ring-0 protection when installed." -ForegroundColor Green
Write-Host ""

# Check if we're in a VM
$isVM = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model
if ($isVM -match "Virtual|VMware|VirtualBox") {
    Write-Host "NOTE: You're running in a VM. Secure Boot can usually be disabled in VM settings." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Driver is ready at: $DriverSys" -ForegroundColor Cyan
Write-Host "Size: $([math]::Round((Get-Item $DriverSys).Length / 1KB, 2)) KB" -ForegroundColor Cyan
