#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Complete Anti-Ransomware Protection Installer
    Includes both Web Admin and Desktop Application
#>

param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Start,
    [switch]$Stop,
    [switch]$WebOnly,
    [switch]$DesktopOnly
)

$InstallPath = "C:\Program Files\AntiRansomware"
$ServiceName = "AntiRansomwareProtection"
$DesktopShortcut = [Environment]::GetFolderPath("Desktop") + "\AntiRansomware Desktop.lnk"
$StartMenuShortcut = [Environment]::GetFolderPath("StartMenu") + "\Programs\AntiRansomware Desktop.lnk"

function Install-AntiRansomware {
    Write-Host "`n══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  ANTI-RANSOMWARE PROTECTION INSTALLER" -ForegroundColor Green
    Write-Host "══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
    
    # Create installation directory
    if (-not (Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath | Out-Null
    }
    
    # Install Web Service (unless DesktopOnly)
    if (-not $DesktopOnly) {
        Write-Host "📦 Installing Web Admin Service..." -ForegroundColor Yellow
        if (Test-Path "AntiRansomware.exe") {
            Copy-Item "AntiRansomware.exe" $InstallPath -Force
            
            $exePath = Join-Path $InstallPath "AntiRansomware.exe"
            sc.exe create $ServiceName binPath= $exePath start= auto DisplayName= "Anti-Ransomware Protection" | Out-Null
            sc.exe description $ServiceName "Real-time ransomware protection and monitoring" | Out-Null
            
            Write-Host "✓ Web Admin Service installed" -ForegroundColor Green
        } else {
            Write-Host "⚠ AntiRansomware.exe not found - skipping web service" -ForegroundColor Yellow
        }
    }
    
    # Install Desktop App (unless WebOnly)
    if (-not $WebOnly) {
        Write-Host "`n🖥️ Installing Desktop Application..." -ForegroundColor Yellow
        if (Test-Path "AntiRansomware-Desktop.exe") {
            Copy-Item "AntiRansomware-Desktop.exe" $InstallPath -Force
            
            # Create shortcuts
            $WshShell = New-Object -ComObject WScript.Shell
            
            # Desktop shortcut
            $Shortcut = $WshShell.CreateShortcut($DesktopShortcut)
            $Shortcut.TargetPath = Join-Path $InstallPath "AntiRansomware-Desktop.exe"
            $Shortcut.WorkingDirectory = $InstallPath
            $Shortcut.Description = "Anti-Ransomware Protection Desktop"
            $Shortcut.Save()
            
            # Start Menu shortcut
            $Shortcut = $WshShell.CreateShortcut($StartMenuShortcut)
            $Shortcut.TargetPath = Join-Path $InstallPath "AntiRansomware-Desktop.exe"
            $Shortcut.WorkingDirectory = $InstallPath
            $Shortcut.Description = "Anti-Ransomware Protection Desktop"
            $Shortcut.Save()
            
            Write-Host "✓ Desktop Application installed" -ForegroundColor Green
            Write-Host "✓ Shortcuts created" -ForegroundColor Green
        } else {
            Write-Host "⚠ AntiRansomware-Desktop.exe not found - skipping desktop app" -ForegroundColor Yellow
        }
    }
    
    # Copy kernel driver if present
    if (Test-Path "AntiRansomwareKernel.sys") {
        Write-Host "`n🔒 Copying Kernel Driver..." -ForegroundColor Yellow
        Copy-Item "AntiRansomwareKernel.sys" $InstallPath -Force
        Write-Host "✓ Kernel driver copied (requires separate installation)" -ForegroundColor Green
    }
    
    Write-Host "`n══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLATION COMPLETE!" -ForegroundColor Green
    Write-Host "══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
    
    Write-Host "Access Options:" -ForegroundColor Yellow
    if (-not $DesktopOnly) {
        Write-Host "  🌐 Web Admin: http://127.0.0.1:8080" -ForegroundColor White
        Write-Host "     Login: admin/admin (CHANGE IMMEDIATELY)" -ForegroundColor White
    }
    if (-not $WebOnly) {
        Write-Host "  🖥️ Desktop App: Launch from Desktop or Start Menu" -ForegroundColor White
    }
    Write-Host ""
}

function Uninstall-AntiRansomware {
    Write-Host "`nUninstalling Anti-Ransomware Protection..." -ForegroundColor Cyan
    
    # Stop and remove service
    Stop-Service $ServiceName -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    
    # Remove shortcuts
    if (Test-Path $DesktopShortcut) {
        Remove-Item $DesktopShortcut -Force
    }
    if (Test-Path $StartMenuShortcut) {
        Remove-Item $StartMenuShortcut -Force
    }
    
    # Remove installation directory
    if (Test-Path $InstallPath) {
        Remove-Item $InstallPath -Recurse -Force
    }
    
    Write-Host "✓ Uninstalled successfully!" -ForegroundColor Green
}

function Start-Protection {
    Write-Host "`nStarting protection..." -ForegroundColor Cyan
    
    # Start service if exists
    try {
        Start-Service $ServiceName -ErrorAction Stop
        Write-Host "✓ Web service started!" -ForegroundColor Green
    } catch {
        Write-Host "⚠ Web service not installed or failed to start" -ForegroundColor Yellow
    }
    
    # Launch desktop app if exists
    $desktopPath = Join-Path $InstallPath "AntiRansomware-Desktop.exe"
    if (Test-Path $desktopPath) {
        Start-Process $desktopPath
        Write-Host "✓ Desktop application launched!" -ForegroundColor Green
    }
    
    # Open web admin
    Start-Sleep -Seconds 2
    try {
        Start-Process "http://127.0.0.1:8080"
    } catch {}
}

function Stop-Protection {
    Write-Host "`nStopping protection..." -ForegroundColor Cyan
    
    # Stop service
    try {
        Stop-Service $ServiceName -ErrorAction Stop
        Write-Host "✓ Web service stopped!" -ForegroundColor Green
    } catch {
        Write-Host "⚠ Web service not running" -ForegroundColor Yellow
    }
    
    # Kill desktop app process
    Get-Process -Name "AntiRansomware-Desktop" -ErrorAction SilentlyContinue | Stop-Process -Force
}

# Main execution
if ($Install) {
    Install-AntiRansomware
    
    $startNow = Read-Host "`nStart protection now? (Y/N)"
    if ($startNow -eq "Y") {
        Start-Protection
    }
    
} elseif ($Uninstall) {
    $confirm = Read-Host "Are you sure you want to uninstall? (Y/N)"
    if ($confirm -eq "Y") {
        Uninstall-AntiRansomware
    }
    
} elseif ($Start) {
    Start-Protection
    
} elseif ($Stop) {
    Stop-Protection
    
} else {
    Write-Host "`n══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  ANTI-RANSOMWARE PROTECTION INSTALLER" -ForegroundColor Green
    Write-Host "══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
    
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\Installer.ps1 -Install         Install complete package" -ForegroundColor White
    Write-Host "  .\Installer.ps1 -Install -WebOnly    Install web service only" -ForegroundColor White
    Write-Host "  .\Installer.ps1 -Install -DesktopOnly Install desktop app only" -ForegroundColor White
    Write-Host "  .\Installer.ps1 -Uninstall       Remove installation" -ForegroundColor White
    Write-Host "  .\Installer.ps1 -Start           Start all components" -ForegroundColor White
    Write-Host "  .\Installer.ps1 -Stop            Stop all components" -ForegroundColor White
    Write-Host ""
    Write-Host "Quick Launch:" -ForegroundColor Yellow
    Write-Host "  .\AntiRansomware.exe              Run web admin directly" -ForegroundColor White
    Write-Host "  .\AntiRansomware-Desktop.exe      Run desktop app directly" -ForegroundColor White
    Write-Host ""
}
