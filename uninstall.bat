@echo off
REM Uninstallation script for Anti-Ransomware Kernel Driver
REM Must be run as Administrator

echo ===============================================
echo  ANTI-RANSOMWARE KERNEL DRIVER REMOVAL
echo ===============================================
echo.

REM Check for Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo Removing Anti-Ransomware kernel driver...
echo.

REM Stop the service
echo Stopping kernel service...
sc stop AntiRansomwareKernel
if %errorlevel% equ 0 (
    echo Service stopped successfully
    timeout /t 3 /nobreak >nul
) else (
    echo Service was not running or already stopped
)

REM Delete the service
echo Removing kernel service...
sc delete AntiRansomwareKernel
if %errorlevel% equ 0 (
    echo Service removed successfully
) else (
    echo Failed to remove service or service does not exist
)

echo.
echo Removing desktop shortcut...
if exist "%USERPROFILE%\Desktop\Anti-Ransomware.lnk" (
    del "%USERPROFILE%\Desktop\Anti-Ransomware.lnk"
    echo Desktop shortcut removed
) else (
    echo Desktop shortcut not found
)

echo.
echo ===============================================
echo  UNINSTALLATION COMPLETE
echo ===============================================
echo.
echo The Anti-Ransomware kernel driver has been removed
echo from your system. All kernel-level protection has
echo been disabled.
echo.
echo Note: Driver files remain in the current directory
echo and can be used to reinstall if needed.
echo.

pause
