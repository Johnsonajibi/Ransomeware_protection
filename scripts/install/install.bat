@echo off
REM Installation script for Anti-Ransomware Kernel Driver
REM Must be run as Administrator

echo ===============================================
echo  ANTI-RANSOMWARE KERNEL DRIVER INSTALLATION
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

echo Checking system requirements...

REM Check if driver file exists
if not exist "antiransomware_kernel.sys" (
    echo ERROR: Driver file not found: antiransomware_kernel.sys
    echo Please ensure the driver is built and present
    pause
    exit /b 1
)

REM Check if user client exists
if not exist "antiransomware_client.exe" (
    echo ERROR: Client application not found: antiransomware_client.exe
    echo Please ensure the client is built and present
    pause
    exit /b 1
)

echo.
echo Installing kernel driver...

REM Stop existing service if running
sc query AntiRansomwareKernel >nul 2>&1
if %errorlevel% equ 0 (
    echo Stopping existing service...
    sc stop AntiRansomwareKernel
    timeout /t 3 /nobreak >nul
    
    echo Removing existing service...
    sc delete AntiRansomwareKernel
    timeout /t 2 /nobreak >nul
)

REM Create service
echo Creating kernel service...
sc create AntiRansomwareKernel type=kernel start=demand error=normal binpath="%CD%\antiransomware_kernel.sys" displayname="Anti-Ransomware Kernel Protection"

if %errorlevel% neq 0 (
    echo ERROR: Failed to create service
    echo Common causes:
    echo   - Driver not digitally signed
    echo   - Test signing not enabled
    echo   - Insufficient privileges
    echo.
    echo For development, enable test signing:
    echo   bcdedit /set testsigning on
    echo   ^(Reboot required^)
    pause
    exit /b 1
)

REM Start service
echo Starting kernel service...
sc start AntiRansomwareKernel

if %errorlevel% neq 0 (
    echo WARNING: Service created but failed to start
    echo This may be due to:
    echo   - Driver signing issues
    echo   - System compatibility
    echo   - Missing dependencies
    echo.
    echo Service is installed and can be started manually
) else (
    echo Kernel driver started successfully!
)

echo.
echo Creating desktop shortcut...
powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\Anti-Ransomware.lnk'); $Shortcut.TargetPath = '%CD%\antiransomware_client.exe'; $Shortcut.WorkingDirectory = '%CD%'; $Shortcut.Description = 'Anti-Ransomware Kernel Protection'; $Shortcut.Save()"

echo.
echo ===============================================
echo  INSTALLATION COMPLETE
echo ===============================================
echo.
echo Service Name: AntiRansomwareKernel
echo Client Application: antiransomware_client.exe
echo Desktop Shortcut: Created
echo.
echo The kernel driver provides real Ring-0 protection
echo against ransomware and malicious file operations.
echo.
echo To use:
echo   1. Run antiransomware_client.exe (GUI mode)
echo   2. Or: antiransomware_client.exe --cli (Command line)
echo.
echo For troubleshooting:
echo   - Check Windows Event Viewer for driver messages
echo   - Ensure test signing is enabled for development
echo   - Run client as Administrator for full functionality
echo.

pause
