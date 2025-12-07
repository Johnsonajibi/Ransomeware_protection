@echo off
echo.
echo ========================================
echo Building RealAntiRansomwareManager v2
echo ========================================
echo.

REM Use Visual Studio Developer Command Prompt
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64

echo Compiling...
cl.exe /EHsc /O2 /DUNICODE /D_UNICODE /MT /W3 RealAntiRansomwareManager_v2.cpp setupapi.lib newdev.lib cfgmgr32.lib crypt32.lib advapi32.lib kernel32.lib /Fe:RealAntiRansomwareManager.exe

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo SUCCESS: RealAntiRansomwareManager.exe
    echo ========================================
) else (
    echo.
    echo ========================================
    echo BUILD FAILED - See errors above
    echo ========================================
    echo.
    echo TROUBLESHOOTING:
    echo 1. Install "Desktop development with C++" in Visual Studio Installer
    echo 2. Make sure Windows 10 SDK is installed
    echo 3. Restart after installation
)
