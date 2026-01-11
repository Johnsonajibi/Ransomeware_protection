@echo off
REM Simple build script using cl.exe directly
REM Must be run from Visual Studio Developer Command Prompt

echo ===============================================
echo  BUILDING ANTI-RANSOMWARE KERNEL SYSTEM
echo ===============================================

REM Check if we're in the right environment
where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Visual Studio build tools not found in PATH
    echo Please run this from "x64 Native Tools Command Prompt for VS"
    echo.
    echo To find it:
    echo 1. Press Windows key
    echo 2. Search for "x64 Native Tools Command Prompt"
    echo 3. Right-click and "Run as administrator"
    echo 4. Navigate to this directory and run: build_simple.bat
    pause
    exit /b 1
)

echo Building user application...

REM Compile the C++ client application
cl.exe /EHsc /std:c++17 ^
    /I"%WindowsSdkDir%Include\%WindowsSDKVersion%\um" ^
    /I"%WindowsSdkDir%Include\%WindowsSDKVersion%\shared" ^
    antiransomware_client.cpp ^
    /link user32.lib gdi32.lib comctl32.lib shell32.lib kernel32.lib ^
    /out:antiransomware_client.exe

if %errorlevel% neq 0 (
    echo ERROR: Failed to build user application
    pause
    exit /b 1
)

echo.
echo ===============================================
echo  BUILD COMPLETE
echo ===============================================
echo.
echo Built successfully:
echo   - antiransomware_client.exe (User Application)
echo.
echo Note: Kernel driver requires Windows Driver Kit (WDK)
echo For now, you can test the user application in simulation mode.
echo.
echo To run:
echo   antiransomware_client.exe        (GUI mode)
echo   antiransomware_client.exe --cli  (CLI mode)
echo.

pause
