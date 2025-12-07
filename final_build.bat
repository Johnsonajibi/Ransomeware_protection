@echo off
REM Final build script - run this from x64 Native Tools Command Prompt
echo ===============================================
echo  BUILDING ANTI-RANSOMWARE C++ APPLICATION
echo ===============================================
echo.

REM Check if cl.exe is available
where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: cl.exe not found in PATH
    echo.
    echo You must run this from: "x64 Native Tools Command Prompt for VS 2022"
    echo.
    echo Steps:
    echo 1. Press Windows key
    echo 2. Search for "x64 Native Tools Command Prompt"
    echo 3. Right-click and "Run as administrator"
    echo 4. cd "C:\Users\ajibi\Music\Anti-Ransomeware"
    echo 5. run: final_build.bat
    echo.
    pause
    exit /b 1
)

echo Compiling Anti-Ransomware Client...
echo.

cl.exe /EHsc /std:c++17 /DUNICODE /D_UNICODE ^
    antiransomware_client.cpp ^
    /link user32.lib gdi32.lib comctl32.lib shell32.lib kernel32.lib comdlg32.lib ^
    /SUBSYSTEM:WINDOWS ^
    /out:antiransomware_client.exe

if %errorlevel% neq 0 (
    echo.
    echo ===============================================
    echo  BUILD FAILED!
    echo ===============================================
    echo Check the error messages above.
    echo.
    pause
    exit /b 1
)

echo.
echo ===============================================
echo  BUILD SUCCESSFUL!
echo ===============================================
echo.
echo ✅ Created: antiransomware_client.exe
echo.

REM Check file size
for %%A in (antiransomware_client.exe) do echo 📁 Size: %%~zA bytes

echo.
echo 🚀 To run the application:
echo    antiransomware_client.exe        (GUI mode)
echo    antiransomware_client.exe --cli  (CLI mode)
echo.
echo 📝 Note: App runs in SIMULATION MODE without kernel driver
echo    All features will work for testing purposes.
echo.

pause
