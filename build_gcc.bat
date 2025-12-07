@echo off
REM Alternative build script using MinGW/GCC
REM Run this if Visual Studio is not available

echo ===============================================
echo  BUILDING WITH MINGW/GCC COMPILER
echo ===============================================

REM Check if GCC is available
where gcc >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: GCC compiler not found
    echo.
    echo Please install one of:
    echo 1. Visual Studio Community 2022 ^(recommended^)
    echo 2. MinGW-w64 ^(lightweight alternative^)
    echo.
    echo To install MinGW-w64:
    echo 1. Download from: https://www.mingw-w64.org/downloads/
    echo 2. Or use MSYS2: https://www.msys2.org/
    echo 3. Add to PATH: C:\msys64\mingw64\bin
    echo.
    pause
    exit /b 1
)

echo Building with GCC...

REM Compile with GCC
g++ -std=c++17 -municode -mwindows ^
    antiransomware_client.cpp ^
    -luser32 -lgdi32 -lcomctl32 -lshell32 -lkernel32 ^
    -o antiransomware_client.exe

if %errorlevel% neq 0 (
    echo ERROR: Build failed with GCC
    pause
    exit /b 1
)

echo.
echo ===============================================
echo  BUILD COMPLETE WITH GCC
echo ===============================================
echo.
echo Built successfully:
echo   - antiransomware_client.exe (User Application)
echo.
echo To run:
echo   antiransomware_client.exe        (GUI mode)
echo   antiransomware_client.exe --cli  (CLI mode)
echo.

pause
