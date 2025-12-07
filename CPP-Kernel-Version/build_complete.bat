@echo off
REM ===============================================
REM ADVANCED C++ ANTI-RANSOMWARE BUILD SCRIPT
REM ===============================================
REM This script builds the complete C++ kernel-level
REM anti-ransomware protection system.
REM
REM Requirements:
REM - Visual Studio 2022 with C++ Build Tools
REM - Windows Driver Kit (WDK) for kernel driver
REM - Administrator privileges
REM ===============================================

echo.
echo ========================================================
echo   ADVANCED ANTI-RANSOMWARE BUILD SYSTEM
echo ========================================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script requires administrator privileges
    echo Please run as administrator
    pause
    exit /b 1
)

REM Set build directory
set BUILD_DIR=%~dp0build
set SRC_DIR=%~dp0src

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/4] Checking Visual Studio installation...

REM Check for Visual Studio 2022
set VS_PATH=""
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" (
    set VS_PATH="C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
    echo Found: Visual Studio 2022 Community
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" (
    set VS_PATH="C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"
    echo Found: Visual Studio 2022 Professional
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat" (
    set VS_PATH="C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"
    echo Found: Visual Studio 2022 Enterprise
) else (
    echo ERROR: Visual Studio 2022 not found
    echo Please install Visual Studio 2022 with C++ build tools
    echo Download from: https://visualstudio.microsoft.com/downloads/
    pause
    exit /b 1
)

REM Check for Windows Driver Kit
echo [2/4] Checking Windows Driver Kit...
set WDK_PATH=""
if exist "C:\Program Files (x86)\Windows Kits\10\bin\x64\inf2cat.exe" (
    set WDK_PATH="C:\Program Files (x86)\Windows Kits\10"
    echo Found: Windows Driver Kit 10
) else (
    echo WARNING: Windows Driver Kit not found
    echo Kernel driver will not be built
    echo Download WDK from: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    set BUILD_KERNEL=0
    goto :skip_wdk
)
set BUILD_KERNEL=1
:skip_wdk

echo [3/4] Building user application...

REM Setup Visual Studio environment and build user application
call %VS_PATH% -arch=x64 >nul 2>&1

REM Check if cl.exe is available
where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: C++ compiler not found in PATH
    echo Please ensure Visual Studio C++ Build Tools are properly installed
    pause
    exit /b 1
)

echo Compiling user application...
cl.exe /EHsc /std:c++17 /DUNICODE /D_UNICODE ^
    /I"%WINDOWS_SDK_PATH%\Include\%WINDOWS_SDK_VERSION%\um" ^
    /I"%WINDOWS_SDK_PATH%\Include\%WINDOWS_SDK_VERSION%\shared" ^
    "%SRC_DIR%\antiransomware_client.cpp" ^
    /link user32.lib gdi32.lib comctl32.lib shell32.lib kernel32.lib ^
    comdlg32.lib psapi.lib fltlib.lib ^
    /SUBSYSTEM:WINDOWS ^
    /out:"%BUILD_DIR%\AntiRansomware.exe"

if %errorlevel% neq 0 (
    echo ERROR: Failed to build user application
    pause
    exit /b 1
)

echo SUCCESS: User application built successfully

REM Build kernel driver if WDK is available
if %BUILD_KERNEL%==1 (
    echo [4/4] Building kernel driver...
    
    REM Create driver project files
    echo Creating driver build files...
    
    REM Create sources file for kernel driver
    echo TARGETNAME=AntiRansomwareKernel > "%SRC_DIR%\sources"
    echo TARGETTYPE=DRIVER_LIBRARY >> "%SRC_DIR%\sources"
    echo DRIVERTYPE=FS >> "%SRC_DIR%\sources"
    echo SOURCES=antiransomware_kernel.c >> "%SRC_DIR%\sources"
    echo INCLUDES=$(DDK_INC_PATH) >> "%SRC_DIR%\sources"
    echo TARGETLIBS=$(DDK_LIB_PATH)\fltmgr.lib $(DDK_LIB_PATH)\ntoskrnl.lib >> "%SRC_DIR%\sources"
    
    REM Build with WDK
    pushd "%SRC_DIR%"
    
    REM Setup WDK environment
    call "%WDK_PATH%\bin\SetupVSEnv.cmd" >nul 2>&1
    
    REM Build the driver
    build -ceZ
    
    if %errorlevel% neq 0 (
        echo WARNING: Kernel driver build failed
        echo This is normal if WDK is not properly configured
        echo The user application will work in simulation mode
    ) else (
        echo SUCCESS: Kernel driver built successfully
        REM Copy driver files to build directory
        if exist "objfre_win7_amd64\amd64\AntiRansomwareKernel.sys" (
            copy "objfre_win7_amd64\amd64\AntiRansomwareKernel.sys" "%BUILD_DIR%\"
            echo Kernel driver: %BUILD_DIR%\AntiRansomwareKernel.sys
        )
    )
    
    popd
) else (
    echo [4/4] Skipping kernel driver build (WDK not available)
)

echo.
echo ========================================================
echo   BUILD COMPLETE
echo ========================================================
echo.
echo Built files:
echo   User Application: %BUILD_DIR%\AntiRansomware.exe
if %BUILD_KERNEL%==1 (
    echo   Kernel Driver:    %BUILD_DIR%\AntiRansomwareKernel.sys
)
echo.
echo To run the application:
echo   1. Double-click AntiRansomware.exe
echo   2. Or run from command line with admin privileges
echo.
if %BUILD_KERNEL%==0 (
    echo NOTE: Application will run in simulation mode
    echo Install Windows Driver Kit to enable kernel protection
    echo.
)
echo Press any key to exit...
pause >nul
