@echo off
    REM ====================================================================
REM ANTI-RANSOMWARE PRODUCTION BUILD SCRIPT (SIMPLIFIED VERSION)
REM ====================================================================

echo.
echo ============================================================
echo   ANTI-RANSOMWARE - PRODUCTION BUILD (SECURITY HARDENED)
echo ============================================================
echo.

REM Check for Administrator privileges
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: This script must be run as Administrator!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

REM Set build paths using short names to avoid spaces
set PROJECT_ROOT=%~dp0
set BUILD_DIR=%PROJECT_ROOT%build_production
set WDK_BASE=C:\Program Files (x86)\Windows Kits\10

echo [1/6] Checking build environment...
echo.

REM Check for WDK
if not exist "%WDK_BASE%" (
    echo ERROR: Windows Driver Kit not found!
    echo Please install WDK 10 from Microsoft
    pause
    exit /b 1
)

echo Found Windows Kit 10, checking SDK versions...

REM Check for available SDK versions in priority order
set SDK_VER=
if exist "%WDK_BASE%\Include\10.0.22621.0" set SDK_VER=10.0.22621.0
if "%SDK_VER%"=="" if exist "%WDK_BASE%\Include\10.0.22000.0" set SDK_VER=10.0.22000.0
if "%SDK_VER%"=="" if exist "%WDK_BASE%\Include\10.0.20348.0" set SDK_VER=10.0.20348.0
if "%SDK_VER%"=="" if exist "%WDK_BASE%\Include\10.0.19041.0" set SDK_VER=10.0.19041.0
if "%SDK_VER%"=="" if exist "%WDK_BASE%\Include\10.0.18362.0" set SDK_VER=10.0.18362.0

if "%SDK_VER%"=="" (
    echo ERROR: Could not find a compatible SDK version in Windows Kit 10.
    echo Checked: 10.0.22621.0, 10.0.22000.0, 10.0.20348.0, 10.0.19041.0, 10.0.18362.0
    echo.
    echo Please install the Windows SDK from:
    echo https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
    pause
    exit /b 1
)

echo Found SDK version: %SDK_VER%

echo [2/6] Checking for Visual Studio...
set VS_FOUND=0
set VS_PATH=

REM Check for VS 2022
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community
    set VS_VER=2022 Community
    set VS_FOUND=1
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
    set VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Professional
    set VS_VER=2022 Professional
    set VS_FOUND=1
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
    set VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise
    set VS_VER=2022 Enterprise
    set VS_FOUND=1
)

REM Check for VS 2019 if 2022 not found
if %VS_FOUND%==0 (
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
        set VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community
        set VS_VER=2019 Community
        set VS_FOUND=1
    ) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
        set VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional
        set VS_VER=2019 Professional
        set VS_FOUND=1
    ) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
        set VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise
        set VS_VER=2019 Enterprise
        set VS_FOUND=1
    )
)

REM If VS not found, provide guidance
if %VS_FOUND%==0 (
    echo ERROR: Visual Studio with C++ support not found!
    echo.
    echo Please install Visual Studio 2022 Community Edition:
    echo 1. Download from: https://visualstudio.microsoft.com/downloads/
    echo 2. During installation, select "Desktop development with C++"
    echo.
    pause
    exit /b 1
)

echo Found Visual Studio %VS_VER% at: %VS_PATH%

echo [3/6] Creating build directory...
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [4/6] Setting up build environment...
echo Setting up Visual Studio environment...
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64

REM Verify that cl.exe is now available
echo [5/6] Verifying compiler setup...
where cl.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: C++ compiler (cl.exe) not found after environment setup!
    echo.
    echo This usually means the "Desktop development with C++" workload is not installed.
    echo.
    echo Please open Visual Studio Installer and:
    echo 1. Select "Modify" on your Visual Studio installation
    echo 2. Check "Desktop development with C++"
    echo 3. Click "Modify" to install the component
    echo.
    pause
    exit /b 1
)

echo Compiler found, proceeding with build...

echo [6/6] Building kernel driver...
cl.exe /c /nologo /W4 /O2 /D "_AMD64_" /D "NDEBUG" /I "%WDK_BASE%\Include\%SDK_VER%\km" /I "%WDK_BASE%\Include\%SDK_VER%\shared" /kernel /Zp8 /GS "%PROJECT_ROOT%real_kernel_driver.c" /Fo"%BUILD_DIR%\real_kernel_driver.obj"

if errorlevel 1 (
    echo ERROR: Kernel driver compilation failed!
    echo.
    echo Please check for errors in the real_kernel_driver.c file.
    echo.
    pause
    exit /b 1
)

echo Linking kernel driver...
link.exe /nologo /DRIVER /NODEFAULTLIB /SUBSYSTEM:NATIVE /MACHINE:X64 /ENTRY:DriverEntry /OUT:"%BUILD_DIR%\AntiRansomwareKernel.sys" /LIBPATH:"%WDK_BASE%\Lib\%SDK_VER%\km\x64" ntoskrnl.lib hal.lib fltmgr.lib wdmsec.lib "%BUILD_DIR%\real_kernel_driver.obj"

if errorlevel 1 (
    echo ERROR: Kernel driver linking failed!
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   BUILD COMPLETED SUCCESSFULLY!
echo ============================================================
echo.
echo Production files created in: %BUILD_DIR%
echo.
echo Files:
echo   - AntiRansomwareKernel.sys - Security Hardened Kernel Driver
echo.
echo NEXT STEPS:
echo   1. Sign the driver with a valid code-signing certificate
echo   2. Enable test signing: bcdedit /set testsigning on
echo   3. Reboot the system
echo   4. Run deploy_production.ps1 to install
echo.
pause