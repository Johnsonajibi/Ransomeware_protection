@echo off
REM Build Anti-Ransomware Kernel Driver - Working Version

echo ========================================
echo Anti-Ransomware Kernel Driver Build
echo ========================================
echo.

REM Paths
set "VS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207"
set "WDK=C:\Program Files (x86)\Windows Kits\10"
set "VER=10.0.26100.0"

set "CLPATH=%VS%\bin\Hostx64\x64\cl.exe"
set "LINKPATH=%VS%\bin\Hostx64\x64\link.exe"

REM Create output dir
if not exist "build_production" mkdir "build_production"
if not exist "build_production\obj" mkdir "build_production\obj"

echo [1/3] Compiling real_kernel_driver.c...
call "%CLPATH%" /c /kernel /W3 /D _AMD64_ /D AMD64 /D _WIN64 /D WIN32=100 /D _WIN32_WINNT=0x0A00 /D WINVER=0x0A00 /D WINNT=1 /D NTDDI_VERSION=0x0A00000A /D POOL_NX_OPTIN=1 /I "%WDK%\Include\%VER%\km\crt" /I "%WDK%\Include\%VER%\km" /I "%WDK%\Include\%VER%\shared" /Fo"build_production\obj\real_kernel_driver.obj" real_kernel_driver.c

if %ERRORLEVEL% NEQ 0 (
    echo [X] Compilation failed
    exit /b 1
)
echo [OK] Compilation successful
echo.

echo [2/3] Linking AntiRansomwareDriver.sys...
call "%LINKPATH%" /OUT:"build_production\AntiRansomwareDriver.sys" /INCREMENTAL:NO /NOLOGO /VERSION:10.0 /SUBSYSTEM:NATIVE,10.0 /Driver /ENTRY:DriverEntry /OPT:REF /OPT:ICF /MACHINE:X64 /KERNEL /RELEASE /NODEFAULTLIB /LIBPATH:"%VS%\lib\x64" /LIBPATH:"%WDK%\Lib\%VER%\km\x64" fltMgr.lib ntoskrnl.lib hal.lib wdmsec.lib BufferOverflowK.lib build_production\obj\real_kernel_driver.obj

if %ERRORLEVEL% NEQ 0 (
    echo [X] Linking failed
    exit /b 1
)
echo [OK] Linking successful
echo.

echo ========================================
echo BUILD SUCCESSFUL!
echo ========================================
echo.
echo Output: build_production\AntiRansomwareDriver.sys
echo.
echo Next steps:
echo 1. Enable test signing: bcdedit /set testsigning on
echo 2. Install driver: sc create AntiRansomwareDriver type=filesys binPath=...
echo 3. Start driver: sc start AntiRansomwareDriver
echo.
