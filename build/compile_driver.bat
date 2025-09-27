@echo off 
REM This script compiles the kernel driver with WDK 
REM Must be run from WDK build environment 
 
set WDK_ROOT=C:\Program Files (x86)\Windows Kits\10 
set WDK_VERSION=10.0.26100.0 
 
REM Set up WDK environment 
call "%WDK_ROOT%\bin\%WDK_VERSION%\x64\setenv.bat" /x64 /win10 /release 
 
REM Compile driver 
build -cZ 
 
if exist objfre_win10_amd64\amd64\RealAntiRansomwareDriver.sys ( 
    copy objfre_win10_amd64\amd64\RealAntiRansomwareDriver.sys . 
    echo ✅ Driver compiled successfully! 
) else ( 
    echo ❌ Driver compilation failed 
) 
