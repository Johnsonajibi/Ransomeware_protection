@echo off
REM Build Anti-Ransomware Kernel Driver using MSBuild with proper WDK environment

echo ========================================
echo Building Anti-Ransomware Kernel Driver
echo ========================================

REM Set WDK paths
set "WDKPath=C:\Program Files (x86)\Windows Kits\10"
set "WDKVersion=10.0.26100.0"
set "VSPath=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"

REM Set environment for kernel driver builds
set "WindowsSdkDir=%WDKPath%\"
set "WindowsSDKVersion=%WDKVersion%\"
set "WindowsSdkVerBinPath=%WDKPath%\bin\%WDKVersion%\"
set "WindowsSdkBinPath=%WDKPath%\bin\"

REM Add build tools to PATH
set "PATH=%VSPath%\MSBuild\Current\Bin;%WDKPath%\bin\%WDKVersion%\x64;%PATH%"

REM Build using MSBuild
echo.
echo Building with MSBuild...
"%VSPath%\MSBuild\Current\Bin\MSBuild.exe" AntiRansomwareDriver.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:WindowsTargetPlatformVersion=%WDKVersion% ^
    /v:minimal

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Build successful!
    echo ========================================
    echo Output: build_production\AntiRansomwareDriver.sys
    echo.
) else (
    echo.
    echo ========================================
    echo Build failed with error code %ERRORLEVEL%
    echo ========================================
    echo.
    exit /b %ERRORLEVEL%
)
