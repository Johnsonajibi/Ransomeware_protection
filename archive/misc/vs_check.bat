@echo off
echo.
echo ============================================================
echo   Visual Studio Installation Diagnostic
echo ============================================================
echo.

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if not exist "%VSWHERE%" (
    echo [ERROR] vswhere.exe not found. Visual Studio Installer is missing or corrupt.
    goto :end
)

echo --- 1. Checking for the specific C++ component required by the build script ---
echo Running: "%VSWHERE%" -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
"%VSWHERE%" -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
echo.
echo --- 2. Listing all installed workloads ---
echo Running: "%VSWHERE%" -latest -property "products"
"%VSWHERE%" -latest -products * -property "displayName"
echo.
echo --- 3. Listing all installed components (this might be long) ---
echo Running: "%VSWHERE%" -latest -property "components"
"%VSWHERE%" -latest -products * -property "id"
echo.
echo ============================================================
echo   Diagnostic Complete.
echo ============================================================
echo.
:end
pause