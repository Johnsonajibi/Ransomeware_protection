#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Build Anti-Ransomware Kernel Driver for Windows
.DESCRIPTION
    Compiles the Windows minifilter driver using VS 2022 and WDK
#>

param(
    [switch]$Clean = $false
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ANTI-RANSOMWARE KERNEL DRIVER BUILD" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $ProjectRoot "build_production"
$DriverSource = Join-Path $ProjectRoot "real_kernel_driver.c"
$InfFile = Join-Path $ProjectRoot "anti_ransomware_minifilter.inf"
$OutputSys = Join-Path $BuildDir "AntiRansomwareKernel.sys"

# Find Visual Studio
Write-Host "[1/7] Locating Visual Studio 2022..." -ForegroundColor Yellow
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vsWhere)) {
    throw "vswhere.exe not found. Please install Visual Studio 2022."
}

$vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    throw "Visual Studio 2022 with C++ tools not found. Please install Desktop development with C++ workload."
}
Write-Host "    Found: $vsPath" -ForegroundColor Green

# Find WDK
Write-Host "[2/7] Locating Windows Driver Kit..." -ForegroundColor Yellow
$wdkBasePath = "C:\Program Files (x86)\Windows Kits\10"
if (-not (Test-Path $wdkBasePath)) {
    throw "Windows Driver Kit not found at: $wdkBasePath"
}

# Detect installed SDK version
$sdkVersions = Get-ChildItem "$wdkBasePath\Include" -Directory | 
    Where-Object { $_.Name -match '^\d+\.' } | 
    Sort-Object Name -Descending

if ($sdkVersions.Count -eq 0) {
    throw "No Windows SDK versions found in WDK"
}

$sdkVersion = $sdkVersions[0].Name
Write-Host "    Found WDK with SDK version: $sdkVersion" -ForegroundColor Green

# Setup paths
$wdkInclude = "$wdkBasePath\Include\$sdkVersion"
$wdkLib = "$wdkBasePath\Lib\$sdkVersion"

# Verify critical paths exist
$pathsToCheck = @(
    "$wdkInclude\km",
    "$wdkInclude\shared",
    "$wdkLib\km\x64"
)

foreach ($path in $pathsToCheck) {
    if (-not (Test-Path $path)) {
        throw "Required WDK path not found: $path"
    }
}

# Clean if requested
if ($Clean -and (Test-Path $BuildDir)) {
    Write-Host "[3/7] Cleaning build directory..." -ForegroundColor Yellow
    Remove-Item $BuildDir -Recurse -Force
    Write-Host "    Cleaned" -ForegroundColor Green
}

# Create build directory
Write-Host "[3/7] Creating build directory..." -ForegroundColor Yellow
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}
Write-Host "    Ready: $BuildDir" -ForegroundColor Green

# Setup build environment
Write-Host "[4/7] Initializing build environment..." -ForegroundColor Yellow
$vcVarsAll = "$vsPath\VC\Auxiliary\Build\vcvarsall.bat"
if (-not (Test-Path $vcVarsAll)) {
    throw "vcvarsall.bat not found at: $vcVarsAll"
}

# Import VS environment variables using proper cmd invocation
$tempBat = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.bat'
$tempOut = [System.IO.Path]::GetTempFileName()
@"
@echo off
call "$vcVarsAll" x64 >nul 2>&1
if errorlevel 1 exit /b 1
set > "$tempOut"
"@ | Set-Content $tempBat

$result = & cmd.exe /c "`"$tempBat`""
if ($LASTEXITCODE -ne 0) {
    throw "Failed to initialize Visual Studio build environment"
}

# Import environment variables
if (Test-Path $tempOut) {
    Get-Content $tempOut | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            $name = $matches[1]
            $value = $matches[2]
            if ($name -notin @('PROMPT', 'TEMP', 'TMP')) {
                [Environment]::SetEnvironmentVariable($name, $value, 'Process')
            }
        }
    }
    Remove-Item $tempOut -ErrorAction SilentlyContinue
}
Remove-Item $tempBat -ErrorAction SilentlyContinue
Write-Host "    Environment initialized" -ForegroundColor Green

# Compile
Write-Host "[5/7] Compiling kernel driver..." -ForegroundColor Yellow
$objFile = Join-Path $BuildDir "real_kernel_driver.obj"

$compileArgs = @(
    "/c"
    "/nologo"
    "/W4"
    "/WX-"
    "/O2"
    "/Oi"
    "/GL"
    "/D", "WIN32"
    "/D", "NDEBUG"
    "/D", "_WINDOWS"
    "/D", "_WIN64"
    "/D", "_AMD64_"
    "/D", "AMD64"
    "/D", "_X86_=0"
    "/D", "_AMD64_=100"
    "/D", "_M_AMD64=100"
    "/Gm-"
    "/EHsc"
    "/MD"
    "/GS"
    "/Gy"
    "/fp:precise"
    "/Zc:wchar_t"
    "/Zc:forScope"
    "/Zc:inline"
    "/GR-"
    "/Fo$objFile"
    "/Fd$BuildDir\\"
    "/Gd"
    "/TC"
    "/kernel"
    "/I$wdkInclude\km"
    "/I$wdkInclude\shared"
    "/I$wdkInclude\um"
    $DriverSource
)

& cl.exe $compileArgs 2>&1 | Tee-Object -Variable compileOutput | Out-Host
if ($LASTEXITCODE -ne 0) {
    Write-Host "    COMPILATION FAILED!" -ForegroundColor Red
    throw "Compilation failed with exit code: $LASTEXITCODE"
}
Write-Host "    Compilation successful" -ForegroundColor Green

# Link
Write-Host "[6/7] Linking driver..." -ForegroundColor Yellow

$linkArgs = @(
    "/nologo"
    "/DRIVER"
    "/SUBSYSTEM:NATIVE"
    "/ENTRY:DriverEntry"
    "/OUT:$OutputSys"
    "/LIBPATH:$wdkLib\km\x64"
    "ntoskrnl.lib"
    "hal.lib"
    "fltmgr.lib"
    "wdmsec.lib"
    "/LTCG"
    "/DYNAMICBASE"
    "/NXCOMPAT"
    "/MACHINE:X64"
    $objFile
)

& link.exe $linkArgs 2>&1 | Tee-Object -Variable linkOutput | Out-Host
if ($LASTEXITCODE -ne 0) {
    Write-Host "    LINKING FAILED!" -ForegroundColor Red
    throw "Linking failed with exit code: $LASTEXITCODE"
}
Write-Host "    Linking successful" -ForegroundColor Green

# Verify output
Write-Host "[7/7] Verifying output..." -ForegroundColor Yellow
if (-not (Test-Path $OutputSys)) {
    throw "Driver file was not created: $OutputSys"
}

$sysInfo = Get-Item $OutputSys
Write-Host "    Driver created: $($sysInfo.Name)" -ForegroundColor Green
Write-Host "    Size: $([math]::Round($sysInfo.Length / 1KB, 2)) KB" -ForegroundColor Green
Write-Host ""

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "   BUILD SUCCESSFUL!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Driver location: $OutputSys" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Enable test signing: bcdedit /set testsigning on" -ForegroundColor White
Write-Host "  2. Create self-signed certificate" -ForegroundColor White
Write-Host "  3. Sign the driver" -ForegroundColor White
Write-Host "  4. Install with: pnputil /add-driver anti_ransomware_minifilter.inf /install" -ForegroundColor White
Write-Host "  5. Load with: fltmc load AntiRansomwareKernel" -ForegroundColor White
Write-Host ""
