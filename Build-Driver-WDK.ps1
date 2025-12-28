#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Build kernel driver using WDK command-line tools
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   KERNEL DRIVER BUILD (WDK CLI)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$ProjectRoot = $PSScriptRoot
$DriverSource = Join-Path $ProjectRoot "real_kernel_driver.c"
$BuildDir = Join-Path $ProjectRoot "build_production"
$OutputSys = Join-Path $BuildDir "AntiRansomwareKernel.sys"

# Clean and create build directory
Write-Host "[1/5] Preparing build directory..." -ForegroundColor Yellow
if (Test-Path $BuildDir) {
    Remove-Item $BuildDir -Recurse -Force
}
New-Item -ItemType Directory -Path $BuildDir | Out-Null
$ObjDir = Join-Path $BuildDir "obj"
New-Item -ItemType Directory -Path $ObjDir | Out-Null
Write-Host "    Ready" -ForegroundColor Green

# Find WDK
Write-Host "[2/5] Locating WDK..." -ForegroundColor Yellow
$wdkPath = "C:\Program Files (x86)\Windows Kits\10"
$sdkVersion = "10.0.26100.0"

if (-not (Test-Path "$wdkPath\Include\$sdkVersion\km")) {
    throw "WDK not found at: $wdkPath"
}
Write-Host "    Found: $sdkVersion" -ForegroundColor Green

# Setup WDK build environment
Write-Host "[3/5] Initializing WDK environment..." -ForegroundColor Yellow

# Find compiler (from Build Tools)
$vsPath = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
$vcToolsPath = Get-ChildItem "$vsPath\VC\Tools\MSVC" | Sort-Object Name -Descending | Select-Object -First 1
if (-not $vcToolsPath) {
    throw "VC compiler tools not found"
}

$compilerPath = Join-Path $vcToolsPath.FullName "bin\Hostx64\x64"
$env:PATH = "$compilerPath;$wdkPath\bin\$sdkVersion\x64;$env:PATH"

# Find Universal CRT
$ucrtVersion = Get-ChildItem "$wdkPath\Include" -Directory | Where-Object { $_.Name -match '^\d+\.' } | Sort-Object Name -Descending | Select-Object -First 1
$ucrtInclude = "$wdkPath\Include\$($ucrtVersion.Name)\ucrt"
$ucrtLib = "$wdkPath\Lib\$($ucrtVersion.Name)\ucrt\x64"

# Setup INCLUDE paths - VC includes and UCRT MUST come BEFORE WDK includes
$env:INCLUDE = "$($vcToolsPath.FullName)\include;$ucrtInclude;$wdkPath\Include\$sdkVersion\km;$wdkPath\Include\$sdkVersion\shared;$wdkPath\Include\$sdkVersion\um"
$env:LIB = "$($vcToolsPath.FullName)\lib\x64;$ucrtLib;$wdkPath\Lib\$sdkVersion\km\x64"
$env:LIBPATH = "$($vcToolsPath.FullName)\lib\x64;$wdkPath\Lib\$sdkVersion\km\x64"

Write-Host "    Compiler: $compilerPath" -ForegroundColor Green

# Compile
Write-Host "[4/5] Compiling driver..." -ForegroundColor Yellow
$objFile = Join-Path $ObjDir "real_kernel_driver.obj"

$compileCmd = "cl.exe"
$compileArgs = @(
    "/c"
    "/nologo"
    "/W3"
    "/WX-"
    "/O2"
    "/Oi"
    "/D", "_WIN64"
    "/D", "_AMD64_"
    "/D", "AMD64"
    "/D", "_WINDOWS"
    "/D", "STD_CALL"
    "/D", "DEPRECATE_DDK_FUNCTIONS=1"
    "/D", "MSC_NOOPT"
    "/D", "_WIN32_WINNT=0x0A00"
    "/D", "WINVER=0x0A00"
    "/D", "WINNT=1"
    "/D", "NTDDI_VERSION=0x0A000000"
    "/D", "KMDF_VERSION_MAJOR=1"
    "/D", "KMDF_VERSION_MINOR=31"
    "/Zp8"
    "/Gy"
    "/Gm-"
    "/Zc:wchar_t-"
    "/Zc:inline"
    "/fp:precise"
    "/errorReport:prompt"
    "/GF"
    "/GS"
    "/Gs32768"
    "/kernel"
    "/GR-"
    "/analyze-"
    "/Fo$objFile"
    "/Fd$ObjDir\"
    "/wd4603"
    "/wd4627"
    "/wd4986"
    "/wd4987"
    "/wd4996"
    $DriverSource
)

$process = Start-Process -FilePath $compileCmd -ArgumentList $compileArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$BuildDir\compile.log" -RedirectStandardError "$BuildDir\compile_err.log"

if ($process.ExitCode -ne 0) {
    Write-Host ""
    Write-Host "Compile output:" -ForegroundColor Red
    Get-Content "$BuildDir\compile.log" -ErrorAction SilentlyContinue
    Get-Content "$BuildDir\compile_err.log" -ErrorAction SilentlyContinue
    throw "Compilation failed with exit code: $($process.ExitCode)"
}

if (-not (Test-Path $objFile)) {
    throw "Object file not created"
}
Write-Host "    Compilation successful" -ForegroundColor Green

# Link
Write-Host "[5/5] Linking driver..." -ForegroundColor Yellow

$linkCmd = "link.exe"
$linkArgs = @(
    "/DRIVER"
    "/SUBSYSTEM:NATIVE"
    "/NOLOGO"
    "/INCREMENTAL:NO"
    "/NODEFAULTLIB"
    "/ENTRY:DriverEntry"
    "/OUT:$OutputSys"
    "/MACHINE:X64"
    "/MERGE:.edata=.data"
    "/MERGE:.rdata=.data"
    "/SECTION:INIT,d"
    "/RELEASE"
    "/FORCE:MULTIPLE"
    "/IGNORE:4001,4037,4039,4065,4070,4078,4087,4089,4221,4108,4088,4218,4218,4235"
    "/OPT:REF"
    "/OPT:ICF"
    "/PDBALTPATH:%_PDB%"
    "ntoskrnl.lib"
    "hal.lib"
    "fltmgr.lib"
    "wdmsec.lib"
    "BufferOverflowK.lib"
    $objFile
)

$process = Start-Process -FilePath $linkCmd -ArgumentList $linkArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$BuildDir\link.log" -RedirectStandardError "$BuildDir\link_err.log"

if ($process.ExitCode -ne 0) {
    Write-Host ""
    Write-Host "Link output:" -ForegroundColor Red
    Get-Content "$BuildDir\link.log" -ErrorAction SilentlyContinue
    Get-Content "$BuildDir\link_err.log" -ErrorAction SilentlyContinue
    throw "Linking failed with exit code: $($process.ExitCode)"
}

if (-not (Test-Path $OutputSys)) {
    throw "Driver file not created"
}

$info = Get-Item $OutputSys
Write-Host "    Driver: $($info.Name)" -ForegroundColor Green
Write-Host "    Size: $([math]::Round($info.Length / 1KB, 2)) KB" -ForegroundColor Green
Write-Host ""

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "   BUILD SUCCESSFUL!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Output: $OutputSys" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. bcdedit /set testsigning on" -ForegroundColor White
Write-Host "  2. Reboot" -ForegroundColor White
Write-Host "  3. Sign the driver" -ForegroundColor White
Write-Host "  4. Install and load" -ForegroundColor White
