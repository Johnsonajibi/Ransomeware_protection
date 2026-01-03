# Build Anti-Ransomware Kernel Driver - Simplified Direct Compilation
# Uses cl.exe from Visual Studio and WDK libraries directly

$ErrorActionPreference = "Stop"

Write-Host "========================================"  -ForegroundColor Cyan
Write-Host "Anti-Ransomware Kernel Driver Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Paths
$vsPath = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
$wdkPath = "C:\Program Files (x86)\Windows Kits\10"
$wdkVersion = "10.0.26100.0"

$clPath = "$vsPath\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe"
$linkPath = "$vsPath\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe"

# WDK includes and libs
$wdkInclude = "$wdkPath\Include\$wdkVersion"
$wdkLib = "$wdkPath\Lib\$wdkVersion"

# Output
$outputDir = "build_production"
$objDir = "$outputDir\obj"

# Create output directories
if (!(Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }
if (!(Test-Path $objDir)) { New-Item -ItemType Directory -Path $objDir | Out-Null }

Write-Host "[1/3] Compiling real_kernel_driver.c..." -ForegroundColor Yellow

# Compile flags for kernel driver
$compileArgs = @(
    "/c"  # Compile only
    "/Zp8"  # 8-byte struct alignment
    "/Gy"  # Enable function-level linking
    "/W3"  # Warning level 3
    "/Zc:wchar_t"  # wchar_t is native type
    "/Zi"  # Debug info
    "/Gm-"  # Disable minimal rebuild
    "/Od"  # Disable optimizations (use /O2 for production)
    "/Oi"  # Generate intrinsic functions
    "/D", "_X86_=1"
    "/D", "i386=1"
    "/D", "STD_CALL"
    "/D", "DEPRECATE_DDK_FUNCTIONS"
    "/D", "MSC_NOOPT"
    "/D", "WIN32=100"
    "/D", "_WIN32_WINNT=0x0A00"
    "/D", "WINVER=0x0A00"
    "/D", "WINNT=1"
    "/D", "NTDDI_VERSION=0x0A00000A"
    "/D", "KMDF_VERSION_MAJOR=1"
    "/D", "KMDF_VERSION_MINOR=15"
    "/D", "_WIN64"
    "/D", "_AMD64_"
    "/D", "AMD64"
    "/D", "POOL_NX_OPTIN=1"
    "/GF"  # Enable string pooling
    "/GS"  # Buffer security check
    "/kernel"  # Kernel mode
    "/Fo$objDir\real_kernel_driver.obj"  # Output object file
    "/I", "$wdkInclude\km\crt"
    "/I", "$wdkInclude\km"
    "/I", "$wdkInclude\shared"
    "real_kernel_driver.c"
)

try {
    $output = & $clPath $compileArgs 2>&1
    $output | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "Compilation failed with exit code $LASTEXITCODE"
    }
    Write-Host "[✓] Compilation successful" -ForegroundColor Green
} catch {
    Write-Host "[✗] Compilation failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[2/3] Linking AntiRansomwareDriver.sys..." -ForegroundColor Yellow

# Link flags for kernel driver
$linkArgs = @(
    "/OUT:$outputDir\AntiRansomwareDriver.sys"
    "/INCREMENTAL:NO"
    "/NOLOGO"
    "/VERSION:10.0"
    "/SUBSYSTEM:NATIVE,10.0"
    "/Driver"
    "/ENTRY:DriverEntry"
    "/OPT:REF"
    "/OPT:ICF"
    "/MACHINE:X64"
    "/KERNEL"
    "/RELEASE"
    "/LIBPATH:$wdkLib\km\x64"
    "fltMgr.lib"
    "ntoskrnl.lib"
    "hal.lib"
    "wdmsec.lib"
    "BufferOverflowK.lib"
    "$objDir\real_kernel_driver.obj"
)

try {
    & $linkPath $linkArgs 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Linking failed with exit code $LASTEXITCODE"
    }
    Write-Host "[✓] Linking successful" -ForegroundColor Green
} catch {
    Write-Host "[✗] Linking failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "BUILD SUCCESSFUL!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output: $outputDir\AntiRansomwareDriver.sys" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Sign the driver with test certificate (bcdedit /set testsigning on)"
Write-Host "2. Install the driver using sc create or .inf file"
Write-Host "3. Start the driver with sc start AntiRansomwareDriver"
Write-Host ""
