Write-Host "`n=== C++ Environment Check ===" -ForegroundColor Cyan

$vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community"
$sdkPath = "C:\Program Files (x86)\Windows Kits\10"

# Check Visual Studio
if (Test-Path $vsPath) {
    Write-Host "[OK] Visual Studio 2022 found" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Visual Studio 2022 NOT found" -ForegroundColor Red
}

# Check compiler
$cl = Get-ChildItem "$vsPath\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($cl) {
    Write-Host "[OK] C++ Compiler found: $($cl.DirectoryName)" -ForegroundColor Green
} else {
    Write-Host "[FAIL] C++ Compiler NOT found" -ForegroundColor Red
    $missing = $true
}

# Check C++ Standard Library
$iostream = Get-ChildItem "$vsPath\VC\Tools\MSVC\*\include\iostream" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($iostream) {
    Write-Host "[OK] C++ Standard Library found" -ForegroundColor Green
} else {
    Write-Host "[FAIL] C++ Standard Library NOT found" -ForegroundColor Red
    $missing = $true
}

# Check Windows SDK
if (Test-Path $sdkPath) {
    Write-Host "[OK] Windows SDK found" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Windows SDK NOT found" -ForegroundColor Red
}

Write-Host "`n=== RESULT ===" -ForegroundColor Cyan

if ($missing) {
    Write-Host "C++ components are MISSING!" -ForegroundColor Red
    Write-Host "`nTO FIX:" -ForegroundColor Yellow
    Write-Host "1. Open Visual Studio Installer"
    Write-Host "2. Click Modify"
    Write-Host "3. Enable 'Desktop development with C++'"
    Write-Host "4. Install and restart"
} else {
    Write-Host "Environment is ready to compile!" -ForegroundColor Green
}
