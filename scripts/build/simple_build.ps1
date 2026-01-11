# Simple PowerShell script to build C++ application
Write-Host "===============================================" -ForegroundColor Green
Write-Host " BUILDING C++ ANTI-RANSOMWARE APPLICATION" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green

# Find Visual Studio
$vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
if (-not (Test-Path $vsPath)) {
    $vsPath = "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
}

if (-not (Test-Path $vsPath)) {
    Write-Host "❌ Visual Studio 2022 not found!" -ForegroundColor Red
    Write-Host "Please install Visual Studio Community 2022" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ Found Visual Studio" -ForegroundColor Green

# Create build script
$script = @"
@echo off
call "$vsPath" -arch=x64 >nul 2>&1
echo Building C++ application...
cl.exe /EHsc /std:c++17 /DUNICODE /D_UNICODE antiransomware_client.cpp /link user32.lib gdi32.lib comctl32.lib shell32.lib kernel32.lib comdlg32.lib /SUBSYSTEM:WINDOWS /out:antiransomware_client.exe
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
) else (
    echo BUILD SUCCESS
    echo Created: antiransomware_client.exe
)
"@

$script | Out-File -FilePath "simple_build.bat" -Encoding ASCII

Write-Host "🔨 Compiling..." -ForegroundColor Yellow
$result = cmd /c "simple_build.bat"
Write-Host $result

Remove-Item "simple_build.bat" -Force -ErrorAction SilentlyContinue

if (Test-Path "antiransomware_client.exe") {
    Write-Host "🎉 SUCCESS!" -ForegroundColor Green
    Write-Host "Run with: .\antiransomware_client.exe" -ForegroundColor White
} else {
    Write-Host "❌ Failed to create executable" -ForegroundColor Red
}

Read-Host "Press Enter to continue"
