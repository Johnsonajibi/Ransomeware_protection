# PowerShell build script for Anti-Ransomware C++ application
# This script loads Visual Studio environment and builds the application

Write-Host "===============================================" -ForegroundColor Green
Write-Host " BUILDING ANTI-RANSOMWARE C++ APPLICATION" -ForegroundColor Green  
Write-Host "===============================================" -ForegroundColor Green
Write-Host ""

# Check if we're in a VS Developer environment
$vsInstallPath = ""
if (Test-Path "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat") {
    $vsInstallPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
} elseif (Test-Path "C:\Program Files\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat") {
    $vsInstallPath = "C:\Program Files\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"
} elseif (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat") {
    $vsInstallPath = "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"
}

if ($vsInstallPath -eq "") {
    Write-Host "ERROR: Visual Studio not found!" -ForegroundColor Red
    Write-Host "Please install Visual Studio Community 2022 from:" -ForegroundColor Yellow
    Write-Host "https://visualstudio.microsoft.com/downloads/" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Found Visual Studio at: $vsInstallPath" -ForegroundColor Yellow
Write-Host "Setting up build environment..." -ForegroundColor Yellow

# Create a temporary batch file to set up environment and compile
$tempBatch = @"
@echo off
call "$vsInstallPath" >nul 2>&1

echo Building C++ Anti-Ransomware Client...
cl.exe /EHsc /std:c++17 /DUNICODE /D_UNICODE ^
    /I"%WindowsSdkDir%Include\%WindowsSDKVersion%\um" ^
    /I"%WindowsSdkDir%Include\%WindowsSDKVersion%\shared" ^
    antiransomware_client.cpp ^
    /link user32.lib gdi32.lib comctl32.lib shell32.lib kernel32.lib comdlg32.lib ^
    /SUBSYSTEM:WINDOWS ^
    /out:antiransomware_client.exe

if %errorlevel% neq 0 (
    echo ERROR: Build failed
    exit /b 1
) else (
    echo BUILD SUCCESSFUL!
    echo.
    echo Created: antiransomware_client.exe
    echo.
    echo To run:
    echo   antiransomware_client.exe        (GUI mode)
    echo   antiransomware_client.exe --cli  (CLI mode)
    echo.
)
"@

# Write the temporary batch file
$tempBatch | Out-File -FilePath "temp_build.bat" -Encoding ASCII

# Execute the batch file
Write-Host "Compiling C++ application..." -ForegroundColor Yellow
& cmd /c "temp_build.bat"

if ($LASTEXITCODE -eq 0) {
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host " BUILD COMPLETED SUCCESSFULLY!" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    
    if (Test-Path "antiransomware_client.exe") {
        Write-Host ""
        Write-Host "✅ antiransomware_client.exe created successfully" -ForegroundColor Green
        
        # Get file info
        $fileInfo = Get-Item "antiransomware_client.exe"
        Write-Host "📁 Size: $([math]::Round($fileInfo.Length/1KB, 2)) KB" -ForegroundColor Cyan
        Write-Host "📅 Created: $($fileInfo.CreationTime)" -ForegroundColor Cyan
        
        Write-Host ""
        Write-Host "🚀 Ready to run:" -ForegroundColor Yellow
        Write-Host "   .\antiransomware_client.exe        (GUI mode)" -ForegroundColor White
        Write-Host "   .\antiransomware_client.exe --cli  (CLI mode)" -ForegroundColor White
        Write-Host ""
        Write-Host "Note: Application will run in SIMULATION MODE" -ForegroundColor Yellow
        Write-Host "      (no kernel driver required for testing)" -ForegroundColor Yellow
    }
} else {
    Write-Host "===============================================" -ForegroundColor Red
    Write-Host " BUILD FAILED!" -ForegroundColor Red
    Write-Host "===============================================" -ForegroundColor Red
    Write-Host "Check the error messages above for details." -ForegroundColor Yellow
}

# Clean up temporary file
if (Test-Path "temp_build.bat") {
    Remove-Item "temp_build.bat" -Force
}

Write-Host ""
Read-Host "Press Enter to continue"
