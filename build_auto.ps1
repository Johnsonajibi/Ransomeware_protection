# PowerShell script to build C++ application with Visual Studio environment
# This automatically loads the Visual Studio build environment

Write-Host "===============================================" -ForegroundColor Green
Write-Host " AUTO-BUILDING C++ ANTI-RANSOMWARE APP" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green
Write-Host ""

# Find Visual Studio installation
$vsPath = $null
$vsPaths = @(
    "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
)

foreach ($path in $vsPaths) {
    if (Test-Path $path) {
        $vsPath = $path
        break
    }
}

if (-not $vsPath) {
    Write-Host "❌ ERROR: Visual Studio 2022 not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Visual Studio 2022:" -ForegroundColor Yellow
    Write-Host "1. Go to: https://visualstudio.microsoft.com/downloads/" -ForegroundColor White
    Write-Host "2. Download 'Visual Studio Community 2022' (free)" -ForegroundColor White
    Write-Host "3. During install, select 'Desktop development with C++'" -ForegroundColor White
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ Found Visual Studio at: $vsPath" -ForegroundColor Green
Write-Host ""

# Create a temporary batch file that sets up VS environment and compiles
$buildScript = @"
@echo off
echo Setting up Visual Studio 2022 build environment...
call "$vsPath" -arch=x64 -host_arch=x64 >nul 2>&1

if errorlevel 1 (
    echo ❌ Failed to initialize Visual Studio environment
    exit /b 1
)

echo ✅ Visual Studio environment loaded
echo ""
echo 🔨 Compiling Anti-Ransomware Client...
echo ""

cl.exe /EHsc /std:c++17 /DUNICODE /D_UNICODE /W3 /O2 ^
    antiransomware_client.cpp ^
    /link user32.lib gdi32.lib comctl32.lib shell32.lib kernel32.lib comdlg32.lib ^
    /SUBSYSTEM:WINDOWS ^
    /out:antiransomware_client.exe

if errorlevel 1 (
    echo ""
    echo ❌ BUILD FAILED!
    echo ""
    echo Common issues:
    echo - Missing Windows SDK
    echo - C++ build tools not installed
    echo - Source code errors
    echo ""
    echo To fix: Open Visual Studio Installer and ensure these are installed:
    echo - Desktop development with C++
    echo - Windows 11 SDK ^(latest^)
    echo - MSVC v143 build tools
    echo ""
    exit /b 1
)

echo ""
echo ===============================================
echo  ✅ BUILD SUCCESSFUL!
echo ===============================================
echo ""

if exist antiransomware_client.exe (
    for %%A in (antiransomware_client.exe) do (
        echo 📁 File: antiransomware_client.exe
        echo 📏 Size: %%~zA bytes
        echo 📅 Created: %%~tA
    )
    echo ""
    echo 🚀 Ready to run:
    echo    antiransomware_client.exe        ^(GUI mode^)
    echo    antiransomware_client.exe --cli  ^(CLI mode^)
    echo ""
    echo 💡 Note: App will run in SIMULATION MODE without kernel driver
    echo    All features available for testing purposes.
) else (
    echo ❌ Error: antiransomware_client.exe was not created
)
"@

# Write and execute the build script
$buildScript | Out-File -FilePath "auto_build.bat" -Encoding ASCII

Write-Host "🔨 Starting compilation..." -ForegroundColor Yellow
Write-Host ""

# Execute the build
$result = Start-Process -FilePath "auto_build.bat" -Wait -PassThru -NoNewWindow

# Clean up
Remove-Item "auto_build.bat" -Force -ErrorAction SilentlyContinue

if ($result.ExitCode -eq 0) {
    Write-Host ""
    Write-Host "🎉 SUCCESS! C++ application built successfully!" -ForegroundColor Green
    Write-Host ""
    
    if (Test-Path "antiransomware_client.exe") {
        $fileInfo = Get-Item "antiransomware_client.exe"
        Write-Host "📊 Build Information:" -ForegroundColor Cyan
        Write-Host "   File: antiransomware_client.exe" -ForegroundColor White
        Write-Host "   Size: $([math]::Round($fileInfo.Length/1KB, 2)) KB" -ForegroundColor White
        Write-Host "   Created: $($fileInfo.CreationTime)" -ForegroundColor White
        Write-Host ""
        
        Write-Host "🏃 To run the application:" -ForegroundColor Yellow
        Write-Host "   .\antiransomware_client.exe        # GUI mode" -ForegroundColor White
        Write-Host "   .\antiransomware_client.exe --cli  # CLI mode" -ForegroundColor White
        Write-Host ""
        
        $run = Read-Host "Would you like to run the GUI version now? (y/n)"
        if ($run -eq 'y' -or $run -eq 'Y') {
            Write-Host "🚀 Launching Anti-Ransomware GUI..." -ForegroundColor Green
            Start-Process ".\antiransomware_client.exe"
        }
    }
} else {
    Write-Host ""
    Write-Host "❌ BUILD FAILED!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Possible solutions:" -ForegroundColor Yellow
    Write-Host "1. Run as Administrator" -ForegroundColor White
    Write-Host "2. Install Visual Studio C++ components" -ForegroundColor White
    Write-Host "3. Check Windows SDK installation" -ForegroundColor White
    Write-Host ""
    Write-Host "For now, use the Python version:" -ForegroundColor Cyan
    Write-Host "   python unified_antiransomware.py --gui" -ForegroundColor White
}

Write-Host ""
Read-Host "Press Enter to continue"
