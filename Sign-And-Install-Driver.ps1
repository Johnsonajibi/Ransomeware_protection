#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Sign and install the Anti-Ransomware kernel driver
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   KERNEL DRIVER SIGNING & INSTALLATION" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$ProjectRoot = $PSScriptRoot
$DriverSys = Join-Path $ProjectRoot "build_production\AntiRansomwareKernel.sys"
$InfFile = Join-Path $ProjectRoot "anti_ransomware_minifilter.inf"
$CertName = "AntiRansomwareTestCert"

# Verify driver exists
if (-not (Test-Path $DriverSys)) {
    throw "Driver not found: $DriverSys. Please build the driver first."
}

# Step 1: Check if test signing is enabled
Write-Host "[1/6] Checking test signing mode..." -ForegroundColor Yellow
$testSigningEnabled = (bcdedit /enum | Select-String "testsigning.*Yes") -ne $null

if (-not $testSigningEnabled) {
    Write-Host "    Test signing is DISABLED" -ForegroundColor Red
    Write-Host ""
    Write-Host "Enabling test signing requires a reboot." -ForegroundColor Yellow
    $response = Read-Host "Enable test signing now? (Y/N)"
    
    if ($response -eq "Y" -or $response -eq "y") {
        bcdedit /set testsigning on
        Write-Host ""
        Write-Host "Test signing enabled. REBOOT REQUIRED!" -ForegroundColor Green
        Write-Host "After rebooting, run this script again to continue." -ForegroundColor Yellow
        Write-Host ""
        $rebootNow = Read-Host "Reboot now? (Y/N)"
        if ($rebootNow -eq "Y" -or $rebootNow -eq "y") {
            Restart-Computer -Force
        }
        exit 0
    } else {
        throw "Test signing must be enabled to install the driver"
    }
}
Write-Host "    Test signing is enabled" -ForegroundColor Green

# Step 2: Create self-signed certificate
Write-Host "[2/6] Creating self-signed certificate..." -ForegroundColor Yellow
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -match $CertName } | Select-Object -First 1

if (-not $cert) {
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=$CertName" `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddYears(5)
    
    # Export to Trusted Root and Trusted Publishers
    $certPath = "Cert:\CurrentUser\My\$($cert.Thumbprint)"
    Export-Certificate -Cert $certPath -FilePath "$ProjectRoot\AntiRansomwareCert.cer" | Out-Null
    
    Import-Certificate -FilePath "$ProjectRoot\AntiRansomwareCert.cer" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath "$ProjectRoot\AntiRansomwareCert.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    
    Write-Host "    Certificate created and installed" -ForegroundColor Green
} else {
    Write-Host "    Certificate already exists" -ForegroundColor Green
}

# Step 3: Sign the driver
Write-Host "[3/6] Signing driver..." -ForegroundColor Yellow
$signToolPath = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"

if (-not (Test-Path $signToolPath)) {
    throw "SignTool not found at: $signToolPath"
}

& $signToolPath sign /v /s My /n $CertName /t http://timestamp.digicert.com /fd SHA256 $DriverSys 2>&1 | Out-Host

if ($LASTEXITCODE -ne 0) {
    Write-Host "    Signing failed, trying without timestamp..." -ForegroundColor Yellow
    & $signToolPath sign /v /s My /n $CertName /fd SHA256 $DriverSys 2>&1 | Out-Host
}

# Verify signature
& $signToolPath verify /v /pa $DriverSys 2>&1 | Out-Host
if ($LASTEXITCODE -eq 0) {
    Write-Host "    Driver signed successfully" -ForegroundColor Green
} else {
    Write-Host "    Warning: Signature verification failed (may still work with test signing)" -ForegroundColor Yellow
}

# Step 4: Copy driver to system
Write-Host "[4/6] Installing driver..." -ForegroundColor Yellow
$systemDriversPath = "C:\Windows\System32\drivers"
$targetSys = Join-Path $systemDriversPath "AntiRansomwareKernel.sys"

Copy-Item $DriverSys $targetSys -Force
Write-Host "    Driver copied to: $targetSys" -ForegroundColor Green

# Step 5: Install .inf file
Write-Host "[5/6] Installing INF..." -ForegroundColor Yellow
if (Test-Path $InfFile) {
    pnputil /add-driver $InfFile /install 2>&1 | Out-Host
    Write-Host "    INF installed" -ForegroundColor Green
} else {
    Write-Host "    Warning: INF file not found, skipping" -ForegroundColor Yellow
}

# Step 6: Load the minifilter
Write-Host "[6/6] Loading minifilter driver..." -ForegroundColor Yellow
try {
    fltmc load AntiRansomwareKernel 2>&1 | Out-Host
    Start-Sleep -Seconds 2
    
    # Verify it's loaded
    $loaded = fltmc filters | Select-String "AntiRansomwareKernel"
    if ($loaded) {
        Write-Host "    Driver loaded successfully!" -ForegroundColor Green
    } else {
        Write-Host "    Driver may not have loaded. Check Event Viewer for errors." -ForegroundColor Yellow
    }
} catch {
    Write-Host "    Warning: Failed to load driver: $_" -ForegroundColor Yellow
    Write-Host "    You may need to create a service manually or check Event Viewer" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "   INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Driver status:" -ForegroundColor Cyan
fltmc filters | Select-String "AntiRansomwareKernel" -Context 0,1
Write-Host ""
Write-Host "To unload: fltmc unload AntiRansomwareKernel" -ForegroundColor Yellow
Write-Host "To reload: fltmc load AntiRansomwareKernel" -ForegroundColor Yellow
