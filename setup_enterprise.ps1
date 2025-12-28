# Enterprise Detection Setup Script
# ==================================
# Automates installation and configuration of enterprise-grade detection features

param(
    [switch]$InstallDependencies,
    [switch]$ConfigureSIEM,
    [switch]$SetupThreatIntel,
    [switch]$TestFeatures,
    [switch]$All
)

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Anti-Ransomware Enterprise Detection Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Helper Functions
function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    $color = switch ($Type) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        default { "White" }
    }
    $prefix = switch ($Type) {
        "Success" { "[✓]" }
        "Warning" { "[!]" }
        "Error" { "[✗]" }
        default { "[i]" }
    }
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Test-PythonInstalled {
    try {
        $pythonVersion = python --version 2>&1
        Write-Status "Python found: $pythonVersion" "Success"
        return $true
    }
    catch {
        Write-Status "Python not found. Please install Python 3.8+ first." "Error"
        return $false
    }
}

function Test-VirtualEnv {
    if (Test-Path ".\.venv") {
        Write-Status "Virtual environment found" "Success"
        return $true
    }
    else {
        Write-Status "Virtual environment not found" "Warning"
        return $false
    }
}

# Main Setup Functions
function Install-Dependencies {
    Write-Host "`n[1] Installing Enterprise Dependencies..." -ForegroundColor Yellow
    Write-Host "==========================================" -ForegroundColor Yellow
    
    if (-not (Test-PythonInstalled)) {
        return
    }
    
    if (-not (Test-VirtualEnv)) {
        Write-Status "Creating virtual environment..." "Info"
        python -m venv .venv
    }
    
    Write-Status "Activating virtual environment..." "Info"
    & .\.venv\Scripts\Activate.ps1
    
    Write-Status "Upgrading pip..." "Info"
    python -m pip install --upgrade pip
    
    Write-Status "Installing enterprise requirements..." "Info"
    pip install -r requirements_enterprise.txt
    
    Write-Status "Verifying installations..." "Info"
    $packages = @("scikit-learn", "yara-python", "requests", "numpy", "pandas")
    $allInstalled = $true
    
    foreach ($package in $packages) {
        try {
            pip show $package | Out-Null
            Write-Status "$package installed" "Success"
        }
        catch {
            Write-Status "$package NOT installed" "Error"
            $allInstalled = $false
        }
    }
    
    if ($allInstalled) {
        Write-Status "All enterprise dependencies installed successfully!" "Success"
    }
    else {
        Write-Status "Some packages failed to install. Check errors above." "Warning"
    }
}

function Configure-SIEM {
    Write-Host "`n[2] Configuring SIEM Integration..." -ForegroundColor Yellow
    Write-Host "=====================================" -ForegroundColor Yellow
    
    Write-Host "`nSelect SIEM Platform:" -ForegroundColor Cyan
    Write-Host "1. Splunk Enterprise Security"
    Write-Host "2. IBM QRadar"
    Write-Host "3. ArcSight"
    Write-Host "4. File-based (for testing)"
    Write-Host "5. Skip SIEM configuration"
    
    $choice = Read-Host "`nEnter choice (1-5)"
    
    switch ($choice) {
        "1" {
            Write-Host "`nSplunk Configuration:" -ForegroundColor Cyan
            $splunkUrl = Read-Host "Enter Splunk HEC URL (e.g., https://splunk.company.com:8088/services/collector/raw)"
            $splunkToken = Read-Host "Enter Splunk HEC Token" -AsSecureString
            
            $tokenPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($splunkToken)
            )
            
            $config = Get-Content "enterprise_config_advanced.json" | ConvertFrom-Json
            $config.siem.enabled = $true
            $config.siem.format = "json"
            $config.siem.endpoints[1].enabled = $true
            $config.siem.endpoints[1].url = $splunkUrl
            $config.siem.endpoints[1].headers.Authorization = "Splunk $tokenPlain"
            
            $config | ConvertTo-Json -Depth 10 | Set-Content "enterprise_config_advanced.json"
            Write-Status "Splunk configuration saved" "Success"
        }
        "2" {
            Write-Host "`nQRadar Configuration:" -ForegroundColor Cyan
            $qradarHost = Read-Host "Enter QRadar hostname/IP"
            $qradarPort = Read-Host "Enter QRadar Syslog port (default: 514)"
            if ([string]::IsNullOrEmpty($qradarPort)) { $qradarPort = "514" }
            
            $config = Get-Content "enterprise_config_advanced.json" | ConvertFrom-Json
            $config.siem.enabled = $true
            $config.siem.format = "leef"
            $config.siem.endpoints[2].enabled = $true
            $config.siem.endpoints[2].host = $qradarHost
            $config.siem.endpoints[2].port = [int]$qradarPort
            
            $config | ConvertTo-Json -Depth 10 | Set-Content "enterprise_config_advanced.json"
            Write-Status "QRadar configuration saved" "Success"
        }
        "3" {
            Write-Host "`nArcSight Configuration:" -ForegroundColor Cyan
            $arcsightHost = Read-Host "Enter ArcSight hostname/IP"
            $arcsightPort = Read-Host "Enter ArcSight Syslog port (default: 514)"
            if ([string]::IsNullOrEmpty($arcsightPort)) { $arcsightPort = "514" }
            
            $config = Get-Content "enterprise_config_advanced.json" | ConvertFrom-Json
            $config.siem.enabled = $true
            $config.siem.format = "cef"
            $config.siem.endpoints[3].enabled = $true
            $config.siem.endpoints[3].host = $arcsightHost
            $config.siem.endpoints[3].port = [int]$arcsightPort
            
            $config | ConvertTo-Json -Depth 10 | Set-Content "enterprise_config_advanced.json"
            Write-Status "ArcSight configuration saved" "Success"
        }
        "4" {
            Write-Status "Using file-based SIEM logging (already configured)" "Success"
        }
        default {
            Write-Status "SIEM configuration skipped" "Warning"
        }
    }
}

function Setup-ThreatIntel {
    Write-Host "`n[3] Configuring Threat Intelligence..." -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    
    Write-Host "`nAvailable Threat Intelligence Sources:" -ForegroundColor Cyan
    Write-Host "1. VirusTotal (Free: 4 req/min, Paid: higher limits)"
    Write-Host "2. AbuseIPDB (Free: 1000 req/day)"
    Write-Host "3. AlienVault OTX (Free: unlimited)"
    Write-Host "4. Configure all"
    Write-Host "5. Skip"
    
    $choice = Read-Host "`nEnter choice (1-5)"
    
    switch ($choice) {
        "1" {
            $vtKey = Read-Host "Enter VirusTotal API Key"
            [Environment]::SetEnvironmentVariable("VIRUSTOTAL_API_KEY", $vtKey, "User")
            Write-Status "VirusTotal API key saved to user environment" "Success"
            Write-Status "Note: Restart terminal for changes to take effect" "Warning"
        }
        "2" {
            $aipdbKey = Read-Host "Enter AbuseIPDB API Key"
            [Environment]::SetEnvironmentVariable("ABUSEIPDB_API_KEY", $aipdbKey, "User")
            Write-Status "AbuseIPDB API key saved to user environment" "Success"
        }
        "3" {
            $otxKey = Read-Host "Enter AlienVault OTX API Key"
            [Environment]::SetEnvironmentVariable("OTX_API_KEY", $otxKey, "User")
            Write-Status "AlienVault OTX API key saved to user environment" "Success"
        }
        "4" {
            $vtKey = Read-Host "Enter VirusTotal API Key"
            $aipdbKey = Read-Host "Enter AbuseIPDB API Key"
            $otxKey = Read-Host "Enter AlienVault OTX API Key"
            
            [Environment]::SetEnvironmentVariable("VIRUSTOTAL_API_KEY", $vtKey, "User")
            [Environment]::SetEnvironmentVariable("ABUSEIPDB_API_KEY", $aipdbKey, "User")
            [Environment]::SetEnvironmentVariable("OTX_API_KEY", $otxKey, "User")
            
            Write-Status "All threat intelligence API keys saved" "Success"
            Write-Status "Note: Restart terminal for changes to take effect" "Warning"
        }
        default {
            Write-Status "Threat intelligence configuration skipped" "Warning"
        }
    }
    
    # Display current configuration
    Write-Host "`nCurrent Environment Variables:" -ForegroundColor Cyan
    $vtConfigured = [Environment]::GetEnvironmentVariable("VIRUSTOTAL_API_KEY", "User")
    $aipdbConfigured = [Environment]::GetEnvironmentVariable("ABUSEIPDB_API_KEY", "User")
    $otxConfigured = [Environment]::GetEnvironmentVariable("OTX_API_KEY", "User")
    
    Write-Status "VirusTotal: $(if ($vtConfigured) { 'Configured' } else { 'Not configured' })" $(if ($vtConfigured) { "Success" } else { "Warning" })
    Write-Status "AbuseIPDB: $(if ($aipdbConfigured) { 'Configured' } else { 'Not configured' })" $(if ($aipdbConfigured) { "Success" } else { "Warning" })
    Write-Status "AlienVault OTX: $(if ($otxConfigured) { 'Configured' } else { 'Not configured' })" $(if ($otxConfigured) { "Success" } else { "Warning" })
}

function Test-Features {
    Write-Host "`n[4] Testing Enterprise Features..." -ForegroundColor Yellow
    Write-Host "===================================" -ForegroundColor Yellow
    
    if (-not (Test-VirtualEnv)) {
        Write-Status "Virtual environment not found. Run with -InstallDependencies first." "Error"
        return
    }
    
    Write-Status "Activating virtual environment..." "Info"
    & .\.venv\Scripts\Activate.ps1
    
    Write-Status "Running enterprise detection demo..." "Info"
    Write-Host ""
    python enterprise_detection_advanced.py
    
    Write-Host ""
    Write-Status "Feature test complete!" "Success"
    Write-Status "Check 'siem_events.log' for generated events" "Info"
}

function Show-Summary {
    Write-Host "`n============================================" -ForegroundColor Cyan
    Write-Host "Setup Complete - Summary" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    
    Write-Host "`n✅ What's Configured:" -ForegroundColor Green
    Write-Host "  • Enterprise detection engine"
    Write-Host "  • Machine learning anomaly detection"
    Write-Host "  • YARA signature matching"
    Write-Host "  • MITRE ATT&CK framework mapping"
    Write-Host "  • Multi-source threat intelligence"
    Write-Host "  • SIEM integration (CEF/LEEF/JSON)"
    Write-Host "  • Compliance reporting (SOC2/HIPAA/PCI)"
    
    Write-Host "`n📋 Next Steps:" -ForegroundColor Yellow
    Write-Host "  1. Review configuration: enterprise_config_advanced.json"
    Write-Host "  2. Customize YARA rules in yara_rules/ directory"
    Write-Host "  3. Train ML model with normal behavior data"
    Write-Host "  4. Integrate with main system (see documentation)"
    Write-Host "  5. Set up monitoring dashboard"
    
    Write-Host "`n📚 Documentation:" -ForegroundColor Cyan
    Write-Host "  • Full guide: ENTERPRISE_DETECTION_GUIDE.md"
    Write-Host "  • API reference: See guide for detailed API docs"
    Write-Host "  • Troubleshooting: See guide section"
    
    Write-Host "`n🔧 Management Commands:" -ForegroundColor Magenta
    Write-Host "  • Test features: python enterprise_detection_advanced.py"
    Write-Host "  • View logs: Get-Content logs\enterprise_detection.log -Tail 50"
    Write-Host "  • Check SIEM events: Get-Content logs\siem_events.log -Tail 20"
    
    Write-Host ""
}

# Main Execution
if ($All) {
    Install-Dependencies
    Configure-SIEM
    Setup-ThreatIntel
    Test-Features
    Show-Summary
}
else {
    if ($InstallDependencies) { Install-Dependencies }
    if ($ConfigureSIEM) { Configure-SIEM }
    if ($SetupThreatIntel) { Setup-ThreatIntel }
    if ($TestFeatures) { Test-Features }
    
    if (-not ($InstallDependencies -or $ConfigureSIEM -or $SetupThreatIntel -or $TestFeatures)) {
        Write-Host "Usage: .\setup_enterprise.ps1 [-InstallDependencies] [-ConfigureSIEM] [-SetupThreatIntel] [-TestFeatures] [-All]" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Options:" -ForegroundColor Cyan
        Write-Host "  -InstallDependencies  : Install Python packages"
        Write-Host "  -ConfigureSIEM        : Set up SIEM integration"
        Write-Host "  -SetupThreatIntel     : Configure threat intelligence APIs"
        Write-Host "  -TestFeatures         : Run feature tests"
        Write-Host "  -All                  : Run all setup steps"
        Write-Host ""
        Write-Host "Example: .\setup_enterprise.ps1 -All" -ForegroundColor Green
    }
    else {
        Show-Summary
    }
}
