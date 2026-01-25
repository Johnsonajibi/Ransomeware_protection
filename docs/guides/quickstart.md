---
layout: default
title: Quick Start Guide
---

# Quick Start Guide

Get the Anti-Ransomware platform running in 10 minutes.

---

## System Requirements

- **OS:** Windows 10 (Build 19041+) or Windows 11
- **RAM:** 2 GB minimum (4 GB recommended)
- **Disk:** 500 MB free space
- **Hardware:** TPM 2.0 (recommended, fallback available)
- **Admin Rights:** Required for installation

---

## Installation

### Step 1: Clone Repository

```bash
git clone https://github.com/johnsonajibi/Ransomeware_protection
cd Ransomeware_protection
```

### Step 2: Install Dependencies

```bash
# Python dependencies
pip install -r requirements.txt

# On Windows, you may need to install additional components:
# - Windows SDK (for WDK driver building)
# - Visual Studio 2022 Community (with C++ workload)
```

### Step 3: Build Components

**Build the kernel driver:**
```bash
.\build_production.bat
```

**Or use the production build script:**
```powershell
.\Build-Driver-Final.bat
```

Wait for the build to complete. You should see:
```
[SUCCESS] Driver compiled successfully
[SUCCESS] All components built
```

### Step 4: Install Driver

```powershell
# Run as Administrator
$AdminPrivilege = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if ($AdminPrivilege.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    sc create AntiRansomware binPath= "C:\Program Files\AntiRansomware\driver.sys"
    sc start AntiRansomware
} else {
    Write-Host "Please run as Administrator"
}
```

### Step 5: Start Admin Dashboard

```bash
python admin_dashboard.py
```

Open browser to: `http://localhost:5000`

---

## Basic Configuration

### Configure Protected Paths

```bash
# Protect user documents
python add_files_to_protected.py \
  --path "C:\Users\YourUser\Documents" \
  --protect

# Protect critical directories
python add_files_to_protected.py \
  --path "C:\ProgramData" \
  --protect \
  --allow-read \
  --block-write
```

### Create a Token

```bash
# Generate a token for your process
python ar_token.py generate \
  --process "notepad.exe" \
  --path "C:\Users\YourUser\Documents\*" \
  --operations "read,write" \
  --expiry 3600  # 1 hour

# Output:
# Token: eyJ...base64...ZQ==
# Save this token and use it in your application
```

### Enable Protection

```bash
# Activate protection
python activate_protection_logging.py --enable

# Check status
python check_security_events.py --status
```

---

## Verify Installation

### Check Driver Status

```powershell
# Verify driver is loaded
Get-Service AntiRansomware | Select-Object Status, DisplayName

# Expected output:
# Status Name
# ------ ----
# Running AntiRansomware
```

### Test Token Validation

```bash
python simple_token_test.py
```

Expected output:
```
[✓] Hardware Fingerprint: a1b2c3d4...
[✓] Token Generated Successfully
[✓] Token validation: PASSED
[✓] All tests completed successfully
```

### View Security Events

```bash
python check_security_events.py --recent 10
```

---

## First Run Walkthrough

### 1. Initialize Baselines

The system learns your normal usage patterns during the first 24 hours:

```bash
# Start baseline collection (runs automatically)
# - Monitors all file operations
# - Records normal access patterns
# - Builds behavioral profiles
```

During this period, protection is in "MONITOR" mode (alerts but doesn't block).

### 2. Configure Protection Policies

Create a policy file (`policy.json`):

```json
{
  "protectedPaths": [
    {
      "path": "C:\\Users\\*\\Documents",
      "level": "high",
      "blockExtensions": [".exe", ".bat", ".ps1", ".locked"],
      "requireToken": true
    },
    {
      "path": "C:\\ProgramData\\Databases",
      "level": "critical",
      "blockExtensions": [],
      "requireToken": true,
      "requireTPM": true
    }
  ],
  "threatResponse": {
    "quarantineOnSuspicion": true,
    "autoNotifyAdmin": true,
    "alertThreshold": 60
  }
}
```

Load the policy:
```bash
python admin_config.py --load policy.json
```

### 3. Test Protection

Try to create a suspicious file:

```powershell
# This should be BLOCKED
$content = "test"
$content | Out-File "C:\Users\YourUser\Documents\test.locked"

# Expected: 
# [BLOCKED] File operation violates protection policy
# Check dashboard for alert
```

### 4: Check Dashboard

Navigate to `http://localhost:5000`:

1. **Dashboard Tab** — Overview of protection status
2. **Events Tab** — Recent security events
3. **Alerts Tab** — Active threats
4. **Policies Tab** — Configured protection rules
5. **Logs Tab** — Detailed audit trail

---

## Common Operations

### Add a Protected Directory

```bash
python add_files_to_protected.py \
  --path "C:\Users\YourUser\Downloads" \
  --protect \
  --alert-on-write
```

### Grant Token to Application

```bash
# Generate token for your app to access protected files
python ar_token.py generate \
  --process "myapp.exe" \
  --path "C:\Users\YourUser\AppData\Local\MyApp\*" \
  --operations "read,write" \
  --require-tpm
```

### Monitor Specific File

```bash
python check_security_events.py \
  --watch "C:\Users\YourUser\Documents" \
  --follow
```

### Block Suspicious Process

```bash
python blocking_protection.py \
  --process "suspicious.exe" \
  --action block
```

### Generate Audit Report

```bash
python admin_dashboard.py --export-audit \
  --from "2026-01-20" \
  --to "2026-01-25" \
  --format csv
```

---

## Troubleshooting

### Driver Won't Load

```powershell
# Check for test signing mode
bcdedit /set testsigning on
# Reboot required

# Verify driver file exists
Test-Path "C:\Program Files\AntiRansomware\driver.sys"

# Check Event Viewer for errors
Get-EventLog -LogName System -Source "AntiRansomware" -Newest 10
```

### High CPU Usage

```bash
# Check what's consuming resources
python check_security_events.py --stats

# If specific path causing issues, reduce monitoring:
python admin_config.py --exclude-path "C:\Temp\*"
```

### Token Validation Failing

```bash
# Verify token format
python ar_token.py validate --token "your_token_here"

# Check hardware fingerprint matches
python simple_token_test.py

# Regenerate token
python ar_token.py generate --process "app.exe" --force
```

### No Events Being Logged

```bash
# Enable debug logging
python activate_protection_logging.py --enable --debug

# Check log file
Get-Content "C:\ProgramData\AntiRansomware\logs\events.log" -Tail 20
```

---

## Next Steps

- **[Explore Architecture](../architecture)** — Understand how it works
- **[Read Operations Guide](./operations)** — Day-to-day administration
- **[Review Security Model](../security-model)** — Understand threat protection
- **[Check API Reference](../api-reference)** — Integrate custom tools
- **[Deployment Guide](./deployment)** — Enterprise rollout

---

## Getting Help

- **Issues:** [GitHub Issues](https://github.com/johnsonajibi/Ransomeware_protection/issues)
- **Documentation:** See [guides/](.) folder
- **Examples:** Check `examples/` directory for sample scripts
- **Community:** [GitHub Discussions](https://github.com/johnsonajibi/Ransomeware_protection/discussions)

---

**Congratulations!** Your anti-ransomware protection is now active. 🛡️
