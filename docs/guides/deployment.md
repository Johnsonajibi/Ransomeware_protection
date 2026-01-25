---
layout: default
title: Deployment Guide
---

# Deployment Guide

Enterprise and single-host deployment strategies.

---

## Deployment Models

### Model 1: Single Workstation (Standalone)

Best for: Individual users, small offices

```
┌──────────────────────────────┐
│     Windows Workstation      │
├──────────────────────────────┤
│  ✓ Kernel Driver             │
│  ✓ User-Mode Manager         │
│  ✓ Admin Dashboard (local)   │
│  ✓ Protection Engine         │
└──────────────────────────────┘
```

**Advantages:**
- Simple setup, no infrastructure
- Works offline
- Full local control

**Disadvantages:**
- Manual management of each machine
- No centralized reporting
- Limited scaling

---

### Model 2: Enterprise Centralized (Recommended)

Best for: Corporations, managed environments

```
┌─────────────────────────────────────────────────┐
│          Admin Server (Central)                  │
├─────────────────────────────────────────────────┤
│  ✓ Master Dashboard                             │
│  ✓ Policy Engine                                │
│  ✓ Audit Database                               │
│  ✓ Threat Intelligence                          │
│  ✓ Backup Integration                           │
└────────────┬────────────────────────────────────┘
             │ gRPC / REST APIs
      ┌──────┴──────────────────────────┐
      │                                  │
  ┌───▼────────────────┐           ┌────▼───────────────┐
  │ Workstation 1      │           │ Workstation N      │
  ├────────────────────┤           ├────────────────────┤
  │ ✓ Kernel Driver    │           │ ✓ Kernel Driver    │
  │ ✓ Thin Manager     │           │ ✓ Thin Manager     │
  │ ✓ Token Validator  │           │ ✓ Token Validator  │
  │ ✓ Event Reporter   │           │ ✓ Event Reporter   │
  └────────────────────┘           └────────────────────┘
```

**Advantages:**
- Centralized policy management
- Real-time threat visibility
- Simplified administration at scale
- Better compliance reporting
- Coordinated incident response

**Disadvantages:**
- Requires infrastructure
- Central point of management
- Network dependency

---

## Single Workstation Deployment

### Prerequisites

- Windows 10 Build 19041+ or Windows 11
- Administrator privileges
- 4 GB RAM minimum
- 500 MB disk space
- Visual C++ Redistributable

### Installation Steps

#### 1. Download and Extract

```powershell
# As Administrator
$DownloadDir = "$env:TEMP\AntiRansomware"
New-Item -ItemType Directory -Path $DownloadDir -Force

# Extract repository
git clone https://github.com/johnsonajibi/Ransomeware_protection $DownloadDir\ar
cd $DownloadDir\ar
```

#### 2. Install Driver

```powershell
# Build driver
.\build_production.bat

# Install as Windows service
sc create AntiRansomware `
  binPath= "C:\Program Files\AntiRansomware\driver.sys" `
  type= kernel `
  start= auto `
  DisplayName= "Anti-Ransomware Kernel Driver"

# Start service
Start-Service -Name AntiRansomware
```

#### 3. Configure Protection

```bash
# Activate protection
python activate_protection_logging.py --enable

# Add protected paths
python add_files_to_protected.py --path "C:\Users\*\Documents" --protect
python add_files_to_protected.py --path "C:\Users\*\Desktop" --protect
```

#### 4. Start Dashboard

```bash
# Run admin dashboard
python admin_dashboard.py --port 5000

# Access at http://localhost:5000
```

---

## Enterprise Deployment

### Prerequisites

- **Admin Server:**
  - Windows Server 2019+ or Linux
  - 8 GB RAM minimum
  - 100 GB storage (for logs)
  - Network accessibility from workstations
  - Database (PostgreSQL recommended)

- **Workstations:**
  - Windows 10/11
  - Network connectivity to admin server
  - Admin privileges for initial setup

### Architecture Setup

#### Step 1: Deploy Admin Server

```bash
# On central admin server
git clone https://github.com/johnsonajibi/Ransomeware_protection
cd Ransomeware_protection

# Install dependencies
pip install -r requirements.txt
pip install postgresql psycopg2-binary

# Configure database connection
cat > config.yaml << EOF
database:
  type: postgresql
  host: localhost
  port: 5432
  name: antiransomware
  user: ar_admin
  password: SecurePassword123!

server:
  host: 0.0.0.0
  port: 5000
  workers: 8
  
logging:
  level: INFO
  path: /var/log/antiransomware/
  retention_days: 90
EOF

# Start admin dashboard
python admin_dashboard.py --config config.yaml
```

#### Step 2: Configure Policy Server

Create a policy distribution server:

```python
# policy_server.py
from flask import Flask, jsonify
import json

app = Flask(__name__)

POLICIES = {
    "default": {
        "protectedPaths": [
            {"path": "C:\\Users\\*\\Documents", "level": "high"},
            {"path": "C:\\Users\\*\\Desktop", "level": "high"},
        ],
        "threatResponse": {
            "quarantineOnSuspicion": True,
            "alertThreshold": 60
        }
    }
}

@app.route('/policy/<policy_id>', methods=['GET'])
def get_policy(policy_id):
    return jsonify(POLICIES.get(policy_id, POLICIES["default"]))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, ssl_context='adhoc')
```

#### Step 3: Deploy to Workstations

Create a deployment script:

```powershell
# deploy_to_workstation.ps1
param(
    [string]$AdminServerUrl = "https://admin-server:5000"
)

# Check admin rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run as Administrator"
    exit 1
}

# Download and extract
$TempDir = "$env:TEMP\AR_Deployment"
New-Item -ItemType Directory -Path $TempDir -Force
git clone https://github.com/johnsonajibi/Ransomeware_protection $TempDir\ar

# Build driver
cd $TempDir\ar
.\build_production.bat

# Install driver
sc create AntiRansomware `
  binPath= "C:\Program Files\AntiRansomware\driver.sys" `
  type= kernel `
  start= auto

# Configure thin manager
$ConfigFile = "C:\Program Files\AntiRansomware\manager_config.json"
@{
    adminServer = $AdminServerUrl
    reportInterval = 60
    enableLocalCache = $true
    tokenVerifyMode = "strict"
} | ConvertTo-Json | Set-Content $ConfigFile

# Start service
Start-Service -Name AntiRansomware
Write-Host "Deployment successful"
```

Run deployment across workstations:

```powershell
# Deploy to multiple machines
$Computers = @("WS-001", "WS-002", "WS-003")

foreach ($Computer in $Computers) {
    Write-Host "Deploying to $Computer..."
    Invoke-Command -ComputerName $Computer `
        -FilePath .\deploy_to_workstation.ps1 `
        -ArgumentList "https://admin-server:5000"
}
```

#### Step 4: Configure Global Policies

```bash
# On admin server, set organization-wide policies
python admin_config.py --set-global-policy <<'EOF'
{
  "organization": "Acme Corp",
  "protectedPaths": [
    {
      "path": "**\\Documents",
      "level": "critical",
      "requireToken": true,
      "requireTPM": true
    },
    {
      "path": "**\\AppData\\Local\\Temp",
      "level": "low",
      "blockExtensions": [".exe", ".bat"]
    }
  ],
  "tokenPolicy": {
    "maxLifetime": 86400,
    "requireTPM": true,
    "requireDeviceFingerprint": true
  },
  "threatResponse": {
    "autoQuarantine": true,
    "alertAdminImmediately": true,
    "notifyUser": true
  }
}
EOF
```

---

## High-Availability Deployment

For mission-critical environments:

```
┌─────────────────────────────────┐
│    Load Balancer / Reverse      │
│         Proxy (HA)              │
└──────────────┬──────────────────┘
               │
      ┌────────┴────────┐
      │                 │
  ┌───▼────┐        ┌───▼────┐
  │ Admin   │        │ Admin   │
  │Server 1 │◄───────┤Server 2 │
  │(Primary)│ Sync   │(Backup) │
  └─────────┘        └─────────┘
      │                 │
      └─────────┬───────┘
                │
          [Workstations]
```

**Configuration:**

```yaml
# ha_config.yaml
ha:
  enabled: true
  primary: admin-server-1.example.com
  backup: admin-server-2.example.com
  
  database:
    type: postgresql
    replication: true
    standby_host: admin-server-2
    
  cache:
    type: redis
    cluster:
      nodes:
        - redis-1:6379
        - redis-2:6379
        - redis-3:6379
        
  failover:
    timeout: 30
    auto_recover: true
```

---

## Network Configuration

### Firewall Rules

```
Admin Server:
  - Port 5000 (gRPC): Accept from workstations
  - Port 5432 (Database): Accept from admin servers only
  - Port 6379 (Redis): Accept from admin servers only

Workstations:
  - Port 5000: Accept from admin server
  - Block all other inbound traffic
```

### Network Segments

```
┌─────────────────────────────────────┐
│  Workstations VLAN (10.1.0.0/24)    │
│  - Can reach admin server           │
│  - Cannot reach each other          │
└────────────────┬────────────────────┘
                 │
            Firewall
                 │
┌────────────────▼────────────────────┐
│  Admin VLAN (10.2.0.0/24)           │
│  - Admin server                     │
│  - Database server                  │
│  - Backup systems                   │
└─────────────────────────────────────┘
```

---

## Monitoring Deployment

### Health Checks

```bash
# Check all workstations
python deployment_monitor.py --check-all

# Expected output:
# Workstation          Status    Version    Last Contact
# WS-001              Online    1.0.0      30s ago
# WS-002              Online    1.0.0      45s ago
# WS-003              Offline   1.0.0      5m ago ⚠️
```

### Logs Aggregation

```bash
# Configure log forwarding
python admin_config.py --enable-log-aggregation \
  --syslog-server admin-server:514

# Verify
curl -s http://admin-server:5000/api/logs/status | jq .
```

---

## Troubleshooting Deployment

### Workstation Not Connecting

```bash
# On workstation
# Check network connectivity
Test-NetConnection -ComputerName admin-server -Port 5000

# Check configuration
Get-Content "C:\Program Files\AntiRansomware\manager_config.json"

# Verify service running
Get-Service AntiRansomware | Select Status

# Check logs
Get-EventLog -LogName Application -Source AntiRansomware -Newest 10
```

### Policy Not Applying

```bash
# On admin server
# Verify policy syntax
python admin_config.py --validate-policy policy.json

# Check policy distribution
python admin_dashboard.py --check-distribution

# Force sync on workstation
# (via admin dashboard -> Workstations -> Force Sync)
```

---

## Rollout Checklist

- [ ] Admin server deployed and verified
- [ ] Database configured and replicated
- [ ] Policies defined and tested
- [ ] Test deployment on 3-5 workstations
- [ ] Monitor for 1 week in ALERT mode
- [ ] Enable blocking on test group
- [ ] Roll out to department (10+ machines)
- [ ] Verify no business impact
- [ ] Full organization rollout
- [ ] Archive pre-deployment baselines

---

**Next:** [Operations Guide](./operations)
