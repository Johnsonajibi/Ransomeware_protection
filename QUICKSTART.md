# Quick Start Guide - Real Anti-Ransomware# Quick Start Guide - Anti-Ransomware Protection System



## 🚀 5-Minute Setup## Prerequisites



### Prerequisites ✅1. **Python 3.10+** (you have Python 3.11.9 ✅)

- Windows 10/11 (64-bit)2. **Administrator/Root privileges** (required for kernel driver)

- Administrator account3. **USB smart card** (YubiKey, NitroKey, or SafeNet - optional for demo)

- Visual Studio 2019/2022 + WDK 10

## Installation & Setup

---

### Step 1: Install Dependencies

## Step 1: Build (First Time Only)```powershell

# Install Python dependencies

```powershellpip install -r requirements.txt

# Open Visual Studio Developer Command Prompt as Administrator

cd C:\Users\ajibi\Music\Anti-Ransomeware# If you get SSL/crypto errors, try:

pip install --upgrade pip

# Build manager applicationpip install cryptography pyscard PyYAML flask psutil requests

cl /EHsc /O2 RealAntiRansomwareManager_v2.cpp setupapi.lib newdev.lib cfgmgr32.lib crypt32.lib advapi32.lib /Fe:RealAntiRansomwareManager.exe```

```

### Step 2: Quick Demo (No USB Dongle Required)

---```powershell

# Start the service in demo mode

## Step 2: Enable Test Signing (First Time Only)python service_manager.py



```powershell# This will:

# Enable test mode (requires reboot)# - Initialize the configuration

bcdedit /set testsigning on# - Start health monitoring

shutdown /r /t 0# - Launch the web dashboard at http://localhost:8080

# - Start the gRPC API on port 50051

# After reboot, create test certificate```

makecert -r -pe -ss PrivateCertStore -n "CN=TestDriverCert" TestCert.cer

### Step 3: Access the Web Dashboard

# Sign driver1. Open your browser to: **http://localhost:8080**

signtool sign /v /s PrivateCertStore /n "TestDriverCert" RealAntiRansomwareDriver.sys2. You'll see the admin dashboard with:

```   - System status

   - Protected files/folders

---   - Security events

   - Policy management

## Step 3: Install & Start

### Step 4: Test the Policy Engine

```powershell```powershell

RealAntiRansomwareManager.exe install# In a new terminal, test the policy engine

RealAntiRansomwareManager.exe enablepython -c "

RealAntiRansomwareManager.exe statusfrom policy_engine import PolicyEngine

```engine = PolicyEngine('policies/default.yaml')

print('Policy engine loaded successfully!')

**Expected Output**:print(f'Loaded {len(engine.policies)} policies')

```"

✓ Driver loaded successfully!```

Protection level set to: Active

Current Level: 🟢 Active### Step 5: Test Token System (Demo Mode)

``````powershell

# Test the cryptographic token system

---python -c "

from ar_token import create_token_system, TokenRequest

## 🗄️ Protect SQL Server (Most Common Use Case)import time



### Quick Setup# Create demo token system (no USB required)

```powershelltoken_system = create_token_system(use_demo_keys=True)

# 1. Find SQL Server path (usually pre-filled)

RealAntiRansomwareManager.exe configure-db sqlservr.exe "C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA"# Create a test token

request = TokenRequest(

# 2. Make sure SQL is running    file_path='C:/Users/test.txt',

net start MSSQLSERVER    process_id=1234,

    user_id='demo-user',

# 3. Issue 24-hour token    operations=['read', 'write']

RealAntiRansomwareManager.exe issue-token sqlservr.exe)



# 4. Verifytoken = token_system.issue_token(request)

RealAntiRansomwareManager.exe list-tokensprint(f'Demo token created: {len(token)} bytes')

```

# Validate the token

### Expected Outputis_valid = token_system.validate_token(token, request)

```print(f'Token validation: {is_valid}')

=== Configuring Database Protection ==="

Database: sqlservr.exe```

Data Directory: C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA

✓ Database protection policy configured## Production Deployment

  Service Token Duration: 24 hours

  Path Confinement: Enabled### Option 1: Install as Windows Service

```powershell

=== Issuing Service Token ===# Run as Administrator

Found process: sqlservr.exe (PID: 2468)python service_manager.py --install

✓ Service token issued successfullynet start antiransomware

  Process ID: 2468```

  Valid for: 24 hours

### Option 2: Docker Deployment

=== Active Service Tokens ===```powershell

🔑 Token #1:# Build and run with Docker

  Process: sqlservr.exe (PID: 2468)python deployment.py docker

  Status: ✅ Activedocker-compose up -d

  File Operations: 0```

  Time Remaining: 23h 59m

  Allowed Paths:### Option 3: Cross-Platform Build

    📁 C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA```powershell

```# Build for current platform

python deployment.py build

---

# Build for specific platforms

## 🧪 Test Protectionpython deployment.py build windows amd64

python deployment.py build linux amd64

### Test 1: Try Creating Ransomware-Like File (Should Block)python deployment.py build darwin amd64

```powershell```

echo "test" > C:\Users\Public\test.encrypted

```## Testing the System



**Expected**: File creation blocked### Health Check

```powershell

### Test 2: Check Statistics# Check system health

```powershellpython -c "

RealAntiRansomwareManager.exe statusfrom health_monitor import create_health_monitor

```import yaml



**Expected**:# Load config

```with open('config.yaml', 'r') as f:

Files Blocked: 1    config = yaml.safe_load(f)

Suspicious Patterns: 1

```# Create and run health monitor

monitor = create_health_monitor(config)

### Test 3: SQL Server Normal Operation (Should Allow)results = monitor.run_all_checks()

```sql

-- Run in SQL Server Management Studiofor result in results:

CREATE DATABASE TestDB;    print(f'{result.name}: {result.status} - {result.message}')

GO"

```

USE TestDB;

CREATE TABLE TestTable (ID INT, Name VARCHAR(50));### Configuration Test

INSERT INTO TestTable VALUES (1, 'Test');```powershell

GO# Test configuration management

```python -c "

from config_manager import init_config

**Expected**: All operations succeed, no promptsconfig = init_config('config.yaml')

print('Configuration loaded successfully!')

### Test 4: Verify Token Activityprint(f'Web port: {config.get(\"network.web.port\", 8080)}')

```powershellprint(f'gRPC port: {config.get(\"network.grpc.port\", 50051)}')

RealAntiRansomwareManager.exe list-tokens"

``````



**Expected**:## Troubleshooting

```

File Operations: 150  (increased from 0)### Common Issues:

```

1. **"Permission denied" errors**

---   - Run PowerShell as Administrator

   - On Linux/macOS: use `sudo`

## 📅 Daily Operations

2. **"Module not found" errors**

### Morning Routine   ```powershell

```powershell   pip install --upgrade -r requirements.txt

# Check status   ```

RealAntiRansomwareManager.exe status

3. **"Port already in use"**

# Check token expiry   - Check if another service is using ports 8080 or 50051

RealAntiRansomwareManager.exe list-tokens   - Edit `config.yaml` to change ports

```

4. **USB dongle not detected**

### Renew Token (When < 1 Hour Remaining)   - Install smart card drivers (PC/SC)

```powershell   - For demo: use `use_demo_keys=True` in token system

RealAntiRansomwareManager.exe issue-token sqlservr.exe

```### Logs and Debugging

```powershell

---# Check logs

Get-Content logs/antiransomware.log -Tail 10

## 🛑 Uninstall

# Enable debug mode

```powershell$env:ANTIRANSOMWARE_DEBUG = "1"

RealAntiRansomwareManager.exe disablepython service_manager.py

RealAntiRansomwareManager.exe uninstall```



# Optional: Disable test signing## Development Mode

bcdedit /set testsigning off

shutdown /r /t 0### Running Individual Components

``````powershell

# Start just the web dashboard

---python admin_dashboard.py



## ⚠️ Common Issues# Start just the token broker

python broker.py

### "Failed to install driver"

- **Solution**: Run as Administrator# Test policy engine

- **Check**: `net session` should succeedpython policy_engine.py --test



### "Service token not found"# Run health checks

- **Solution**: Make sure SQL Server is running: `tasklist | findstr sqlservr.exe`python health_monitor.py --check-all

```

### "Path blocked"

- **Solution**: Add path to allowed paths in `configure-db` command### Code Quality Checks

```powershell

---# Install dev dependencies

pip install black flake8 mypy pytest

## 📊 Database-Specific Examples

# Run code quality checks

### PostgreSQLpython cicd_pipeline.py quality

```powershell

RealAntiRansomwareManager.exe configure-db postgres.exe "C:\PostgreSQL\data"# Run tests

net start postgresql-x64-14pytest tests/ -v

RealAntiRansomwareManager.exe issue-token postgres.exe```

```

## Next Steps

### MongoDB

```powershell1. **Configure Policies**: Edit `policies/default.yaml` to protect your folders

RealAntiRansomwareManager.exe configure-db mongod.exe "C:\data\db"2. **Setup USB Dongle**: Connect your YubiKey/NitroKey for hardware security

net start MongoDB3. **Enable Monitoring**: Configure alerts in `config.yaml`

RealAntiRansomwareManager.exe issue-token mongod.exe4. **Production Deploy**: Use `deployment.py` for production installation

```

## Getting Help

### MySQL

```powershell- Check `README.md` for complete documentation

RealAntiRansomwareManager.exe configure-db mysqld.exe "C:\ProgramData\MySQL\MySQL Server 8.0\Data"- View `ARCHITECTURE.md` for technical details

net start MySQL80- See `PRODUCTION_README.md` for enterprise features

RealAntiRansomwareManager.exe issue-token mysqld.exe- Enable debug logging for detailed troubleshooting

```

**🚀 Your anti-ransomware protection system is ready to run!**

---

## 🎯 Production Checklist

Before deploying to production servers:

- [ ] Obtain code signing certificate ($250-600/year)
- [ ] Purchase hardware security token (YubiKey $45)
- [ ] Document token renewal schedule (every 24 hours)
- [ ] Test disaster recovery procedure
- [ ] Configure Windows Event Log monitoring
- [ ] Set up alerts for `ServiceTokenRejections > 0`
- [ ] Backup current driver/manager versions
- [ ] Document rollback procedure

---

## 🔗 Next Steps

1. ✅ **You are here**: Quick start working
2. 📖 Read `README_DATABASE_PROTECTION.md` for architecture details
3. 🔬 Review troubleshooting section for edge cases
4. 🏭 Follow production deployment checklist
5. 📞 Plan incident response procedures

---

**Status**: ✅ Complete working implementation - NO PLACEHOLDERS

*Protection Level*: **🟢 Active** | *Service Tokens*: **✅ Operational** | *Database Support*: **✅ Full**
