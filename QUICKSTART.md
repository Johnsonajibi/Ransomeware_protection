# Quick Start Guide - Anti-Ransomware Protection System

## Prerequisites

1. **Python 3.10+** (you have Python 3.11.9 ✅)
2. **Administrator/Root privileges** (required for kernel driver)
3. **USB smart card** (YubiKey, NitroKey, or SafeNet - optional for demo)

## Installation & Setup

### Step 1: Install Dependencies
```powershell
# Install Python dependencies
pip install -r requirements.txt

# If you get SSL/crypto errors, try:
pip install --upgrade pip
pip install cryptography pyscard PyYAML flask psutil requests
```

### Step 2: Quick Demo (No USB Dongle Required)
```powershell
# Start the service in demo mode
python service_manager.py

# This will:
# - Initialize the configuration
# - Start health monitoring
# - Launch the web dashboard at http://localhost:8080
# - Start the gRPC API on port 50051
```

### Step 3: Access the Web Dashboard
1. Open your browser to: **http://localhost:8080**
2. You'll see the admin dashboard with:
   - System status
   - Protected files/folders
   - Security events
   - Policy management

### Step 4: Test the Policy Engine
```powershell
# In a new terminal, test the policy engine
python -c "
from policy_engine import PolicyEngine
engine = PolicyEngine('policies/default.yaml')
print('Policy engine loaded successfully!')
print(f'Loaded {len(engine.policies)} policies')
"
```

### Step 5: Test Token System (Demo Mode)
```powershell
# Test the cryptographic token system
python -c "
from ar_token import create_token_system, TokenRequest
import time

# Create demo token system (no USB required)
token_system = create_token_system(use_demo_keys=True)

# Create a test token
request = TokenRequest(
    file_path='C:/Users/test.txt',
    process_id=1234,
    user_id='demo-user',
    operations=['read', 'write']
)

token = token_system.issue_token(request)
print(f'Demo token created: {len(token)} bytes')

# Validate the token
is_valid = token_system.validate_token(token, request)
print(f'Token validation: {is_valid}')
"
```

## Production Deployment

### Option 1: Install as Windows Service
```powershell
# Run as Administrator
python service_manager.py --install
net start antiransomware
```

### Option 2: Docker Deployment
```powershell
# Build and run with Docker
python deployment.py docker
docker-compose up -d
```

### Option 3: Cross-Platform Build
```powershell
# Build for current platform
python deployment.py build

# Build for specific platforms
python deployment.py build windows amd64
python deployment.py build linux amd64
python deployment.py build darwin amd64
```

## Testing the System

### Health Check
```powershell
# Check system health
python -c "
from health_monitor import create_health_monitor
import yaml

# Load config
with open('config.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Create and run health monitor
monitor = create_health_monitor(config)
results = monitor.run_all_checks()

for result in results:
    print(f'{result.name}: {result.status} - {result.message}')
"
```

### Configuration Test
```powershell
# Test configuration management
python -c "
from config_manager import init_config
config = init_config('config.yaml')
print('Configuration loaded successfully!')
print(f'Web port: {config.get(\"network.web.port\", 8080)}')
print(f'gRPC port: {config.get(\"network.grpc.port\", 50051)}')
"
```

## Troubleshooting

### Common Issues:

1. **"Permission denied" errors**
   - Run PowerShell as Administrator
   - On Linux/macOS: use `sudo`

2. **"Module not found" errors**
   ```powershell
   pip install --upgrade -r requirements.txt
   ```

3. **"Port already in use"**
   - Check if another service is using ports 8080 or 50051
   - Edit `config.yaml` to change ports

4. **USB dongle not detected**
   - Install smart card drivers (PC/SC)
   - For demo: use `use_demo_keys=True` in token system

### Logs and Debugging
```powershell
# Check logs
Get-Content logs/antiransomware.log -Tail 10

# Enable debug mode
$env:ANTIRANSOMWARE_DEBUG = "1"
python service_manager.py
```

## Development Mode

### Running Individual Components
```powershell
# Start just the web dashboard
python admin_dashboard.py

# Start just the token broker
python broker.py

# Test policy engine
python policy_engine.py --test

# Run health checks
python health_monitor.py --check-all
```

### Code Quality Checks
```powershell
# Install dev dependencies
pip install black flake8 mypy pytest

# Run code quality checks
python cicd_pipeline.py quality

# Run tests
pytest tests/ -v
```

## Next Steps

1. **Configure Policies**: Edit `policies/default.yaml` to protect your folders
2. **Setup USB Dongle**: Connect your YubiKey/NitroKey for hardware security
3. **Enable Monitoring**: Configure alerts in `config.yaml`
4. **Production Deploy**: Use `deployment.py` for production installation

## Getting Help

- Check `README.md` for complete documentation
- View `ARCHITECTURE.md` for technical details
- See `PRODUCTION_README.md` for enterprise features
- Enable debug logging for detailed troubleshooting

**🚀 Your anti-ransomware protection system is ready to run!**
