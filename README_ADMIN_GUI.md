# Anti-Ransomware Admin Dashboard - Quick Start

## Overview
Production-ready web admin console for the Anti-Ransomware system with:
- **Protected Paths Management**: Add/remove folders via web UI, persist to policy
- **PQC Token Status**: Real-time hardware token detection and status
- **Driver/Agent Monitoring**: Windows minifilter, Linux netlink, macOS ES status
- **Event Logging**: Real-time security event monitoring with SIEM integration
- **Multi-Platform Support**: Windows, Linux, macOS with platform-specific drivers

## Quick Start

### 1. Install Dependencies
```powershell
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Set Environment Variables
```powershell
# Windows PowerShell
$env:ADMIN_USERNAME="admin"
$env:ADMIN_PASSWORD="S3cure!Adm1n#2025"
$env:ADMIN_SECRET_KEY="change-this-to-random-secret-key"
```

```bash
# Linux/macOS
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="S3cure!Adm1n#2025"
export ADMIN_SECRET_KEY="change-this-to-random-secret-key"
```

### 3. Start the Server

**Development Mode (Flask dev server):**
```bash
python admin_dashboard.py
```

**Production Mode (Waitress - recommended for Windows):**
```bash
python -m waitress --listen=127.0.0.1:8080 admin_dashboard:create_wsgi_app
```

**Production Mode (Gunicorn - Linux/macOS):**
```bash
gunicorn -b 127.0.0.1:8080 -w 4 'admin_dashboard:create_wsgi_app()'
```

### 4. Access the Dashboard
Open browser to: **http://127.0.0.1:8080**

Login with credentials set in environment variables.

## Web UI Features

### Dashboard (`/`)
- **System Statistics**: Events today, denied operations, active tokens, dongles, hosts
- **PQC Token Status**: Real-time hardware token detection
  - Shows serial number and public key when connected
  - Visual indicators for connection status
- **Recent Events**: Last 10 security events with timestamps

### Protected Paths (`/paths`)
- **Add Protected Folders**: Enter glob pattern (e.g., `C:\Documents\*`, `/home/*/protected/*`)
- **Configure Quotas**: Set max files/min and bytes/min limits per path
- **Recursive Protection**: Enable/disable subdirectory protection
- **Remove Paths**: Delete protection rules via web UI
- **Persistence**: All changes saved to `policy.yaml` automatically

### Drivers & Agents (`/drivers`)
- **Windows Minifilter**: 
  - Driver load status (via `fltmc filters`)
  - Service status (via `sc query RealAntiRansomware`)
  - Management commands provided
  
- **Linux Netlink Broker**:
  - systemd service status
  - `linux_broker.service` state monitoring
  - Start/stop commands
  
- **macOS EndpointSecurity**:
  - launchd agent status
  - `com.real.antiransomware` service state
  - Load/unload commands

### Events (`/events`)
- Real-time security event log
- Auto-refresh every 5 seconds
- Columns: timestamp, type, result, file path, user ID

### Policy (`/policy`)
- View current policy rules in JSON format
- Shows all path patterns, quotas, process rules
- Read-only display (edit via `/paths` page)

### Dongles (`/dongles`)
- Enumerate removable USB drives
- Show device path, mount point, filesystem type
- Platform-specific detection (uses `win32file` on Windows, psutil elsewhere)

## Architecture

### Authentication
- **Database-Backed Auth**: SQLite with werkzeug password hashing
- **Initial User Bootstrap**: First admin created from `ADMIN_USERNAME`/`ADMIN_PASSWORD` env vars
- **Session Management**: Flask-Login with secure cookies
- **TLS Support**: Optional TLS for both web (Flask) and gRPC endpoints

### Backend Components
- **Policy Engine** (`policy_engine.py`): YAML/JSON policy parsing, path/process/quota rules
- **Token Broker** (`broker.py`): gRPC token issuance with PQC hardware enforcement
- **Database Manager**: SQLite for events, tokens, users, dongles, hosts
- **gRPC Admin API**: `admin.proto` for remote management (optional)

### Platform-Specific Drivers
- **Windows**: Minifilter driver (`RealAntiRansomwareDriver.c/.inf`) for file system monitoring
- **Linux**: Netlink broker (`linux_broker.py`) for kernel communication
- **macOS**: EndpointSecurity agent (`driver_macos.swift`) for system event monitoring

## Configuration

### Database
- **Location**: `admin.db` (SQLite)
- **Tables**: users, events, tokens, dongles, hosts
- **Automatic**: Created on first startup

### Policy
- **File**: `policy.yaml`
- **Format**: YAML with path rules, quotas, process rules, time windows
- **Editable**: Via `/paths` web UI or manual YAML editing

### Admin Config
- **File**: `admin_config.json`
- **Auto-Generated**: Created with defaults on first run
- **Settings**:
  - Web server host/port
  - gRPC server port
  - TLS cert/key paths
  - SIEM integration endpoints
  - Elasticsearch configuration

## Security Hardening

### Required
- ✅ Database-backed user authentication with hashed passwords
- ✅ Secure session cookies (HttpOnly, Secure when TLS enabled)
- ✅ TLS support for web and gRPC (configurable)
- ✅ Fail-closed secret validation (startup blocked if missing)
- ✅ Debug mode disabled in production
- ✅ WSGI server (waitress/gunicorn) instead of Flask dev server

### Recommended
- 🔒 Generate strong random `ADMIN_SECRET_KEY` (32+ bytes)
- 🔒 Use TLS certificates (Let's Encrypt or self-signed)
- 🔒 Run behind reverse proxy (nginx/Caddy) for HTTPS termination
- 🔒 Bind to loopback (127.0.0.1) if using reverse proxy
- 🔒 Use systemd/launchd/Windows service for auto-restart
- 🔒 Enable SIEM integration for centralized logging
- 🔒 Regular security updates: `pip install -U -r requirements.txt`

## Platform-Specific Setup

### Windows Driver Installation
```powershell
# Build driver with Windows Driver Kit (WDK)
# Sign with test certificate for development:
MakeCert -r -pe -ss PrivateCertStore -n "CN=RealAntiRansomware" RealTest.cer

# Install driver
pnputil /add-driver RealAntiRansomwareDriver.inf /install

# Load driver
fltmc load RealAntiRansomware

# Start service
sc start RealAntiRansomware
```

### Linux Broker Installation
```bash
# Copy systemd unit
sudo cp linux_broker.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable linux_broker
sudo systemctl start linux_broker
```

### macOS Agent Installation
```bash
# Sign binary with Developer ID
codesign -s "Developer ID Application: YourName" driver_macos

# Install launchd plist
sudo cp com.real.antiransomware.plist /Library/LaunchDaemons/

# Load agent
sudo launchctl load /Library/LaunchDaemons/com.real.antiransomware.plist

# Grant Full Disk Access in System Preferences > Security & Privacy
```

## Troubleshooting

### Login Issues
- **Problem**: "Invalid credentials" error
- **Solution**: Check `ADMIN_USERNAME` and `ADMIN_PASSWORD` environment variables match
- **Verify**: `SELECT * FROM users;` in `admin.db`

### Template Not Found
- **Problem**: `TemplateNotFound: dashboard.html`
- **Solution**: Ensure `templates/` directory exists with all HTML files
- **Files Required**: `base.html`, `login.html`, `dashboard.html`, `events.html`, `paths.html`, `drivers.html`, `policy.html`, `dongles.html`

### PQC Token Not Detected
- **Problem**: "No PQC token detected" on dashboard
- **Solution**: 
  - Insert PQC USB hardware token
  - Verify `pqcdualusb` library installed: `pip install pqcdualusb`
  - Check USB permissions (may require admin/root)

### Driver Not Loaded
- **Windows**: Run `fltmc load RealAntiRansomware` as Administrator
- **Linux**: Check service status: `sudo systemctl status linux_broker`
- **macOS**: Verify Full Disk Access granted in System Preferences

### Port Already in Use
- **Problem**: `OSError: [Errno 98] Address already in use`
- **Solution**: Change port in environment or config:
  ```bash
  python -m waitress --listen=127.0.0.1:8081 admin_dashboard:create_wsgi_app
  ```

## API Reference

### REST Endpoints

**GET /api/events**
- Returns: JSON array of recent events
- Query params: `limit` (default 100), `offset`, `severity`, `host`

**GET /api/paths**
- Returns: JSON array of protected path rules
- Example: `[{"pattern": "C:\\Documents\\*", "recursive": true, "quota_files": 10, "quota_bytes": 1048576}]`

**POST /api/paths**
- Body: `{"pattern": "C:\\Secure\\*", "quota_files": 5, "quota_bytes": 524288, "recursive": true}`
- Returns: `{"success": true, "pattern": "C:\\Secure\\*"}`

**DELETE /api/paths**
- Body: `{"pattern": "C:\\Secure\\*"}`
- Returns: `{"success": true}`

### gRPC API

See `admin.proto` for full schema.

**GetDashboardStats**
- Request: `GetDashboardStatsRequest {}`
- Response: `DashboardStatsResponse { events_today, denied_today, active_tokens, active_dongles, active_hosts }`

**GetEvents**
- Request: `GetEventsRequest { limit, offset, severity, host }`
- Response: `GetEventsResponse { events[], total }`

**UpdatePolicy**
- Request: `UpdatePolicyRequest { policy_yaml }`
- Response: `UpdatePolicyResponse { success, error, version }`

## Production Deployment

See **PRODUCTION_GUI.md** for detailed deployment guides including:
- Waitress/Gunicorn configuration
- TLS certificate generation (Let's Encrypt, self-signed)
- Systemd service setup (Linux)
- Launchd service setup (macOS)
- Windows service setup (NSSM)
- Nginx/Caddy reverse proxy examples
- Security hardening checklist

## Development

### Generate Protocol Buffers
```bash
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. admin.proto
```

### Run Tests
```bash
pytest tests/
```

### Code Style
```bash
black admin_dashboard.py policy_engine.py
flake8 admin_dashboard.py
mypy admin_dashboard.py
```

## License
Copyright 2025 - All Rights Reserved

## Support
For issues, see project documentation or contact the development team.
