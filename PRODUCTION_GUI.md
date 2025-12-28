# Admin GUI (Production)

## Prereqs
- Python env activated; install deps per `requirements.txt`.
- TLS cert/key files provisioned (PEM) if serving HTTPS directly.
- Set secrets via env or config file before start.

## Required secrets (fail closed if missing)
- `ADMIN_USERNAME` / `ADMIN_PASSWORD`: used to bootstrap the first admin user when no users exist.
- `ADMIN_SECRET_KEY`: Flask session secret (32+ random bytes).
- Optional config file values may override; env wins.

## Initial user bootstrap
- On first start, if the users table is empty, the service requires credentials from env/config and will create that admin user automatically.
- If neither users nor credentials are present, startup fails with an explicit error.

## TLS
- gRPC: set `grpc.tls.cert`/`grpc.tls.key` in `admin_config.json` (or edit after first run). Set `require` to `true` to forbid plaintext.
- Web: set `web.tls.cert`/`web.tls.key`; set `require` true to force HTTPS. Cookie security auto-enables when TLS is required.
- For reverse proxies, leave TLS empty and terminate upstream, but keep `cookie_secure` true.

## Config file
- On first run, `admin_config.json` is created with placeholders. Populate:
  - `auth.username_env` / `auth.password_env` (env names) or supply literal `username`/`password` values.
  - `web.secret_key_env` or `web.secret_key` for Flask secret.
  - `web.host`/`web.port` for bind address (default 127.0.0.1:8080).
  - `grpc.port` for admin gRPC port (default 50052).

## Production WSGI Servers

### Waitress (Recommended for Windows)
```powershell
# Direct startup
python -m waitress --listen=127.0.0.1:8080 admin_dashboard:create_wsgi_app

# With TLS (requires waitress[ssl])
python -m waitress --listen=127.0.0.1:8443 --url-scheme=https --channel-timeout=300 admin_dashboard:create_wsgi_app
```

### Gunicorn (Linux/macOS)
```bash
# Basic startup
gunicorn -b 127.0.0.1:8080 -w 4 'admin_dashboard:create_wsgi_app()'

# With TLS
gunicorn -b 127.0.0.1:8443 -w 4 --certfile=/path/to/cert.pem --keyfile=/path/to/key.pem 'admin_dashboard:create_wsgi_app()'
```

## TLS Certificate Generation

### Self-Signed Certificate (Development/Internal)
```bash
# Generate private key and self-signed cert (valid 365 days)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=admin.antiransomware.local"
```

### Let's Encrypt (Production)
```bash
# Install certbot
sudo apt install certbot  # Debian/Ubuntu
brew install certbot      # macOS

# Obtain certificate (requires domain with public DNS)
sudo certbot certonly --standalone -d admin.antiransomware.example.com

# Certificates will be in:
# /etc/letsencrypt/live/admin.antiransomware.example.com/fullchain.pem
# /etc/letsencrypt/live/admin.antiransomware.example.com/privkey.pem
```

## Systemd Service (Linux)

Create `/etc/systemd/system/admin-dashboard.service`:

```ini
[Unit]
Description=Anti-Ransomware Admin Dashboard
After=network.target

[Service]
Type=simple
User=antiransomware
Group=antiransomware
WorkingDirectory=/opt/antiransomware
Environment="ADMIN_USERNAME=admin"
Environment="ADMIN_PASSWORD=SecurePassword123!"
Environment="ADMIN_SECRET_KEY=random-secret-key-here"
ExecStart=/opt/antiransomware/venv/bin/gunicorn -b 127.0.0.1:8080 -w 4 'admin_dashboard:create_wsgi_app()'
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable admin-dashboard
sudo systemctl start admin-dashboard
sudo systemctl status admin-dashboard
```

## Launchd Service (macOS)

Create `/Library/LaunchDaemons/com.real.admin-dashboard.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.real.admin-dashboard</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/antiransomware/venv/bin/python</string>
        <string>-m</string>
        <string>waitress</string>
        <string>--listen=127.0.0.1:8080</string>
        <string>admin_dashboard:create_wsgi_app</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/opt/antiransomware</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>ADMIN_USERNAME</key>
        <string>admin</string>
        <key>ADMIN_PASSWORD</key>
        <string>SecurePassword123!</string>
        <key>ADMIN_SECRET_KEY</key>
        <string>random-secret-key-here</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/admin-dashboard.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/admin-dashboard.error.log</string>
</dict>
</plist>
```

Load and start:
```bash
sudo launchctl load /Library/LaunchDaemons/com.real.admin-dashboard.plist
sudo launchctl start com.real.admin-dashboard
launchctl list | grep admin-dashboard
```

## Windows Service

Use NSSM (Non-Sucking Service Manager):

```powershell
# Download NSSM from https://nssm.cc/download
# Install service
nssm install AdminDashboard "C:\Python311\python.exe" `
  "-m" "waitress" "--listen=127.0.0.1:8080" "admin_dashboard:create_wsgi_app"

# Set working directory
nssm set AdminDashboard AppDirectory "C:\AntiRansomware"

# Set environment variables
nssm set AdminDashboard AppEnvironmentExtra ADMIN_USERNAME=admin ADMIN_PASSWORD=SecurePassword123! ADMIN_SECRET_KEY=random-secret-key

# Start service
nssm start AdminDashboard
sc query AdminDashboard
```

## Reverse Proxy Setup

### Nginx
```nginx
server {
    listen 443 ssl http2;
    server_name admin.antiransomware.example.com;

    ssl_certificate /etc/letsencrypt/live/admin.antiransomware.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/admin.antiransomware.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Caddy (Automatic HTTPS)
```
admin.antiransomware.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

## Start
```bash
# Development (Flask dev server)
python admin_dashboard.py

# Production (waitress)
python -m waitress --listen=127.0.0.1:8080 admin_dashboard:create_wsgi_app

# Production (gunicorn - Linux/macOS)
gunicorn -b 127.0.0.1:8080 -w 4 'admin_dashboard:create_wsgi_app()'
```

Service will refuse to start if required secrets are unset or TLS is marked required but files are missing.

## Web UI Features

### Protected Paths Management (`/paths`)
- Add/remove protected folders and files via web UI
- Configure per-path quota limits (files/min, bytes/min)
- Recursive protection for subdirectories
- Changes persist to `policy.yaml` automatically

### PQC Token Status (Dashboard)
- Real-time PQC hardware token detection
- Display token serial number and public key
- Visual status indicators (connected/disconnected)

### Driver/Agent Status (`/drivers`)
- Windows minifilter driver status (loaded/service state)
- Linux netlink broker status (systemd service)
- macOS EndpointSecurity agent status (launchd)
- Installation and management commands for each platform

### Event Monitoring (`/events`)
- Real-time security event log
- Filter by severity, host, event type
- Auto-refresh with configurable interval

### Policy Management (`/policy`)
- View current policy rules
- Update policy from web UI
- Version control and rollback support

### Removable Devices (`/dongles`)
- Enumerate USB drives and removable media
- Monitor device connections/disconnections

## Hardening checklist
- Run behind TLS (either direct or via proxy) and set `cookie_secure=true`.
- Disable default debug; we run `debug=False`.
- Use strong, rotated `ADMIN_SECRET_KEY`.
- Restrict bind host to loopback or protected network; place behind an auth proxy if multi-tenant.
- Apply OS-level service units (systemd/launchd/Windows service) to supervise process.
- Configure SIEM outputs in `siem` section for central logging/alerts.
- Enable rate limiting and brute-force protection for login endpoint.
- Implement audit logging for all administrative actions.
- Use Content Security Policy (CSP) headers to prevent XSS.
- Regular security updates for Python dependencies (use `pip-audit`).
