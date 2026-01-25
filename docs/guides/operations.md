---
layout: default
title: Operations Guide
---

# Operations Guide

Day-to-day administration, monitoring, and troubleshooting.

---

## Daily Operations

### Morning Checklist

```bash
#!/bin/bash
# daily_ops_check.sh

echo "=== Anti-Ransomware Daily Operations Check ==="
echo ""

# 1. Verify services are running
echo "[1] Checking services..."
python admin_dashboard.py --health
if [ $? -ne 0 ]; then
  echo "ALERT: Dashboard is not responding"
  exit 1
fi

# 2. Check recent events
echo "[2] Checking recent security events..."
python check_security_events.py --since "1 hour ago" --severity high

# 3. Verify data backups
echo "[3] Verifying backup status..."
python backup_integration.py --check-backup-status

# 4. Review active alerts
echo "[4] Review active alerts..."
curl -H "Authorization: Bearer $API_TOKEN" \
  https://admin-server:5000/api/v1/alerts?severity=high

echo ""
echo "Daily check complete"
```

### Weekly Tasks

| Task | Command | Frequency |
|------|---------|-----------|
| Policy Review | `python admin_config.py --review-policies` | Weekly |
| Token Audit | `python ar_token.py --audit-tokens` | Weekly |
| Performance Analysis | `python admin_dashboard.py --performance-report` | Weekly |
| Security Patching | Check Windows Update | As needed |
| Backup Verification | `python backup_integration.py --verify` | Weekly |

### Monthly Tasks

- [ ] Full security audit
- [ ] Threat intelligence update
- [ ] Performance baseline comparison
- [ ] Storage usage review
- [ ] Team training review
- [ ] Policy effectiveness assessment

---

## Monitoring & Alerting

### Key Metrics to Monitor

```
┌─────────────────────────────────────┐
│ System Health Metrics               │
├─────────────────────────────────────┤
│ • Driver CPU usage: < 5%            │
│ • Driver memory: < 50 MB            │
│ • Manager process: < 100 MB         │
│ • Event queue depth: < 1000         │
│ • False positive rate: < 1%         │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ Security Metrics                    │
├─────────────────────────────────────┤
│ • Threats blocked: 0-10/day (normal)│
│ • Suspicious events: < 100/day      │
│ • Quarantined files: < 50/day       │
│ • Token validation failures: < 5/min│
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ Operational Metrics                 │
├─────────────────────────────────────┤
│ • Dashboard availability: 99.5%+    │
│ • Database response time: < 100ms   │
│ • Policy sync latency: < 30s        │
│ • Event delivery latency: < 5s      │
└─────────────────────────────────────┘
```

### Setting Up Alerts

```yaml
# alerts.yaml
alerts:
  high_cpu_usage:
    condition: "cpu_usage > 20%"
    duration: "5 minutes"
    severity: "high"
    notification:
      - email: admin@company.com
      - slack: "#security-alerts"
  
  token_validation_failures:
    condition: "validation_failures > 10/minute"
    duration: "1 minute"
    severity: "critical"
    notification:
      - pagerduty
      - email: security-team@company.com
  
  threat_detected:
    condition: "threat_score > 80"
    duration: "immediate"
    severity: "critical"
    notification:
      - pagerduty
      - hipchat
      - email

  quarantine_quota:
    condition: "quarantine_usage > 80%"
    duration: "1 hour"
    severity: "high"
    notification:
      - email: storage-admin@company.com
```

Load alerts:
```bash
python admin_config.py --load alerts.yaml
```

---

## Token Management

### Generate Tokens

```bash
# For a specific application
python ar_token.py generate \
  --process "myapp.exe" \
  --path "C:\Users\*\AppData\Local\MyApp\*" \
  --operations "read,write" \
  --lifetime 3600 \
  --require-tpm

# For a service account
python ar_token.py generate \
  --service "SQL Server" \
  --path "C:\ProgramData\MSSQL\*" \
  --operations "read,write,delete" \
  --lifetime 86400 \
  --require-tpm \
  --require-fingerprint
```

### Audit Token Usage

```bash
# View all active tokens
python ar_token.py list --status active

# Check token validation attempts
python ar_token.py audit \
  --since "2026-01-20" \
  --token-id "tok_12345"

# Output:
# Token ID: tok_12345
# Process: notepad.exe
# Created: 2026-01-20T10:00:00Z
# Expires: 2026-01-20T11:00:00Z
# Status: Valid
#
# Usage:
#   Validations: 1523
#   Failures: 0
#   Last used: 2026-01-20T10:59:45Z
#
# Incidents:
#   None
```

### Revoke Tokens

```bash
# Revoke specific token
python ar_token.py revoke --token-id "tok_12345"

# Revoke all tokens for process
python ar_token.py revoke-process --process "oldapp.exe"

# Revoke by expiration (cleanup old tokens)
python ar_token.py revoke --before "2026-01-01"
```

---

## Policy Management

### View Current Policies

```bash
python admin_config.py --list-policies

# Output:
# Policy: Documents Protection
#   Path: C:\Users\*\Documents
#   Level: Critical
#   Require Token: Yes
#   Require TPM: Yes
#   Active: Yes
#
# Policy: Downloads Monitor
#   Path: C:\Users\*\Downloads
#   Level: High
#   Require Token: No
#   Block Extensions: .exe, .bat, .ps1
#   Active: Yes
```

### Create New Policy

```bash
cat > policy_new.json << 'EOF'
{
  "name": "Database Protection",
  "paths": ["C:\\ProgramData\\Databases"],
  "level": "critical",
  "require_token": true,
  "require_tpm": true,
  "require_fingerprint": true,
  "block_extensions": [],
  "allowed_operations": ["read", "write"],
  "anomaly_threshold": 70,
  "alert_on_write": true
}
EOF

python admin_config.py --create-policy policy_new.json
```

### Test Policy Before Deployment

```bash
# Deploy in AUDIT mode first (log but don't block)
python admin_config.py --create-policy policy_new.json --mode audit

# Monitor for 1 week
sleep 604800

# Review audit log
python check_security_events.py --policy "Database Protection" --since "7 days ago"

# If no issues, enable enforcement
python admin_config.py --update-policy "Database Protection" --mode enforce
```

### Update Policy

```bash
# Add new paths to existing policy
python admin_config.py --update-policy "Documents Protection" \
  --add-path "C:\Users\*\OneDrive\*"

# Change protection level
python admin_config.py --update-policy "Documents Protection" \
  --level high

# Add blocked extensions
python admin_config.py --update-policy "Documents Protection" \
  --block-extensions ".exe,.bat,.ps1,.vbs"
```

### Disable Policy

```bash
# Temporarily disable (keeps configuration)
python admin_config.py --disable-policy "Documents Protection"

# Delete policy permanently
python admin_config.py --delete-policy "Documents Protection"
```

---

## Incident Response

### Detect an Incident

```bash
# Check recent events
python check_security_events.py --since "1 hour ago" --severity critical

# Output might show:
# Event: FILE_MODIFICATION_BLOCKED
# Timestamp: 2026-01-25T14:23:45Z
# Process: unknown_process.exe (PID: 2840)
# Target: C:\Users\User\Documents\*.docx (10 files)
# Threat Score: 95
# Action: QUARANTINED
```

### Investigate Incident

```bash
# 1. Check process details
python admin_dashboard.py --process-details "PID=2840"

# 2. See all files accessed by process
python check_security_events.py --process-id 2840 --since "30 minutes ago"

# 3. Check threat intelligence
python admin_dashboard.py --check-threat-hash "process_hash_here"

# 4. Review quarantine contents
python admin_dashboard.py --list-quarantine --since "30 minutes ago"
```

### Contain Incident

```bash
# 1. Immediately block process
python blocking_protection.py --process "unknown_process.exe" --action block

# 2. Alert security team (automatic via gRPC)
# (Notifications go to Slack/PagerDuty based on alert config)

# 3. Check for lateral movement
python admin_dashboard.py --check-network-activity --process-id 2840

# 4. Check backup status
python backup_integration.py --check-backup-status
```

### Recover from Incident

```bash
# 1. Restore quarantined files
python admin_dashboard.py --restore-quarantine \
  --incident-id "evt_12345" \
  --target-path "C:\Recovery\Restored"

# 2. Scan restored files
python admin_dashboard.py --scan-path "C:\Recovery\Restored"

# 3. Verify restore integrity
python backup_integration.py --verify-restore \
  --timestamp "2026-01-25T14:00:00Z"

# 4. Enable protection on restored paths
python add_files_to_protected.py \
  --path "C:\Recovery\Restored\*" \
  --protect
```

### Post-Incident Actions

```bash
# 1. Generate incident report
python admin_dashboard.py --generate-incident-report \
  --incident-id "evt_12345" \
  --format pdf

# 2. Update threat signatures
python admin_dashboard.py --update-threat-intelligence

# 3. Review and update policies
python admin_config.py --review-policies \
  --after-incident "evt_12345"

# 4. Schedule RCA (Root Cause Analysis)
echo "Schedule incident review meeting"
```

---

## Performance Tuning

### Monitor Performance

```bash
# Get performance metrics
python admin_dashboard.py --performance-report

# Output:
# Performance Metrics:
#   Driver overhead:
#     - CPU: 2.3%
#     - Memory: 12 MB
#   File operations:
#     - Open: +0.8ms average
#     - Write: +1.2ms average
#   Validation:
#     - Token verify: 0.5ms
#     - Hash compute: 2.1ms
```

### Optimize Cache

```bash
# Current cache settings
python admin_config.py --show-cache-settings

# Increase cache size
python admin_config.py --set-cache-size 500MB

# Clear cache
python admin_config.py --clear-cache

# Verify optimization
python admin_dashboard.py --performance-report
```

### Database Optimization

```bash
# Check database size
python admin_dashboard.py --database-stats

# Archive old logs (> 90 days)
python admin_config.py --archive-logs --before "2025-10-26"

# Rebuild indexes
python admin_dashboard.py --rebuild-database-indexes

# Verify performance
python admin_dashboard.py --database-performance-test
```

---

## Backup & Recovery

### Backup Configuration

```bash
# Backup driver and policy configuration
python backup_integration.py --backup \
  --include-driver \
  --include-policies \
  --include-tokens \
  --destination "\\\\backup-server\\share\ar-backups"
```

### Restore Configuration

```bash
# Restore from backup
python backup_integration.py --restore \
  --backup-id "backup_20260120" \
  --verify-integrity
```

### Test Disaster Recovery

```bash
# Monthly DR drill
python backup_integration.py --test-recovery \
  --backup-id "backup_latest" \
  --test-environment "DR-Lab"

# Verify recovery success
python backup_integration.py --verify-recovery --test-environment "DR-Lab"
```

---

## Troubleshooting

### High CPU Usage

```bash
# Check what's consuming CPU
python admin_dashboard.py --cpu-profiling --duration 60

# Likely causes:
# 1. Too many events - reduce policy scope
#    python admin_config.py --exclude-path "C:\Temp\*"
#
# 2. Hash computation bottleneck - increase cache
#    python admin_config.py --set-cache-size 1GB
#
# 3. Malware in quarantine - scan and clean
#    python admin_dashboard.py --scan-quarantine
```

### Memory Leak

```bash
# Monitor memory over time
python admin_dashboard.py --memory-profiling --duration 3600

# Check for memory leaks
python admin_dashboard.py --check-memory-leaks

# If found:
# 1. Restart manager service
sc restart AntiRansomware

# 2. Clear caches
python admin_config.py --clear-cache

# 3. Archive logs
python admin_config.py --archive-logs
```

### Driver Unresponsive

```bash
# Check driver status
sc query AntiRansomware

# If unresponsive:
# 1. Check system event log
Get-EventLog -LogName System -Source AntiRansomware -Newest 20

# 2. Try graceful restart
sc stop AntiRansomware
sc start AntiRansomware

# 3. If still unresponsive, reboot required
shutdown /r /t 300 /c "AR driver recovery"
```

### Token Validation Failures

```bash
# Check token validation logs
python ar_token.py --check-failures --since "1 hour ago"

# Investigate specific failure
python ar_token.py --debug-token "tok_12345"

# Likely causes:
# 1. Token expired
#    python ar_token.py generate --process "app.exe"
#
# 2. Hardware mismatch
#    python ar_token.py --check-hardware-fingerprint
#
# 3. TPM issue
#    python ar_token.py --check-tpm-status
```

---

## Security Maintenance

### Update Threat Intelligence

```bash
# Check for updates
python admin_dashboard.py --check-ti-updates

# Update manually
python admin_dashboard.py --update-threat-intelligence

# Verify signatures loaded
python admin_dashboard.py --check-signatures

# Output:
# Threat Intelligence Status:
#   Last update: 2026-01-25T10:00:00Z
#   Signature count: 45,123
#   Hash database: current
#   ML models: 3 days old
```

### Rotate Cryptographic Keys

```bash
# Schedule key rotation
python admin_config.py --schedule-key-rotation \
  --rotation-date "2026-02-25T00:00:00Z"

# Review scheduled rotations
python admin_config.py --list-scheduled-rotations

# Perform emergency rotation (if needed)
python admin_config.py --rotate-keys-now --emergency
```

### Security Audit

```bash
# Generate monthly security audit
python admin_dashboard.py --generate-audit-report \
  --month January \
  --year 2026 \
  --format pdf

# Includes:
# - All admin actions
# - Policy changes
# - Token operations
# - Threat incidents
# - Compliance status
```

---

## Compliance & Reporting

### Generate Compliance Report

```bash
# SOC 2 compliance report
python admin_dashboard.py --compliance-report \
  --standard SOC2 \
  --period "2025-Q4"

# HIPAA audit trail
python admin_dashboard.py --audit-trail \
  --standard HIPAA \
  --format csv

# PCI-DSS evidence
python admin_dashboard.py --pci-report \
  --save-location "\\\\compliance-share\reports"
```

### Export Audit Logs

```bash
# Export for external audit
python admin_dashboard.py --export-audit-log \
  --since "2026-01-01" \
  --until "2026-01-25" \
  --format syslog \
  --destination "siem-server:514"
```

---

## Common Commands Reference

```bash
# Status checks
python admin_dashboard.py --health              # System health
python check_security_events.py --status       # Protection status
python ar_token.py --list                      # Active tokens

# Policy management
python admin_config.py --list-policies         # View policies
python admin_config.py --create-policy <file>  # Create policy
python admin_config.py --delete-policy <name>  # Delete policy

# Incident response
python check_security_events.py --since "1h"   # Recent events
python blocking_protection.py --process <exe>  # Block process
python admin_dashboard.py --list-quarantine    # View quarantine

# Maintenance
python backup_integration.py --backup           # Backup config
python admin_config.py --archive-logs          # Archive logs
python admin_dashboard.py --clear-cache        # Clear cache

# Monitoring
python admin_dashboard.py --performance-report  # Performance
python admin_dashboard.py --check-health       # Full health check
```

---

**Next:** [Troubleshooting Guide](./troubleshooting)
