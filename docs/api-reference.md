---
layout: default
title: API Reference
---

# API Reference

IOCTL commands, REST endpoints, and Python SDK for programmatic access.

---

## Overview

The Anti-Ransomware platform provides three APIs:

1. **Kernel IOCTL** — Direct kernel driver communication
2. **REST/gRPC** — Remote management and monitoring
3. **Python SDK** — High-level programmatic interface

---

## Kernel IOCTL Interface

### IOCTL Commands

#### 1. IOCTL_AR_VALIDATE_TOKEN

**Purpose:** Validate a token for file access authorization

**Code:**
```c
#define IOCTL_AR_VALIDATE_TOKEN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input Buffer:**
```c
struct {
    uint32_t token_size;
    uint8_t token_data[MAX_TOKEN_SIZE];  // Serialized token
};
```

**Output Buffer:**
```c
struct {
    uint32_t status;                    // 0 = valid, !0 = error
    uint32_t threat_score;              // 0-100
    char threat_reason[256];            // Why denied, if applicable
};
```

**Example:**
```c
HANDLE device = CreateFile(
    "\\\\.\\AntiRansomware",
    GENERIC_READ | GENERIC_WRITE,
    0, NULL,
    OPEN_EXISTING, 0, NULL
);

struct TokenValidation input = {
    .token_size = 128,
    .token_data = { /* Ed25519 signature */ }
};

struct TokenValidationResult output;
DWORD bytes_returned;

DeviceIoControl(
    device,
    IOCTL_AR_VALIDATE_TOKEN,
    &input, sizeof(input),
    &output, sizeof(output),
    &bytes_returned, NULL
);
```

---

#### 2. IOCTL_AR_GET_THREAT_SCORE

**Purpose:** Get current threat level for a file

**Code:**
```c
#define IOCTL_AR_GET_THREAT_SCORE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input Buffer:**
```c
struct {
    char file_path[MAX_PATH];  // Path to evaluate
};
```

**Output Buffer:**
```c
struct {
    uint32_t threat_score;     // 0-100
    uint32_t threat_flags;     // Bitmask of threats detected
    char threat_description[512];
};
```

**Threat Flags:**
```c
#define THREAT_ENCRYPTED_EXTENSION  0x01  // File extension changed
#define THREAT_RAPID_DELETE         0x02  // Many files deleted
#define THREAT_UNUSUAL_PATTERN      0x04  // Abnormal access pattern
#define THREAT_KNOWN_SIGNATURE      0x08  // Matches known malware
#define THREAT_BEHAVIOR_ANOMALY     0x10  // ML anomaly detected
```

---

#### 3. IOCTL_AR_SET_PROTECTED_PATH

**Purpose:** Add or update a protected file path

**Code:**
```c
#define IOCTL_AR_SET_PROTECTED_PATH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input Buffer:**
```c
struct {
    char path[MAX_PATH];           // Path pattern (supports * wildcards)
    uint32_t protection_level;     // 1=Low, 2=Medium, 3=High, 4=Critical
    uint32_t require_token;        // 1=yes, 0=no
    uint32_t block_extensions;     // Bitmask of extensions to block
};
```

**Output Buffer:**
```c
struct {
    uint32_t status;  // 0=success, !0=error
};
```

---

#### 4. IOCTL_AR_QUARANTINE_FILE

**Purpose:** Move a file to quarantine

**Code:**
```c
#define IOCTL_AR_QUARANTINE_FILE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input Buffer:**
```c
struct {
    char file_path[MAX_PATH];
    char reason[256];  // Why quarantined
};
```

**Output Buffer:**
```c
struct {
    uint32_t status;
    char quarantine_location[MAX_PATH];
};
```

---

## REST API

### Base URL
```
https://admin-server:5000/api/v1
```

### Authentication
```bash
# All requests require Bearer token
curl -H "Authorization: Bearer $TOKEN" https://admin-server:5000/api/v1/events
```

---

### Endpoints

#### GET /health

Get system health status

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 84600,
  "components": {
    "kernel_driver": "running",
    "admin_dashboard": "running",
    "database": "connected"
  }
}
```

---

#### GET /events

List security events

**Query Parameters:**
```
?limit=100          # Default: 100
&offset=0           # Default: 0
&severity=critical  # Filter by: critical, high, medium, low
&since=2026-01-20T00:00:00Z  # ISO 8601 timestamp
```

**Response:**
```json
{
  "total": 1523,
  "events": [
    {
      "id": "evt_12345",
      "timestamp": "2026-01-25T14:23:45Z",
      "type": "FILE_WRITE_BLOCKED",
      "severity": "high",
      "process_name": "ransomware.exe",
      "file_path": "C:\\Users\\User\\Documents\\data.docx",
      "threat_score": 95,
      "action_taken": "BLOCKED"
    }
  ]
}
```

---

#### GET /policies

List active protection policies

**Response:**
```json
{
  "policies": [
    {
      "id": "pol_001",
      "name": "Documents Protection",
      "paths": ["C:\\Users\\*\\Documents"],
      "level": "critical",
      "require_token": true,
      "active": true
    }
  ]
}
```

---

#### POST /policies

Create new protection policy

**Request:**
```json
{
  "name": "Database Protection",
  "paths": ["C:\\ProgramData\\Databases"],
  "level": "critical",
  "require_token": true,
  "require_tpm": true,
  "block_extensions": [".exe", ".bat"],
  "alert_threshold": 60
}
```

**Response:**
```json
{
  "id": "pol_002",
  "status": "created",
  "effective_from": "2026-01-25T14:30:00Z"
}
```

---

#### GET /tokens/{token_id}

Get token details

**Response:**
```json
{
  "id": "tok_12345",
  "process_name": "notepad.exe",
  "issued_at": "2026-01-25T12:00:00Z",
  "expires_at": "2026-01-25T13:00:00Z",
  "status": "valid",
  "hardware_bound": true,
  "allowed_paths": ["C:\\Users\\*\\Documents"],
  "allowed_operations": ["read", "write"],
  "threat_detections": 0
}
```

---

#### POST /tokens/generate

Generate a new access token

**Request:**
```json
{
  "process_path": "C:\\Program Files\\MyApp\\app.exe",
  "allowed_paths": ["C:\\Users\\*\\Documents\\MyApp\\*"],
  "allowed_operations": ["read", "write"],
  "lifetime_seconds": 3600,
  "require_tpm": true,
  "require_fingerprint": true
}
```

**Response:**
```json
{
  "token": "eyJ...(base64 encoded token)...ZQ==",
  "id": "tok_12346",
  "expires_in_seconds": 3600,
  "algorithm": "Ed25519"
}
```

---

#### GET /workstations

List connected workstations

**Response:**
```json
{
  "workstations": [
    {
      "id": "ws_001",
      "hostname": "WORKSTATION-01",
      "os": "Windows 11",
      "driver_version": "1.0.0",
      "last_contact": "2026-01-25T14:25:00Z",
      "status": "online",
      "threat_level": "low",
      "events_24h": 12
    }
  ]
}
```

---

#### POST /incident/quarantine

Quarantine a file immediately

**Request:**
```json
{
  "file_path": "C:\\Users\\User\\Downloads\\suspicious.exe",
  "reason": "Ransomware signature match"
}
```

**Response:**
```json
{
  "status": "quarantined",
  "quarantine_location": "C:\\ProgramData\\AntiRansomware\\Quarantine\\suspicious_12345.exe",
  "evidence_id": "evt_12345"
}
```

---

## Python SDK

### Installation

```bash
pip install antiransomware-sdk
```

### Basic Usage

```python
from antiransomware import TokenManager, PolicyEngine, ThreatAnalyzer

# Initialize token manager
token_mgr = TokenManager(admin_server="https://admin:5000")

# Generate token
token = token_mgr.generate(
    process_path="C:\\Program Files\\MyApp\\app.exe",
    allowed_paths=["C:\\Users\\*\\Documents\\*"],
    allowed_operations=["read", "write"],
    lifetime_seconds=3600
)

print(f"Token: {token.token_string}")
print(f"Expires: {token.expires_at}")

# Validate token
result = token_mgr.validate(token.token_string)
if result.is_valid:
    print("Token is valid")
else:
    print(f"Token invalid: {result.reason}")
```

---

### Token Management

```python
from antiransomware import TokenManager

mgr = TokenManager()

# Generate with TPM binding
token = mgr.generate(
    process_path="app.exe",
    require_tpm=True,
    require_fingerprint=True
)

# Check token status
status = mgr.get_token_status(token.id)
print(f"Status: {status.status}")
print(f"Threat detections: {status.threat_detections}")

# Revoke token
mgr.revoke(token.id)
```

---

### Policy Management

```python
from antiransomware import PolicyEngine

policy = PolicyEngine(admin_server="https://admin:5000")

# Create protection policy
policy.create(
    name="Critical Files",
    paths=["C:\\Users\\*\\Documents"],
    level="critical",
    require_token=True,
    block_extensions=[".exe", ".bat"]
)

# List policies
policies = policy.list_all()
for p in policies:
    print(f"{p.name}: {p.paths}")

# Update policy
policy.update("Critical Files", active=True)

# Delete policy
policy.delete("Critical Files")
```

---

### Threat Analysis

```python
from antiransomware import ThreatAnalyzer

analyzer = ThreatAnalyzer()

# Get threat score for file
score = analyzer.get_threat_score("C:\\Users\\User\\file.docx")
print(f"Threat score: {score.score}/100")
print(f"Threats: {score.threat_types}")

# Analyze process
proc_threat = analyzer.analyze_process("ransomware.exe")
if proc_threat.is_suspicious():
    print("Process is suspicious!")
    print(f"Indicators: {proc_threat.indicators}")
```

---

### Event Monitoring

```python
from antiransomware import EventManager

events = EventManager(admin_server="https://admin:5000")

# Get recent events
recent = events.get(
    limit=100,
    severity="high",
    since="2026-01-25T12:00:00Z"
)

for event in recent:
    print(f"{event.timestamp}: {event.type}")
    print(f"  Process: {event.process_name}")
    print(f"  File: {event.file_path}")
    print(f"  Action: {event.action_taken}")

# Stream events in real-time
for event in events.stream():
    print(f"Event: {event.type}")
```

---

### Example: Build Integration

```python
#!/usr/bin/env python3
"""
Integrate Anti-Ransomware token generation into build pipeline
"""

from antiransomware import TokenManager
import subprocess
import json

# Initialize token manager
token_mgr = TokenManager(admin_server="https://build-admin:5000")

# Generate token for build process
build_token = token_mgr.generate(
    process_path="C:\\Program Files\\BuildTools\\msbuild.exe",
    allowed_paths=[
        "C:\\BuildOutput\\*",
        "C:\\Users\\BuildService\\AppData\\Local\\*"
    ],
    allowed_operations=["read", "write", "delete"],
    lifetime_seconds=7200  # 2 hours
)

print(f"Generated build token: {build_token.id}")

# Save token to environment
with open(".build_token.json", "w") as f:
    json.dump({
        "token": build_token.token_string,
        "expires": build_token.expires_at.isoformat()
    }, f)

# Run build with protection
result = subprocess.run([
    "msbuild.exe",
    "project.vcxproj",
    "/p:AntiRansomwareToken=" + build_token.token_string
])

if result.returncode != 0:
    print("Build failed")
    token_mgr.revoke(build_token.id)
else:
    print("Build succeeded")

# Cleanup
import os
os.remove(".build_token.json")
```

---

## Error Handling

### Common Error Codes

| Code | Status | Meaning |
|------|--------|---------|
| 0 | Success | Operation completed |
| 1 | INVALID_TOKEN | Token format or signature invalid |
| 2 | TOKEN_EXPIRED | Token lifetime exceeded |
| 3 | HARDWARE_MISMATCH | Device fingerprint doesn't match |
| 4 | TPM_ATTESTATION_FAILED | TPM verification failed |
| 5 | PATH_DENIED | Operation not allowed for this path |
| 6 | OPERATION_DENIED | Operation type not permitted |
| 7 | THREAT_DETECTED | Suspicious activity detected |
| 8 | DRIVER_ERROR | Kernel driver error |
| 9 | NETWORK_ERROR | Can't reach admin server |
| 10 | DATABASE_ERROR | Backend database error |

### Error Response Example

```json
{
  "error": {
    "code": 2,
    "status": "TOKEN_EXPIRED",
    "message": "Token expired at 2026-01-25T13:00:00Z",
    "timestamp": "2026-01-25T14:30:00Z"
  }
}
```

---

## Rate Limiting

API requests are rate-limited to:
- **100 requests/minute** per client
- **1000 requests/minute** per token

When rate limit exceeded:
```json
{
  "error": {
    "code": 429,
    "status": "RATE_LIMITED",
    "retry_after_seconds": 60
  }
}
```

---

## Backward Compatibility

The API maintains backward compatibility within major versions:
- v1.x: Current stable API
- Breaking changes: Reserved for v2.0+
- Deprecations announced 2 releases in advance

---

**Next:** [Operations Guide](./guides/operations)
