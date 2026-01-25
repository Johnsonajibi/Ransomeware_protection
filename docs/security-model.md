---
layout: default
title: Security Model
---

# Security Model

Understanding threat protection, attack surfaces, and trust boundaries.

---

## Threat Model

### Assets We Protect

1. **User Data** — Documents, photos, databases, source code
2. **System Integrity** — OS files, configurations, registry
3. **Intellectual Property** — Proprietary files, trade secrets
4. **Business Continuity** — Critical services availability

### Threat Actors

| Threat Actor | Capability | Motivation | Attack Vector |
|--------------|-----------|-----------|---|
| **Script Kiddie** | Low | Vandalism | Exploit tools, worms |
| **Opportunistic Malware** | Medium | Financial | Spam, credential theft |
| **Targeted Ransomware** | High | Financial | Spear-phishing, exploits |
| **Nation-State APT** | Critical | Espionage | Supply chain, 0-days |

### Attack Scenarios We Address

#### Scenario 1: Ransomware Execution
```
Attacker sends phishing email
    ↓
User clicks link / opens attachment
    ↓
Ransomware executable runs
    ↓
[INTERCEPTED BY KERNEL DRIVER]
    ↓
Suspicious behavior detected
    ↓
File modification BLOCKED
    ↓
User alerted, threat quarantined
```

#### Scenario 2: Privilege Escalation
```
Local attacker gains user privileges
    ↓
Attempts to modify protected files
    ↓
[TOKEN VALIDATION FAILS]
    ↓
Hardware fingerprint mismatch
    ↓
TPM attestation fails
    ↓
Access DENIED
```

#### Scenario 3: Supply Chain Attack
```
Legitimate software compromised
    ↓
Updates software on system
    ↓
Modified binary attempts file access
    ↓
[BEHAVIORAL ANALYSIS TRIGGERS]
    ↓
Threat score exceeds threshold
    ↓
Process quarantined immediately
```

---

## Trust Boundaries

### System Trust Zones

```
┌─────────────────────────────────────────────────┐
│ Zone 1: Kernel Space (HIGHEST TRUST)            │
│  ✓ Minifilter driver                            │
│  ✓ TPM interactions                             │
│  ✓ Hardware enforcement                         │
│ [ISOLATED FROM USER SPACE]                      │
└──────────────────┬──────────────────────────────┘
                   │ IOCTL Interface (Validated)
┌──────────────────▼──────────────────────────────┐
│ Zone 2: Privileged Service (HIGH TRUST)         │
│  ✓ User-mode manager (SYSTEM account)           │
│  ✓ Token validation                             │
│  ✓ Policy engine                                │
│ [PROTECTED FROM USER INTERFERENCE]              │
└──────────────────┬──────────────────────────────┘
                   │ Named Pipes (Authenticated)
┌──────────────────▼──────────────────────────────┐
│ Zone 3: Dashboard (MEDIUM TRUST)                │
│  ✓ Admin interface (local or authenticated)     │
│  ✓ Policy configuration                         │
│  ✓ Event viewing                                │
│ [RESTRICTED TO ADMINISTRATORS]                  │
└──────────────────┬──────────────────────────────┘
                   │ Local/Network Access
┌──────────────────▼──────────────────────────────┐
│ Zone 4: User Space (LOW TRUST)                  │
│  ✗ Untrusted applications                       │
│  ✗ Downloaded files                             │
│  ✗ External inputs                              │
└─────────────────────────────────────────────────┘
```

### Token Trust Verification

```
Token Received
    ├─► Cryptographic Signature
    │   └─ Ed25519 or Dilithium
    │       (Can't forge without private key)
    │
    ├─► Expiration Time
    │   └─ Must be valid at present time
    │       (Can't use expired token)
    │
    ├─► Hardware Fingerprint
    │   └─ Must match current device
    │       (Can't move token to other machine)
    │
    ├─► TPM Attestation
    │   └─ Must match TPM state
    │       (Can't bypass hardware checks)
    │
    └─► Path/Operation Constraints
        └─ Must match file operation
            (Can't exceed authorization scope)

ALL must pass → ACCESS ALLOWED
ANY fails → ACCESS DENIED
```

---

## Attack Surface Analysis

### External Attack Surface

| Component | Attack Vector | Mitigation |
|-----------|---|---|
| Network Interface | Man-in-the-middle | TLS encryption, certificate pinning |
| Admin Dashboard | Authentication bypass | Multi-factor auth, session tokens |
| Policy API | Malicious configuration | Policy validation, signed updates |
| Log collection | Log tampering | Cryptographic signing, immutable storage |

### Internal Attack Surface

| Component | Attack Vector | Mitigation |
|-----------|---|---|
| Kernel Driver | IOCTL abuse | Input validation, privilege checks |
| Token System | Token forgery | Cryptographic signing, short lifetime |
| Device Fingerprint | Spoofing | TPM binding, hardware measurement |
| Policy Cache | Cache poisoning | Frequent revalidation, checksums |

### Physical Attack Surface

| Threat | Impact | Mitigation |
|--------|--------|-----------|
| USB debugging enabled | Full system access | Require attestation at boot |
| Firmware modification | Driver bypass | TPM PCR checking |
| Hardware theft | Token extraction | Hardware binding, short lifetimes |
| Disk access (offline) | Encryption bypass | Enable disk encryption (BitLocker) |

---

## Cryptographic Security

### Algorithm Selection

**Ed25519 (Primary)**
```
- Key size: 256-bit (32 bytes)
- Signature size: 512-bit (64 bytes)
- Speed: ~1.2ms for signature verification
- Security: 128-bit strength
- Quantum: Vulnerable to quantum computing
- Use: Fast path, normal operations
```

**CRYSTALS-Dilithium (Backup)**
```
- Key size: 1952 bytes
- Signature size: 2420 bytes
- Speed: ~2.5ms for signature verification
- Security: 128-bit (equivalent)
- Quantum: Resistant to quantum computing
- Use: Future-proofing, emergency mode
```

### Key Management

```
┌─────────────────────────────────┐
│ Key Generation                  │
│ - Done on isolated system       │
│ - Air-gapped from network       │
│ - Hardcopy backup stored safely │
└──────────┬──────────────────────┘
           │
           ▼
┌─────────────────────────────────┐
│ Key Storage                     │
│ - Private keys: TPM only        │
│ - Public keys: Distributed      │
│ - Never on disk in plaintext    │
└──────────┬──────────────────────┘
           │
           ▼
┌─────────────────────────────────┐
│ Key Rotation                    │
│ - Annual rotation schedule      │
│ - Emergency rotation available  │
│ - Old keys kept for revocation  │
└─────────────────────────────────┘
```

---

## Authentication & Authorization

### Multi-Layer Authentication

```
User attempts to configure protection
    │
    ├─► Windows Authentication
    │   └─ Must be Windows domain user / admin
    │
    ├─► Application-Level Auth
    │   └─ Must provide credentials again
    │
    ├─► Session Token
    │   └─ Issued with limited lifetime
    │
    ├─► TLS Certificate Pinning
    │   └─ Dashboard communication encrypted
    │
    └─► Operation Logging
        └─ All admin actions logged + signed

ALL layers pass → Operation allowed
```

### Role-Based Access Control (RBAC)

```json
{
  "roles": {
    "viewer": {
      "permissions": ["read:events", "read:dashboard"]
    },
    "operator": {
      "permissions": ["read:*", "write:policies", "manage:tokens"]
    },
    "administrator": {
      "permissions": ["*"]
    }
  }
}
```

---

## Defense in Depth

### Layer 1: Prevention
- Hardware-gated token validation
- Path confinement enforcement
- Operation-level granularity
- Real-time kernel interception

### Layer 2: Detection
- Behavioral analysis
- Threat scoring
- Pattern matching
- Anomaly detection

### Layer 3: Response
- Immediate access denial
- File quarantine
- Process termination
- Admin notification

### Layer 4: Recovery
- Backup integration
- Point-in-time restore
- Forensic analysis
- Event audit trail

### Layer 5: Forensics
- Complete event logging
- Cryptographic signatures
- Immutable storage
- Compliance reporting

---

## Assumptions & Limitations

### Assumptions We Make

✓ Windows kernel is secure (unpatchable vulnerabilities rare)
✓ TPM implementation is correct (NIST validated modules)
✓ Private keys never leaked (proper key management)
✓ Bitlocker or equivalent enabled (offline disk protection)
✓ BIOS/UEFI is not modified (validated via TPM)

### What We Cannot Protect Against

✗ **Unpatched OS vulnerabilities** — Requires OS security updates
✗ **Compromised BIOS** — Requires secure boot + firmware updates
✗ **Physical hardware theft** — Requires encryption + device tracking
✗ **Insider threats** — Requires RBAC + audit logging + monitoring
✗ **Quantum computing (far future)** — Addressed via Dilithium support

---

## Incident Response

### Threat Detection Levels

```
Level 1: Anomaly
- Unusual file access pattern
- Action: ALERT admin, continue monitoring

Level 2: Suspicious
- Multiple suspicious indicators
- Action: ALERT admin, prepare quarantine

Level 3: Critical
- High confidence ransomware behavior
- Action: QUARANTINE file, BLOCK process, NOTIFY admin

Level 4: System Compromise
- Kernel-level threats detected
- Action: ISOLATE system, ALERT security team
```

### Response Procedures

When threat detected:
```
1. Immediately:
   - Block further file modifications
   - Quarantine suspicious files
   - Log all context

2. Short-term (minutes):
   - Notify administrators
   - Isolate affected workstation
   - Preserve forensic evidence

3. Medium-term (hours):
   - Analyze incident
   - Identify attack vector
   - Coordinate restore

4. Long-term (days):
   - Full forensic analysis
   - Identify root cause
   - Implement hardening
   - Update threat intelligence
```

---

## Compliance & Standards

### Standards Addressed

- **NIST Cybersecurity Framework** — Risk management
- **CIS Controls** — Prevention + detection
- **ISO 27001** — Information security management
- **SOC 2** — Audit trail + access control
- **HIPAA** — Encryption + audit logging
- **PCI-DSS** — Access control + logging

### Audit Trail

Every security-relevant action is logged:

```json
{
  "timestamp": "2026-01-25T14:23:45Z",
  "event_type": "FILE_WRITE_BLOCKED",
  "source": "kernel_driver",
  
  "process": {
    "pid": 2840,
    "name": "ransomware.exe",
    "path": "C:\\Temp\\malware.exe"
  },
  
  "target": {
    "path": "C:\\Users\\User\\Documents\\data.docx",
    "operation": "WRITE",
    "size_bytes": 1024000
  },
  
  "decision": {
    "allowed": false,
    "reason": "THREAT_DETECTED",
    "threat_score": 95,
    "threat_type": "RANSOMWARE_ENCRYPTION"
  },
  
  "token_validation": {
    "token_present": false,
    "hardware_match": null
  }
}
```

---

## Hardening Guide

### System Hardening Checklist

- [ ] Enable Windows Defender (in addition to this system)
- [ ] Enable BitLocker full disk encryption
- [ ] Configure Windows Firewall appropriately
- [ ] Enable Windows Update auto-patching
- [ ] Disable unnecessary services
- [ ] Implement strong password policy
- [ ] Enable multi-factor authentication
- [ ] Configure audit logging
- [ ] Regular security patching
- [ ] Annual security review

### Configuration Hardening

```yaml
# hardening.yaml
kernel_driver:
  disable_user_mode_override: true
  require_tpm: true
  signature_algorithm: dilithium  # Use post-quantum

token_policy:
  max_lifetime_seconds: 3600  # 1 hour
  require_tpm: true
  require_device_fingerprint: true
  
policy_engine:
  enforce_strict_validation: true
  deny_by_default: true  # Whitelist approach
  
audit_logging:
  log_all_decisions: true
  immutable_logging: true
  retention_days: 365
```

---

## Testing Security

### Penetration Testing Checklist

- [ ] Attempt token forgery
- [ ] Try to move token to different machine
- [ ] Attempt to use expired tokens
- [ ] Try signature bypass via tampering
- [ ] Attempt hardware fingerprint spoofing
- [ ] Test TPM attestation validation
- [ ] Try IOCTL command injection
- [ ] Test policy bypass attempts
- [ ] Attempt cache poisoning
- [ ] Try privilege escalation

---

**Next:** [API Reference](../api-reference)
