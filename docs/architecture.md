---
layout: default
title: Architecture & Design
---

# System Architecture

## Overview

The Anti-Ransomware Platform is built on a three-tier architecture:

1. **Kernel Layer** — Real-time file system monitoring
2. **User-Mode Layer** — Token validation and policy enforcement
3. **Admin Layer** — Centralized management and threat response

---

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Admin Dashboard                           │
│  ┌────────────────┐  ┌──────────────┐  ┌───────────────┐   │
│  │  Policy UI     │  │ Threat View  │  │ Audit Logs    │   │
│  └────────────────┘  └──────────────┘  └───────────────┘   │
└────────────────────┬──────────────────────────────────────┘
                     │ gRPC / REST APIs
┌────────────────────▼──────────────────────────────────────┐
│           User-Mode Security Manager                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Token Validation Service                            │   │
│  │  • Ed25519/Dilithium signature verification        │   │
│  │  • Hardware fingerprint matching                   │   │
│  │  • TPM attestation                                 │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Policy Engine                                       │   │
│  │  • Access control evaluation                       │   │
│  │  • Path confinement                                │   │
│  │  • Operation-level permissions                     │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Behavioral Analysis                                 │   │
│  │  • Threat scoring                                  │   │
│  │  • Pattern matching                                │   │
│  │  • Anomaly detection                               │   │
│  └─────────────────────────────────────────────────────┘   │
└────────────────────┬──────────────────────────────────────┘
                     │ IOCTL Interface
┌────────────────────▼──────────────────────────────────────┐
│            Kernel Minifilter Driver                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ File System Interception                            │   │
│  │  • Pre/post operation callbacks                     │   │
│  │  • Real-time access decisions                       │   │
│  │  • File hash computation                            │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Access Control Enforcement                          │   │
│  │  • Operation blocking                               │   │
│  │  • Request validation                               │   │
│  │  • Audit event generation                           │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Protection Logic                                    │   │
│  │  • Encrypted file monitoring                        │   │
│  │  • Extension-based detection                        │   │
│  │  • Quarantine triggering                            │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Data Flow: File Access Request

```
1. User/Application attempts file operation
                    │
                    ▼
2. Kernel Minifilter intercepts (pre-operation)
   ├─ Captures: Process ID, File Path, Operation Type
   ├─ Computes: File Hash
                    │
                    ▼
3. Query User-Mode Manager (IOCTL)
   ├─ Validate token
   ├─ Verify hardware fingerprint
   ├─ Check TPM attestation
                    │
                    ▼
4. Policy Engine Evaluation
   ├─ Lookup protection policy for path
   ├─ Evaluate access control rules
   ├─ Check operation permissions
                    │
                    ▼
5. Behavioral Analysis
   ├─ Compute threat score
   ├─ Pattern matching against signatures
   ├─ Anomaly detection from baseline
                    │
                    ▼
6. Decision & Action
   ├─ ALLOW: Permit operation to complete
   ├─ BLOCK: Reject operation
   ├─ QUARANTINE: Copy file and block
   ├─ ALERT: Notify admin dashboard
                    │
                    ▼
7. Audit Event Logged
   └─ Stored for compliance & investigation
```

---

## Token-Gating Mechanism

### Token Structure

```c
struct TokenPayload {
    uint32_t version;           // Token format version
    uint32_t process_id;        // Authorized process ID
    uint64_t issued_timestamp;  // Creation time
    uint64_t expiry_timestamp;  // Expiration time
    
    uint8_t hardware_fingerprint[32];  // Device identity
    uint8_t tpm_nonce[16];              // TPM attestation
    
    char allowed_paths[256];    // Path confinement (glob patterns)
    uint32_t allowed_ops;       // Bitmask: READ|WRITE|DELETE|RENAME
    
    uint8_t ed25519_sig[64];    // Primary signature (Ed25519)
    uint8_t dilithium_sig[2420]; // Post-quantum backup (Dilithium)
};
```

### Validation Pipeline

```
Token Received
      │
      ├─► Check Expiry Time
      │   ├─ VALID: Continue
      │   └─ EXPIRED: REJECT
      │
      ├─► Verify Cryptographic Signature
      │   ├─ Try Ed25519 first (faster)
      │   ├─ Fall back to Dilithium if needed
      │   └─ INVALID: REJECT
      │
      ├─► Match Hardware Fingerprint
      │   ├─ Compute current device fingerprint
      │   ├─ Compare with token fingerprint
      │   └─ MISMATCH: REJECT
      │
      ├─► Validate TPM Attestation
      │   ├─ Query TPM for current measurements
      │   ├─ Match against token nonce
      │   └─ INVALID: REJECT
      │
      ├─► Check Path Confinement
      │   ├─ Match file path against allowed_paths
      │   └─ NOT ALLOWED: REJECT
      │
      └─► Verify Operation Permission
          ├─ Check if operation in allowed_ops
          └─ NOT PERMITTED: REJECT

RESULT: ALLOW or DENY
```

---

## Protection Policies

### Policy Types

**1. Path-Based Protection**
```
Path: C:\Users\*\Documents
- Allow read by: Office.exe, AdobeReader.exe
- Block write to: *.exe, *.bat, *.ps1
- Quarantine: Double encryption, suspicious extensions
```

**2. Service-Based Protection**
```
Service: SQL Server (sqlservr.exe)
- Token required for: Write, Delete, Truncate
- Allowed database paths: C:\ProgramData\MSSQL
- Disallowed operations: Move, Rename (outside service scope)
```

**3. Behavioral Policies**
```
Threat Level: High
- Encrypted file writes: Alert and block
- Rapid file deletion (>100 files/min): Quarantine
- File extension changes: Investigate
- Registry modifications (HKLM): Block
```

---

## Hardware Binding

### Device Fingerprinting

The system creates a unique fingerprint combining:

```
├─ TPM Platform Configuration Registers (PCR)
│  └─ System firmware + bootloader integrity
├─ Machine GUID (Windows registry)
├─ Network adapters (MAC addresses)
├─ Disk serial numbers
├─ CPU identifier
├─ BIOS version
└─ Motherboard serial number
    ↓
SHA-256 → 32-byte Fingerprint
```

This fingerprint is:
- **Immutable** without hardware changes
- **Unique** per system
- **Cryptographically bound** to tokens
- **Verified at every access**

### TPM Attestation

```
User-Mode Manager
      │
      └─► Query TPM 2.0
          ├─ Get Platform Configuration Registers (PCRs)
          ├─ Get System Log (firmware/OS integrity)
          └─ Return signed attestation
              │
              ▼
          Compare with Token Nonce
          ├─ Match: Continue
          └─ Mismatch: BLOCK
```

---

## Threat Detection Pipeline

### 1. Signature-Based Detection
```
File Hash Computed
      │
      └─► SHA-256 Hash
          │
          └─► Check Against Threat Database
              ├─ Known ransomware signatures
              ├─ Malicious hash lists
              └─ Community threat intelligence
                  │
                  ├─ Match: QUARANTINE
                  └─ No Match: Continue
```

### 2. Behavioral Detection
```
File Access Pattern
      │
      ├─► Extract Features
      │   ├─ Process: name, PID, memory usage
      │   ├─ Operation: type, frequency, volume
      │   ├─ Target: file type, location, age
      │   └─ Time: burst patterns, off-hours access
      │
      ├─► Compute Threat Score
      │   ├─ Baseline learning from initial 24 hours
      │   ├─ Anomaly scoring (deviation from normal)
      │   └─ Malware indicators (known attack patterns)
      │
      └─► Decision
          ├─ Score < 30: ALLOW
          ├─ Score 30-70: ALERT
          └─ Score > 70: QUARANTINE
```

### 3. Extension-Based Detection
```
File being written with suspicious extension
      │
      ├─► Is it ransomware indicator?
      │   ├─ .locked, .crypt, .encrypted, etc.
      │   ├─ Double encryption (.docx.crypt)
      │   └─ Unusual combinations (.txt.exe)
      │
      └─► Action
          ├─ Known bad extension: BLOCK + QUARANTINE
          └─ Suspicious pattern: ALERT + MONITOR
```

---

## Cryptography

### Token Signing

**Primary: Ed25519**
- Fast signature verification (~1.2ms)
- Secure against known attacks
- Used for normal operations

**Fallback: CRYSTALS-Dilithium**
- Post-quantum resistant
- Larger signatures (2.42 KB)
- Used if Ed25519 ever compromised
- Automatically validates both

### Hardware Protection

- **TPM 2.0:** Secure key storage, attestation
- **Fingerprinting:** Unique per-device binding
- **Nonce:** One-time values prevent replay attacks

---

## Performance Considerations

### Kernel Driver Optimization
- **Inline caching** for frequently accessed paths
- **Parallel processing** for independent checks
- **Lazy evaluation** of expensive operations
- **Batching** of event notifications

### Typical Latency
- File open: **0.5-1.5 ms** overhead
- File write: **1-3 ms** overhead
- Signature verification: **< 1 ms**
- Hash computation: Varies by file size

### Memory Usage
- Driver: ~5 MB
- User-mode service: ~50 MB
- Per-policy cache: ~1 MB per 1000 rules

---

## Deployment Models

### Single Host
```
┌─────────────────┐
│ Workstation     │
├─────────────────┤
│ Driver          │
│ Manager Service │
│ Local Dashboard │
└─────────────────┘
```

### Enterprise (Centralized)
```
┌──────────────────┐         ┌──────────────────┐
│ Workstation 1    │         │ Admin Server     │
├──────────────────┤         ├──────────────────┤
│ Driver           │◄───────►│ Dashboard        │
│ Manager (thin)   │ gRPC    │ Policy Engine    │
└──────────────────┘         │ Audit Database   │
                             └──────────────────┘
         │                         ▲
         ├─ Workstation 2          │
         │                         │
         └─ Workstation N ─────────┘
```

---

**Next:** [Quick Start Guide](guides/quickstart)
