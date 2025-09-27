# Immune Folders - Ransomware-Proof File Protection

## Overview
Immune Folders provides **true ransomware immunity** through encrypted containers that are only mounted when authorized. Unlike traditional "protection" that can be bypassed, immune folders are **literally inaccessible** when locked - ransomware cannot encrypt what it cannot see.

## Core Security Principles

1. **Default Locked**: Folders are encrypted containers, unmounted by default
2. **Two-Factor Unlock**: USB token + optional PIN/biometrics 
3. **Auto-Lock**: Automatic dismount on inactivity
4. **Recovery by Design**: QR codes + passphrase for token loss
5. **Tamper Evidence**: Hash-chained audit logs
6. **No Admin Bypasses**: Even administrators cannot access locked folders

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   USB Token     │    │   Immune Service │    │  VeraCrypt      │
│  (FMK wrapped)  │───▶│   (Windows Svc)  │───▶│  Container      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                               │
                       ┌──────────────────┐
                       │   Audit Chain    │
                       │  (tamper-proof)  │
                       └──────────────────┘
```

## Trust Model

- **Folder Master Key (FMK)**: 256-bit key that encrypts the container
- **USB Token**: Contains FMK wrapped with device-bound key (DPAPI/TPM)
- **Recovery QR**: Contains FMK shares or password-wrapped FMK
- **No Plaintext Storage**: FMK never stored in plaintext on disk

## Protection Levels

| Attack Vector | Traditional AV | Admin-Proof ACLs | Immune Folders |
|---------------|----------------|-------------------|----------------|
| File Encryption | ⚠️ Detection | ❌ Bypassable | ✅ **Impossible** |
| Process Injection | ⚠️ Heuristics | ❌ Token Bypass | ✅ **Impossible** |
| Admin Privileges | ❌ No Protection | ❌ Brittle ACLs | ✅ **Cryptographic** |
| Zero-Day Ransomware | ❌ Unknown Signatures | ❌ Logic Flaws | ✅ **Math-Based** |

## Quick Start

1. **Install Service**: `.\infra\installer.ps1`
2. **Create Immune Folder**: Select folder, insert USB, set PIN
3. **Use Normally**: Auto-unlocks with USB, auto-locks on idle
4. **Print Recovery QR**: Keep QR code + passphrase in safe place

## Recovery Scenario

**Lost USB Token?**
1. Boot from recovery media (if needed)
2. Scan QR code with phone/camera
3. Enter recovery passphrase
4. System generates new USB token
5. Print new QR code

**Ransomware Attack?**
- Immune folders remain encrypted and inaccessible
- Ransomware cannot touch what it cannot see
- Files are mathematically protected, not just "hidden"
