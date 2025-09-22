# Anti-Ransomware Folder: Architecture Overview

## System Components

- **Kernel Driver (Windows, Linux, macOS)**
  - Per-handle gate for write/rename/delete/truncate
  - Token verification (Ed25519/Dilithium)
  - Zero-copy token cache
- **User-Space Broker**
  - gRPC/REST API for token requests
  - Policy engine (YAML/JSON)
  - Hardware dongle interface (USB CCID)
- **Hardware Root of Trust**
  - USB smart-card (YubiKey, NitroKey, etc.)
  - FIDO2/PIV/OpenPGP applet
- **Admin Dashboard**
  - Policy management
  - SIEM/syslog integration
  - Live monitoring

## Data Flow

1. **App requests write access to protected folder**
2. **Kernel driver intercepts file operation**
3. **Driver checks for valid token attached to file handle**
4. **If missing/expired, driver requests token from broker**
5. **Broker prompts user for dongle + PIN/touch**
6. **Dongle signs token, broker returns to driver**
7. **Driver attaches token to file handle, allows access**
8. **Token expires or dongle removed → access revoked**

## Trust Boundaries

- **Kernel ↔ Broker**: Secure IPC (local socket, named pipe)
- **Broker ↔ Dongle**: USB CCID protocol
- **Broker ↔ Admin Dashboard**: gRPC/REST over TLS
- **Driver ↔ Policy Engine**: Signed policy files

## Platform-Specific Notes

- **Windows**: FltMgr minifilter, PPL protection, TPM integration
- **Linux**: LSM module, IMA/SELinux, TPM
- **macOS**: EndpointSecurity, notarization, hardened runtime

---

## Diagram (Block Format)

[User App]
    |
[Kernel Driver] <----> [User-Space Broker] <----> [USB Dongle]
    |                        |
[Policy Engine]         [Admin Dashboard]

- All file operations gated by kernel driver
- Broker mediates token requests and policy enforcement
- Hardware dongle provides root of trust for signatures
- Admin dashboard manages policies, keys, and monitoring
