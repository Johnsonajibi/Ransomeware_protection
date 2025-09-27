# Threat Model - Immune Folders

## Threat Actors

### 1. Ransomware Families
- **Capability**: File encryption, process injection, privilege escalation
- **Motivation**: Financial gain through encryption and extortion
- **Attack Vectors**: Email attachments, drive-by downloads, supply chain

### 2. Insider Threats
- **Capability**: Physical access, legitimate credentials, admin privileges
- **Motivation**: Data theft, sabotage, financial gain
- **Attack Vectors**: USB insertion, credential abuse, social engineering

### 3. Advanced Persistent Threats (APTs)
- **Capability**: Zero-day exploits, custom malware, living-off-the-land
- **Motivation**: Espionage, intellectual property theft, disruption
- **Attack Vectors**: Spear phishing, watering holes, supply chain compromise

## Attack Scenarios

### Scenario 1: Traditional Ransomware
**Attack**: WannaCry-style encryption of all accessible files
**Defense**: Immune folders are dismounted → inaccessible → cannot be encrypted
**Result**: ✅ **Immune folders protected**, system recoverable

### Scenario 2: Admin-Level Ransomware  
**Attack**: Malware gains SYSTEM privileges, disables security software
**Defense**: Even SYSTEM cannot access unmounted encrypted containers
**Result**: ✅ **Cryptographic protection**, no admin bypasses possible

### Scenario 3: USB Token Theft
**Attack**: Physical theft of USB token by insider
**Defense**: Device-bound keys (DPAPI/TPM) prevent use on other machines
**Result**: ✅ **Token useless** on attacker's machine

### Scenario 4: Coercion/Rubber Hose
**Attack**: Physical coercion to unlock immune folders
**Defense**: Recovery process requires multiple factors (QR + passphrase)
**Result**: ⚠️ **Physical security limits**, duress features possible

### Scenario 5: Supply Chain Compromise
**Attack**: Malicious update to immune folders software
**Defense**: Code signing, hash verification, minimal attack surface
**Result**: ✅ **Signed components**, isolated crypto operations

## Security Assumptions

### What We MUST Trust
1. **Hardware Security**: TPM/DPAPI implementation
2. **OS Integrity**: Windows kernel and crypto APIs
3. **VeraCrypt**: Container encryption implementation
4. **Physical Security**: USB token storage location

### What We DO NOT Trust
1. **User Applications**: All user-mode software is potentially compromised
2. **Admin Processes**: Even elevated processes cannot bypass crypto
3. **Network**: All network communication is monitored/intercepted
4. **File System**: NTFS permissions can be manipulated

## Cryptographic Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED CRYPTO CORE                     │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │     FMK     │  │    DPAPI     │  │   VeraCrypt     │   │
│  │  (256-bit)  │  │  (TPM/HW)    │  │  (AES-256)      │   │
│  └─────────────┘  └──────────────┘  └─────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                           │
                    TRUST BOUNDARY
                           │
┌─────────────────────────────────────────────────────────────┐
│                     UNTRUSTED ZONE                         │
│  • All user applications                                   │
│  • Admin processes                                         │
│  • Network services                                        │
│  • File system permissions                                 │
└─────────────────────────────────────────────────────────────┘
```

## Residual Risks

### High Priority
- **Physical coercion**: Cannot defend against torture/threats
- **Hardware compromise**: Compromised TPM/motherboard
- **Quantum computing**: Future threat to AES-256

### Medium Priority  
- **Implementation bugs**: Coding errors in crypto handling
- **Side-channel attacks**: Timing/power analysis during unlock
- **Social engineering**: Tricking users into unlock procedures

### Low Priority
- **Brute force attacks**: 256-bit keys are computationally infeasible
- **Cryptanalytic attacks**: AES-256 considered quantum-resistant for decades
- **Zero-day OS exploits**: Cannot bypass cryptographic boundaries

## Mitigation Strategies

### Immediate
1. **Minimize unlock time**: Auto-lock after short idle periods
2. **Audit everything**: Tamper-evident logs for all operations
3. **Recovery planning**: Multiple independent recovery methods
4. **User training**: Recognize social engineering attempts

### Future Enhancements
1. **Hardware security modules**: Dedicated crypto processors
2. **Duress codes**: Different unlock codes for coercion scenarios
3. **Remote wipe**: Emergency destruction of keys via authenticated signal
4. **Quantum-resistant crypto**: Post-quantum cryptographic algorithms
