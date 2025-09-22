# Hardware Root of Trust & Cryptographic Agility

## Hardware Root of Trust
- USB CCID smart-card (YubiKey 5C, NitroKey 3, SafeNet 5110, etc.)
- Private key generated on-chip; never exportable
- Supports FIDO2, PIV, OpenPGP applets (no custom firmware required)
- Optional PIN or biometric touch for every signature
- Multi-key whitelist: driver supports multiple dongles, revocation list pushed via policy

## Integration Flow
1. Broker detects USB dongle via CCID
2. Broker requests signature from dongle (FIDO2/PIV/OpenPGP)
3. Dongle prompts user for PIN/touch
4. Dongle signs token; broker returns signed token to kernel driver
5. Driver verifies token using public key (baked into driver or loaded from policy)

## Cryptographic Agility
- Dual-stack: Ed25519 (current), CRYSTALS-Dilithium-3 (ML-DSA, PQC)
- Hybrid mode: sign and verify with both algorithms
- FIPS 204 compliance (when finalized)
- Kernel verification uses open-source assembly (Linux crypto API, Windows CNG, macOS CTK)

## Example Python Broker Integration (YubiKey)
```python
from yubikit.piv import PivSession
from yubikit.management import ManagementSession
from yubikit.core.smartcard import SmartCardConnection
from yubikit.core import YubiKey

# Detect YubiKey
connection = SmartCardConnection()
yk = YubiKey(connection)
piv = PivSession(connection)

# Request signature
data = b"token_data_to_sign"
sig = piv.sign(0x9A, data, hash_algorithm="SHA256")
```

## Example Token Verification (Ed25519)
```python
import nacl.signing
import nacl.encoding

verify_key = nacl.signing.VerifyKey(public_key_bytes)
try:
    verify_key.verify(token_data, signature)
    print("Valid token")
except Exception:
    print("Invalid token")
```

---

See `broker.py` for integration points. For Dilithium, use PQCrypto libraries when available.
