# USB Token Generation - When and How

## USB Token Generation Flow

The USB token is generated **automatically** when you run the tri-factor authentication manager **IF a USB drive is connected**.

## Exact Execution Flow

```
┌────────────────────────────────────────────────────────────┐
│  1. YOU RUN: python trifactor_auth_manager.py              │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│  2. SYSTEM INITIALIZATION                                  │
├────────────────────────────────────────────────────────────┤
│  class PQCUSBAuthenticator.__init__():                     │
│    • Initializes USB detector                              │
│    • Generates Dilithium3 keypair (once)                   │
│       - Public key: 1952 bytes                             │
│       - Private key: 4032 bytes                            │
│    • Stores keypair in memory                              │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│  3. USB DETECTION (detect_pqc_usb_token)                   │
├────────────────────────────────────────────────────────────┤
│  • Scans for removable drives                              │
│  • Gets drive info (serial number, label, size)            │
│  • Creates device_id: USB_{drive}_{serial}                 │
│  • Returns device info OR None if no USB                   │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│  4. TOKEN ISSUANCE (issue_trifactor_token)                 │
├────────────────────────────────────────────────────────────┤
│  Creates token payload with:                               │
│    • file_id, pid, user_sid                                │
│    • allowed_ops, byte_quota, expiry                       │
│    • nonce (16 random bytes)                               │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│  5. LAYER 1: TPM Sealing (if admin)                        │
├────────────────────────────────────────────────────────────┤
│  • Generates 32-byte encryption key                        │
│  • Seals key to TPM PCRs [0,1,2,7]                        │
│  • Encrypts token with sealed key                          │
│  • Result: sealed_blob + nonce + ciphertext                │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│  6. LAYER 2: Device Fingerprint Binding                    │
├────────────────────────────────────────────────────────────┤
│  • Generates hardware fingerprint (6-8 layers)             │
│  • Derives encryption key from fingerprint                 │
│  • Encrypts token with device-specific key                 │
│  • Stores fingerprint hash in metadata                     │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│  7. LAYER 3: USB SIGNATURE (sign_with_usb_token)           │
├────────────────────────────────────────────────────────────┤
│  IF USB DETECTED:                                          │
│    • Gets private key from keypair                         │
│    • Signs token with Dilithium3                           │
│    • Signature size: 3309 bytes                            │
│    • Prepends signature to token                           │
│    • Stores device_id in metadata                          │
│                                                             │
│  RESULT: signature (3309) + token_data                     │
│  Total size: ~3500 bytes (MAXIMUM security)                │
│                                                             │
│  IF NO USB:                                                │
│    • Skips USB signing                                     │
│    • Token size: ~200 bytes (HIGH security)                │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│  8. METADATA STORAGE                                       │
├────────────────────────────────────────────────────────────┤
│  Saves to: data/token_metadata/device_{fingerprint}.json  │
│    {                                                        │
│      "device_fingerprint": "blake2b_hash",                 │
│      "usb_device_id": "USB_E_ABC123",                      │
│      "pcr_values": {...},                                  │
│      "security_level": "MAXIMUM",                          │
│      "created": "2025-12-28T00:00:00"                      │
│    }                                                        │
└────────────────────────────────────────────────────────────┘
```

## Code Implementation

### USB Detection (runs first)
```python
# In PQCUSBAuthenticator.__init__()
if HAS_PQC_USB:
    self.usb_detector = UsbDriveDetector()
    self.pqc_crypto = PostQuantumCrypto()
    
    # Generate keypair ONCE at initialization
    supposed_pub, supposed_priv = self.pqc_crypto.generate_sig_keypair()
    self.keypair = (supposed_priv, supposed_pub)  # Stored in memory
```

### USB Signature Generation (runs during token issuance)
```python
# In issue_trifactor_token(), Layer 3
if "USB" in available_factors:
    print("  [3/3] Adding PQC USB signature...")
    
    # Detect USB drive
    usb_device = self.usb_auth.detect_pqc_usb_token()
    
    if usb_device:
        # Sign token with private key
        signature = self.usb_auth.sign_with_usb_token(
            token_bytes, 
            usb_device['device_id']
        )
        
        if signature:
            # Prepend signature to token
            token_bytes = signature + token_bytes
            
            # Store USB device ID for verification
            self._store_usb_device_id(file_id, usb_device['device_id'])
```

### Signature Function
```python
def sign_with_usb_token(self, message: bytes, device_id: str) -> Optional[bytes]:
    """Sign message with PQC signature"""
    if not self.pqc_crypto or not self.keypair:
        return None
    
    try:
        # Get private key (4032 bytes)
        private_key = self.keypair[1]
        
        # Generate Dilithium3 signature (3309 bytes)
        signature = self.pqc_crypto.sign(message, private_key)
        
        # Store signature association
        if device_id in self.usb_devices:
            self.usb_devices[device_id]['last_signature'] = signature
        
        return signature
        
    except Exception as e:
        print(f"⚠️ USB signing failed: {e}")
        return None
```

## When USB Token is Generated

### Timing
1. **System Start**: Keypair generated when `PQCUSBAuthenticator()` initializes
2. **USB Detection**: Happens when `detect_pqc_usb_token()` is called
3. **Signature Creation**: Happens during `issue_trifactor_token()` if USB present

### What Gets Stored

**In Memory (during runtime):**
- Dilithium3 keypair (public + private keys)
- USB device information (drive letter, serial, label)
- Generated signature (3309 bytes)

**On Disk (persistent):**
- `data/token_metadata/device_*.json`: Device fingerprint, USB device ID, PCR values
- Token file itself is NOT saved (generated on-demand)

## How to Generate USB Token

### Command
```powershell
# Insert USB drive FIRST!
python trifactor_auth_manager.py
```

### Expected Output (with USB)
```
✓ PQC USB authenticator initialized
=== Tri-Factor Auth Manager Initialized ===
TPM Available: True
Device FP Layers: 6
PQC USB Available: True  ← USB DETECTED!
=============================================

🔐 Issuing token with MAXIMUM security...
  [1/3] Sealing to TPM PCRs...
  [2/3] Binding to device fingerprint...
  [3/3] Adding PQC USB signature...  ← USB SIGNATURE ADDED!
✓ Token issued with MAXIMUM security (3502 bytes)
```

### Expected Output (without USB)
```
✓ PQC USB authenticator initialized
=== Tri-Factor Auth Manager Initialized ===
TPM Available: True
Device FP Layers: 6
PQC USB Available: False  ← NO USB!
=============================================

🔐 Issuing token with HIGH security...
  [1/2] Sealing to TPM PCRs...
  [2/2] Binding to device fingerprint...
✓ Token issued with HIGH security (212 bytes)
```

## Token Size Differences

| Components | With USB | Without USB |
|------------|----------|-------------|
| **USB Signature** | 3309 bytes | 0 bytes |
| **TPM Sealed Blob** | ~100 bytes | ~100 bytes |
| **Device FP Encrypted** | ~80 bytes | ~80 bytes |
| **Token Payload** | ~32 bytes | ~32 bytes |
| **Total** | **~3520 bytes** | **~212 bytes** |
| **Security Level** | MAXIMUM | HIGH |

## Verification Process

When you run `grant` to access protected files:

```python
# In verify_trifactor_token()
if "USB" in available_factors:
    # Extract signature (first 3309 bytes)
    SIGNATURE_SIZE = 3309
    signature = token[:SIGNATURE_SIZE]
    token = token[SIGNATURE_SIZE:]
    
    # Verify signature with public key
    usb_device = self.usb_auth.detect_pqc_usb_token()
    if not usb_device:
        return (False, SecurityLevel.EMERGENCY, "USB not detected")
    
    if usb_device['device_id'] != stored_device_id:
        return (False, SecurityLevel.EMERGENCY, "Wrong USB device")
    
    if not self.usb_auth.verify_usb_signature(token, signature, device_id):
        return (False, SecurityLevel.EMERGENCY, "Invalid USB signature")
    
    print("   ✅ USB token verified")
```

## Key Points

1. **Keypair Generation**: Happens ONCE when program starts
2. **USB Detection**: Scans for removable drives at token issuance
3. **Signature Creation**: Only if USB is detected during token generation
4. **Signature Verification**: Requires SAME USB device to be present
5. **Device Binding**: USB device ID is stored and checked during verification

## Troubleshooting

**Q: I ran the program but USB token wasn't generated**

**A:** Check the output - if you see:
- `PQC USB Available: False` → No USB detected
- `PQC USB Available: True` → USB detected, signature should be added

**Q: How do I know if USB signature was added?**

**A:** Check token size:
- ~3500 bytes = USB signature included (MAXIMUM security)
- ~200 bytes = No USB signature (HIGH security)

**Q: Can I generate USB token later?**

**A:** Yes! Just run `python trifactor_auth_manager.py` again with USB connected. The new token will include the USB signature.

## Summary

USB token generation happens **automatically** during `python trifactor_auth_manager.py` **IF** a USB drive is connected at that moment. The signature (3309 bytes) is created using Dilithium3 post-quantum cryptography and prepended to the token, making it ~3500 bytes total for MAXIMUM security.
