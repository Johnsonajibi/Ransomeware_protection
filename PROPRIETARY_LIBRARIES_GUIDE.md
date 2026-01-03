# Integration Guide for Proprietary Security Libraries

## Overview
Your anti-ransomware system is configured to use three proprietary hardware security libraries that must be obtained directly from vendors.

## Required Libraries

### 1. **pqcdualusb** - Post-Quantum Cryptography
**Purpose:** Hardware-accelerated post-quantum cryptography (Kyber1024 + Dilithium3)

**Where to obtain:**
- Contact your USB security token vendor
- Examples: YubiKey HSM, Nitrokey HSM, SoloKeys
- Check if your organization has enterprise PQC hardware

**Installation:**
```bash
# After obtaining from vendor:
pip install /path/to/pqcdualusb-*.whl
# Or if provided as source:
cd pqcdualusb_sdk
python setup.py install
```

**Expected API:**
```python
import pqcdualusb

# Initialize
pqc = pqcdualusb.PQCDualUSB()

# Generate KEM keypair
kem_keypair = pqc.generate_kem_keypair(algorithm="Kyber1024")
# Returns: {'public_key': bytes, 'secret_key': bytes}

# Generate signature keypair
sig_keypair = pqc.generate_signature_keypair(algorithm="Dilithium3")
# Returns: {'public_key': bytes, 'secret_key': bytes}
```

---

### 2. **Trustcore-TPM** - Hardware TPM Integration
**Purpose:** Direct TPM 2.0 hardware integration with PCR binding

**Where to obtain:**
- Check your TPM chip manufacturer:
  - **Intel PTT:** https://www.intel.com/content/www/us/en/support/articles/000007452/
  - **AMD fTPM:** Contact AMD enterprise support
  - **Infineon:** https://www.infineon.com/tpm
  - **NXP:** https://www.nxp.com/security
  - **STMicroelectronics:** https://www.st.com/tpm

**Installation:**
```bash
# After obtaining vendor SDK:
pip install /path/to/trustcore_tpm-*.whl
```

**Expected API:**
```python
import trustcore_tpm as tpm

# Initialize TPM
tpm_device = tpm.TPM()

# Check availability
if tpm_device.is_available():
    # Create primary key
    tpm_device.create_primary_key()
    
    # Seal data with PCR binding
    policy = tpm.SealingPolicy(
        pcrs=tpm.PCRSelection([0, 1, 2, 7]),
        algorithm='SHA256'
    )
    
    sealed_blob = tpm_device.seal_data(
        data=b"secret_key_data",
        policy=policy,
        auth_value=b"auth_password"
    )
    
    # Unseal data (fails if PCRs changed)
    unsealed = tpm_device.unseal_data(
        sealed_blob=sealed_blob,
        auth_value=b"auth_password"
    )
```

---

### 3. **device-fingerprinting-pro** - Advanced Device Fingerprinting
**Purpose:** Multi-factor hardware fingerprinting with TPM binding

**Where to obtain:**
- Check with enterprise security vendors:
  - DeviceAtlas
  - FingerprintJS Pro
  - SEON Fraud Fighters
  - Your organization's security team

**Installation:**
```bash
# After obtaining license and SDK:
pip install /path/to/device_fingerprinting_pro-*.whl
```

**Expected API:**
```python
import device_fingerprinting_pro as dfp

# Initialize
fp_gen = dfp.FingerprintGenerator(
    include_hardware=True,
    include_bios=True,
    include_tpm=True,
    include_secure_boot=True
)

# Generate fingerprint
fp_data = fp_gen.generate(
    factors=['cpu_id', 'mainboard_serial', 'bios_serial', 
             'disk_serial', 'tpm_endorsement_key']
)

# Get hash
fingerprint = fp_data.get_hash('sha256')  # Returns: str (64 hex chars)

# Check TPM binding
has_tpm = fp_data.has_tpm_binding()  # Returns: bool
```

---

## Current Fallback Behavior

Without the proprietary libraries, the system uses:

| Component | Proprietary | Fallback |
|-----------|-------------|----------|
| **PQC** | pqcdualusb (Kyber+Dilithium) | RSA-4096 (classical) |
| **TPM** | Trustcore-TPM (hardware) | Software-only (no PCR binding) |
| **Fingerprinting** | device-fingerprinting-pro | Basic WMI (CPU+UUID) |

**Security Implications:**
- ⚠️ No quantum resistance (RSA vulnerable to quantum attacks)
- ⚠️ No hardware key sealing (vulnerable to cold boot attacks)
- ⚠️ Weak device binding (easy to spoof)

---

## Integration Checklist

Once you obtain the libraries:

- [ ] **pqcdualusb**
  - [ ] Install package
  - [ ] Verify import: `python -c "import pqcdualusb; print('OK')"`
  - [ ] Test key generation
  - [ ] Verify hardware device detected

- [ ] **Trustcore-TPM**
  - [ ] Ensure TPM enabled in BIOS/UEFI
  - [ ] Install package  
  - [ ] Verify import: `python -c "import trustcore_tpm as tpm; print('OK')"`
  - [ ] Test TPM initialization: `tpm.TPM().is_available()`
  - [ ] Test seal/unseal operations

- [ ] **device-fingerprinting-pro**
  - [ ] Install package with license key
  - [ ] Verify import: `python -c "import device_fingerprinting_pro as dfp; print('OK')"`
  - [ ] Generate test fingerprint
  - [ ] Verify TPM binding works

---

## Testing Integration

After installing all libraries:

```bash
python test_trustcore_tpm.py
```

Expected output:
```
[1/4] Testing Trustcore-TPM import...
✅ trustcore-tpm imported successfully
✅ TPM hardware detected
   Version: 2.0

[2/4] Testing device-fingerprinting-pro import...
✅ device-fingerprinting-pro imported successfully
✅ Device fingerprint generated
   Fingerprint: a7f3e2b1c9d8...

[3/4] Testing integrated module...
✅ pqcdualusb loaded
✅ Trustcore-TPM loaded
✅ device-fingerprinting-pro loaded

TPM 2.0 Available: ✅ YES
PQC Backend: ✅ pqcdualusb
PQC Algorithms: ✅ Kyber1024 (KEM) + Dilithium3 (Sig)
Device Fingerprinting: ✅ device-fingerprinting-pro

✅ Device key generated
   TPM sealed: True
   KEM public key: 1568 bytes
   Signature public key: 2592 bytes
```

---

## Alternative: Use Open-Source Libraries

If proprietary libraries are unavailable, consider:

### For PQC:
```bash
# Build liboqs from source (requires compilation)
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make && sudo make install

# Install Python wrapper
pip install liboqs-python
```

### For TPM:
```bash
# Use Windows native TPM via ctypes (no external library needed)
# Or install tpm2-pytss (requires compilation)
```

### For Device Fingerprinting:
Use the included [device_fingerprint_enhanced.py](device_fingerprint_enhanced.py) which uses WMI directly.

---

## Contact Information

**Need help obtaining libraries?**
- Contact your organization's IT security team
- Check with your hardware vendor (motherboard/laptop manufacturer)
- Consult with a security vendor for enterprise licenses

**System is fully functional with fallbacks** - you can use the anti-ransomware system now, but hardware-backed security requires the proprietary libraries.
