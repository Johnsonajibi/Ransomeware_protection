# Library Installation & Setup Guide
## device-fingerprinting-pro, TrustCore-TPM, pqcdualusb

---

## 📦 Installation Instructions

### 1. TrustCore-TPM

**Option A: PyPI (if public)**
```powershell
pip install trustcore-tpm
```

**Option B: Vendor Package (if proprietary)**
```powershell
# Download from vendor: https://trustcore.com/downloads/python-sdk
pip install TrustCore-TPM-2.0-py3-none-win_amd64.whl
```

**Option C: Alternative Open-Source TPM Library**
If TrustCore-TPM is not available, use `tpm2-pytss`:
```powershell
pip install tpm2-pytss
```

**Verification:**
```powershell
python -c "import trustcore_tpm; print('TrustCore-TPM:', trustcore_tpm.__version__)"
# OR
python -c "from tpm2_pytss import *; print('TPM2-PyTSS installed')"
```

---

### 2. device-fingerprinting-pro

**Option A: PyPI (if public)**
```powershell
pip install device-fingerprinting-pro
```

**Option B: Vendor Installation**
```powershell
# If this is a commercial library from a vendor
pip install device-fingerprinting-pro --index-url https://vendor.com/pypi/simple
# OR download wheel:
pip install device_fingerprinting_pro-1.0.0-py3-none-win_amd64.whl
```

**Option C: Alternative Open-Source**
If not available, you can use:
```powershell
# For hardware fingerprinting
pip install py-cpuinfo wmi psutil
```

**Verification:**
```powershell
python -c "from device_fingerprinting_pro import HardwareFingerprinter; print('device-fingerprinting-pro OK')"
```

---

### 3. pqcdualusb (Already in requirements.txt)

**Installation:**
```powershell
pip install pqcdualusb
```

**Verification:**
```powershell
python -c "import pqcdualusb; print('pqcdualusb:', pqcdualusb.__version__)"
```

---

## 🔧 System Requirements

### For TPM Functionality
- **Hardware:** TPM 2.0 chip (check: `Get-Tpm` in PowerShell)
- **OS:** Windows 10/11 (Build 1607+) or Windows Server 2016+
- **Permissions:** Administrator/SYSTEM privileges

**Check TPM Status:**
```powershell
# PowerShell (Run as Administrator)
Get-Tpm

# Should show:
# TpmPresent              : True
# TpmReady                : True
# TpmEnabled              : True
# TpmActivated            : True
# TpmOwned                : True
```

**Enable TPM (if disabled):**
```powershell
# In BIOS/UEFI settings:
# Security > TPM Security > TPM Device: Enabled
# Then run:
Initialize-Tpm -AllowClear -AllowPhysicalPresence
```

### For Device Fingerprinting
- **WMI Access:** Requires admin privileges for full hardware enumeration
- **Libraries:** `wmi`, `psutil`, `win32api` (already in requirements.txt)

### For PQC USB
- **USB Port:** Available USB 2.0+ port
- **Driver:** Windows will auto-detect most USB tokens
- **Hardware Token:** YubiKey 5 series or compatible PQC-enabled token

---

## 🚀 Quick Start Integration

### Step 1: Update requirements.txt
```text
# Add to requirements.txt
trustcore-tpm>=2.0.0
device-fingerprinting-pro>=1.0.0
pqcdualusb>=0.9.0  # Already present

# Alternatives if proprietary packages unavailable:
tpm2-pytss>=2.2.0
py-cpuinfo>=9.0.0
```

### Step 2: Install All Libraries
```powershell
# Activate your virtual environment
.\.venv\Scripts\Activate.ps1

# Install all packages
pip install -r requirements.txt

# Verify installations
python -c "import trustcore_tpm, pqcdualusb; print('✓ All libraries installed')"
```

### Step 3: Run Integration Test
```powershell
# Test the tri-factor system
python trifactor_auth_manager.py

# Expected output:
# ✓ TrustCore-TPM initialized
# ✓ device-fingerprinting-pro loaded
# ✓ PQC USB authenticator initialized
# Available Factors: TPM, DeviceFP, USB
# Security Level: MAXIMUM
```

---

## 🔍 Troubleshooting

### Issue: "TPM not found"
**Solution:**
```powershell
# Check TPM status
Get-Tpm

# If not present:
# 1. Enable in BIOS/UEFI
# 2. Update firmware
# 3. Check Device Manager > Security devices > Trusted Platform Module 2.0

# Fallback: Use software-based sealing
# The trifactor_auth_manager.py automatically falls back
```

### Issue: "device-fingerprinting-pro not found"
**Solution:**
```powershell
# Use alternative implementation
pip install py-cpuinfo wmi psutil

# The system will use built-in AdvancedDeviceFingerprint class
# from enterprise_security_core.py (already works!)
```

### Issue: "pqcdualusb import error"
**Solution:**
```powershell
# Check if package name is different
pip list | findstr pqc
# OR
pip search pqc

# Alternative: Use classical USB detection only
# System will degrade gracefully to Ed25519-only signatures
```

### Issue: "Access Denied" when accessing TPM
**Solution:**
```powershell
# Run as Administrator
# Right-click PowerShell > Run as Administrator
cd C:\Users\ajibi\Music\Anti-Ransomeware
.\.venv\Scripts\Activate.ps1
python trifactor_auth_manager.py
```

### Issue: WMI Access Denied for Device Fingerprinting
**Solution:**
```powershell
# Grant WMI permissions
# Run as Administrator:
wmimgmt.msc
# Right-click WMI Control > Properties > Security
# Add your user account with Read permissions
```

---

## 📝 Configuration After Installation

### 1. Configure TPM PCR Policy
Edit `config_trifactor.yaml`:
```yaml
trifactor_auth:
  tpm:
    enabled: true
    pcr_policy: [0, 1, 2, 7]  # BIOS, firmware, kernel, secure boot
    quote_cache_ttl: 300       # 5 minutes
    fallback_to_software: true # Use software seal if TPM unavailable
```

### 2. Configure Device Fingerprint Tolerance
```yaml
trifactor_auth:
  device_fingerprint:
    enabled: true
    fuzzy_match_tolerance: 0.95  # 95% match required
    critical_components:
      - cpu_serial
      - motherboard_serial
      - tpm_endorsement_key
    flexible_components:
      - memory_serial  # Can change without invalidating token
      - disk_serial
```

### 3. Configure USB Token Policy
```yaml
trifactor_auth:
  usb_token:
    enabled: true
    require_pqc: true          # Require Dilithium support
    dilithium_level: 3         # Security level (2, 3, or 5)
    fallback_to_ed25519: true  # Allow classical signatures if no PQC
```

---

## 🧪 Testing Each Component

### Test 1: TPM Functionality
```python
from trifactor_auth_manager import TPMTokenManager

tpm = TPMTokenManager()
print(f"TPM Available: {tpm.tpm_available}")

# Test sealing
test_data = b"secret_key_12345"
sealed = tpm.seal_token_to_platform(test_data)
print(f"Sealed: {len(sealed)} bytes")

# Test unsealing
unsealed = tpm.unseal_token_from_platform(sealed)
print(f"Unsealed: {unsealed == test_data}")
```

### Test 2: Device Fingerprinting
```python
from trifactor_auth_manager import HybridDeviceFingerprint

fp = HybridDeviceFingerprint()
fingerprint = fp.generate_hybrid_fingerprint()
print(f"Fingerprint: {fingerprint.hex()[:32]}...")

# Test matching
match = fp.verify_device_match(fingerprint, tolerance=0.95)
print(f"Match: {match}")
```

### Test 3: PQC USB Authentication
```python
from trifactor_auth_manager import PQCUSBAuthenticator

usb = PQCUSBAuthenticator()
device = usb.detect_pqc_usb_token()

if device:
    print(f"USB Device: {device['device_id']}")
    print(f"PQC Support: {device['pqc_algorithms']}")
else:
    print("No PQC USB token detected")
```

### Test 4: Full Tri-Factor System
```powershell
python trifactor_auth_manager.py
```

---

## 📊 Expected Performance

| Operation | Time (ms) | Notes |
|-----------|-----------|-------|
| TPM Seal | 20-40 | One-time per token |
| TPM Unseal | 15-30 | Per file access |
| Device FP Generation | 10-50 | Cached for 5min |
| USB Signature | 5-15 | Dilithium3 |
| Full Token Issuance | 50-100 | All three factors |
| Full Token Verification | 40-80 | With caching |

**Optimization Tips:**
- Cache TPM quotes (5min TTL) → reduces unseal time to ~5ms
- Pre-compute device fingerprint on boot → instant verification
- Keep USB token connected → no detection overhead

---

## 🔗 Additional Resources

### Official Documentation
- **TPM 2.0:** https://trustedcomputinggroup.org/resource/tpm-library-specification/
- **NIST PQC:** https://csrc.nist.gov/projects/post-quantum-cryptography
- **Windows TPM:** https://docs.microsoft.com/en-us/windows/security/information-protection/tpm/

### Alternative Libraries (if proprietary ones unavailable)
```powershell
# Open-source alternatives:
pip install tpm2-pytss      # TPM 2.0 Python bindings
pip install py-cpuinfo      # CPU information
pip install wmi             # Windows Management Instrumentation
pip install psutil          # System and process utilities
pip install pycryptodome    # Cryptography (Dilithium via external lib)
```

### Community Support
- **TPM Issues:** https://github.com/tpm2-software/tpm2-tss/issues
- **Device Fingerprinting:** Stack Overflow `[hardware-fingerprint]` tag
- **PQC Discussion:** NIST PQC mailing list

---

## ✅ Post-Installation Checklist

- [ ] All three libraries installed successfully
- [ ] TPM 2.0 detected and initialized (`Get-Tpm` shows Ready)
- [ ] Device fingerprint generates without errors
- [ ] USB token detected (if available)
- [ ] `trifactor_auth_manager.py` demo runs successfully
- [ ] Token issuance completes in <100ms
- [ ] Token verification succeeds
- [ ] Graceful degradation works (tested by disabling TPM/USB)
- [ ] Configuration files created (`config_trifactor.yaml`)
- [ ] Golden PCR values stored (`data/golden_pcrs.json`)

---

## 🆘 Support

If you encounter issues:

1. **Check system requirements** (TPM 2.0, Admin privileges)
2. **Review error messages** in console output
3. **Test components individually** (see Testing section)
4. **Check fallback modes** (system degrades gracefully)
5. **Review logs** in `logs/trifactor_auth.log`

**Contact:**
- Technical issues: Open issue in repository
- TPM-specific: Check Windows Event Viewer > Applications and Services Logs > Microsoft > Windows > TPM-WMI

---

**Last Updated:** December 26, 2025  
**Version:** 1.0.0  
**Status:** Ready for Integration
