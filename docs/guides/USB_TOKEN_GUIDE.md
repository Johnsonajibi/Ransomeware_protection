# USB Token Protection - Complete Workflow

## Design Overview

The system requires a **physical USB drive** to be present for accessing protected files/folders. This adds a hardware-based security layer that prevents access even if:
- The attacker has admin credentials
- TPM is compromised
- Device fingerprint is spoofed

## USB Token Requirements

### What Counts as a USB Token?
- Any removable USB drive (flash drive, external HDD)
- Must be present during token generation
- Must be the SAME USB device during access validation
- USB device ID is bound to the token

### How It Works

```
┌─────────────────────────────────────────────────┐
│  Step 1: Generate Token WITH USB Present       │
├─────────────────────────────────────────────────┤
│  1. Insert USB drive                            │
│  2. Run: python trifactor_auth_manager.py       │
│  3. System detects USB device ID                │
│  4. Creates Dilithium3 signature (3309 bytes)   │
│  5. Token = USB_SIG + TPM_BLOB + FP_DATA        │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│  Step 2: Protect Files/Folders with USB Req    │
├─────────────────────────────────────────────────┤
│  python token_gated_access.py protect \         │
│    "C:\Folder" --require-usb                    │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│  Step 3: Try Access WITHOUT USB = BLOCKED      │
├─────────────────────────────────────────────────┤
│  • Remove USB drive                             │
│  • Try: dir C:\Folder                           │
│  • Result: Access Denied (Windows ACL)          │
│  • Try: grant access → FAILS (no USB)           │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│  Step 4: Grant Access WITH USB = SUCCESS       │
├─────────────────────────────────────────────────┤
│  1. Insert SAME USB drive                       │
│  2. python token_gated_access.py grant \        │
│       "C:\Folder"                               │
│  3. System verifies:                            │
│     ✓ USB device ID matches                     │
│     ✓ Dilithium3 signature valid               │
│     ✓ TPM PCR values match                     │
│     ✓ Device fingerprint matches               │
│  4. Access granted → ACLs removed               │
└─────────────────────────────────────────────────┘
```

## Complete Usage Example

### Step 1: Insert USB Drive

```powershell
# Check connected USB drives
Get-Volume | Where-Object {$_.DriveType -eq 'Removable'}

# Example output:
# DriveLetter FileSystemLabel Size
# ----------- --------------- ----
# E           MY_USB_KEY      32GB
```

### Step 2: Generate Token WITH USB Present (Run as Admin)

```powershell
# Make sure USB is connected!
python trifactor_auth_manager.py
```

**Expected output:**
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
  [3/3] Adding PQC USB signature...
✓ Token issued with MAXIMUM security (3502 bytes)

Token saved to: data/token_metadata/device_e7a4b2c8.json
```

### Step 3: Protect Folder/File with USB Requirement

```powershell
# Protect folder - requires USB for access
python token_gated_access.py protect "C:\SecretFiles" --require-usb

# Protect single file
python token_gated_access.py protect "C:\TopSecret.docx" --require-usb
```

**Output:**
```
✅ Protected: C:\SecretFiles
   Requirements: TPM=True, Fingerprint=True, USB=True
```

### Step 4: Verify Protection Works

```powershell
# Remove USB drive (important!)
# Then try to access:

dir C:\SecretFiles
# Result: Access is denied ✓

# Try to grant access WITHOUT USB
python token_gated_access.py grant "C:\SecretFiles"
# Result: ❌ USB token required but not present
```

### Step 5: Grant Access WITH USB Present

```powershell
# 1. Insert USB drive (SAME ONE used in token generation)
# 2. Grant access

python token_gated_access.py grant "C:\SecretFiles"
```

**Expected validation flow:**
```
🔑 Token validation required
   Checking for existing tokens...
   Found 1 token(s)
   Using token: device_e7a4b2c8.json

   Validating token...
   Security Level: MAXIMUM
   ✅ TPM verified
   ✅ Device fingerprint verified
   ✅ USB token verified  ← USB CHECK PASSED!

✅ All authentication factors verified
  🔓 Folder access restored
✅ Access granted: C:\SecretFiles
```

### Step 6: Access Files

```powershell
# Now you can access the folder
dir C:\SecretFiles  # ✅ Works
notepad C:\SecretFiles\secret.txt  # ✅ Opens
```

## Protection Levels

### Without USB (Standard Protection)
```powershell
python token_gated_access.py protect "C:\Data"
# TPM=True, Fingerprint=True, USB=False
# Security: HIGH (2 factors)
```

### With USB (Maximum Protection)
```powershell
python token_gated_access.py protect "C:\Data" --require-usb
# TPM=True, Fingerprint=True, USB=True
# Security: MAXIMUM (3 factors)
```

### Optional Flags
```powershell
# Without TPM (for systems without TPM 2.0)
python token_gated_access.py protect "C:\Data" --no-tpm --require-usb

# Without fingerprint (not recommended)
python token_gated_access.py protect "C:\Data" --no-fingerprint --require-usb

# USB only
python token_gated_access.py protect "C:\Data" --no-tpm --no-fingerprint --require-usb
```

## USB Token Storage

### Token Metadata Location
```
.\data\token_metadata\device_<fingerprint>.json
```

**Contains:**
- Device fingerprint hash (BLAKE2b)
- USB device ID (drive serial number)
- PCR measurements (for TPM binding)
- Token creation timestamp
- Security level

### USB Signature Format
- Algorithm: Dilithium3 (ML-DSA-65) - NIST standardized
- Signature size: 3309 bytes
- Public key size: 1952 bytes
- Private key: Stored on USB drive only
- Quantum-resistant: Yes

## Security Features

### What Happens Without USB?

1. **Protection Phase:**
   - Windows ACLs deny ALL access (Everyone, SYSTEM, Administrators)
   - Files set to System + Hidden + Read-only
   - Folder inheritance ensures new files are protected

2. **Access Attempt Without USB:**
   ```
   User → Try Open File
     ↓
   Windows → Check ACL → DENY (Everyone denied)
     ↓
   Result: Access is denied
   ```

3. **Grant Attempt Without USB:**
   ```
   User → python grant
     ↓
   System → Check token
     ↓
   System → Verify USB signature
     ↓
   USB Not Present → FAIL
     ↓
   Result: ❌ USB token required but not present
   ```

### What Happens With USB?

1. **User inserts correct USB drive**
2. **Run grant command**
3. **System validates:**
   - ✅ USB device ID matches stored ID
   - ✅ Dilithium3 signature verifies
   - ✅ TPM PCR values match boot state
   - ✅ Device fingerprint matches hardware
4. **ACLs removed, access granted**

## Advanced Scenarios

### Multiple USB Tokens

You can use different USB drives for different protected folders:

```powershell
# Folder 1 with USB Drive A
# Insert USB-A
python trifactor_auth_manager.py  # Creates token with USB-A ID
python token_gated_access.py protect "C:\Folder1" --require-usb

# Folder 2 with USB Drive B
# Insert USB-B
python trifactor_auth_manager.py  # Creates token with USB-B ID
python token_gated_access.py protect "C:\Folder2" --require-usb

# Now:
# - Folder1 requires USB-A
# - Folder2 requires USB-B
# - Cannot use USB-A to access Folder2 (device ID mismatch)
```

### Emergency Access Without USB

If USB drive is lost:

```powershell
# Option 1: Remove protection (requires admin)
python token_gated_access.py remove "C:\Folder"

# Option 2: Manual ACL reset (requires admin)
takeown /F "C:\Folder" /R /A
icacls "C:\Folder" /reset /T /C

# Option 3: Re-protect with new USB
python token_gated_access.py remove "C:\Folder"
# Insert new USB
python trifactor_auth_manager.py
python token_gated_access.py protect "C:\Folder" --require-usb
```

### Corporate Deployment

For enterprise environments:

1. **Master USB Keys:**
   - Issue company USB drives to authorized personnel
   - Each drive has unique device ID
   - Bind critical folders to specific USB keys

2. **Access Control Matrix:**
   ```
   Folder: C:\FinanceData
   Required: TPM + Fingerprint + USB_CFO
   
   Folder: C:\HRRecords
   Required: TPM + Fingerprint + USB_HR_Manager
   
   Folder: C:\BackupData
   Required: TPM + Fingerprint + USB_IT_Admin
   ```

3. **Audit Trail:**
   ```powershell
   # Check who accessed what
   Get-Content .\.audit_logs\audit_*.jsonl | 
     Where-Object {$_ -like "*usb_verified*true*"}
   ```

## Troubleshooting

### USB Not Detected During Token Generation

**Problem:** "PQC USB Available: False"

**Solutions:**
1. Check USB is properly connected: `Get-Volume | Where {$_.DriveType -eq 'Removable'}`
2. Try different USB port
3. Check USB drive has a unique serial number: `wmic diskdrive get SerialNumber`
4. Ensure USB is formatted (any filesystem works)

### USB Verification Fails

**Problem:** "❌ USB token required but not present"

**Cause:** Wrong USB drive or USB not connected

**Solutions:**
1. Verify correct USB is inserted
2. Check USB device ID: Compare with stored ID in token metadata
3. Re-generate token if USB was reformatted (device ID changes)

### Token Size Mismatch

**Problem:** Token too small (< 3400 bytes)

**Cause:** USB signature not included in token

**Solution:** Regenerate token with USB connected

## Best Practices

✅ **Do:**
- Keep USB drive in secure physical location
- Use high-quality USB drives (less likely to fail)
- Backup token metadata files
- Test access workflow after protection setup
- Document which USB goes with which folders

❌ **Don't:**
- Share USB drives between users
- Leave USB connected when not needed
- Format USB drive after token generation (changes device ID)
- Use USB drives for other purposes (prevents accidental format)

## Comparison: With vs Without USB

| Scenario | Without USB Requirement | With USB Requirement |
|----------|------------------------|---------------------|
| **Access with credentials** | Possible after token validation | Requires physical USB drive |
| **Remote attack** | Possible if attacker has token + TPM + fingerprint | IMPOSSIBLE (requires physical USB) |
| **Insider threat** | Possible with valid token | Requires stealing USB drive |
| **Security level** | HIGH (2 factors) | MAXIMUM (3 factors) |
| **Convenience** | More convenient | Requires USB insertion |
| **Use case** | General protection | Maximum security scenarios |

## Conclusion

USB token requirement adds a **physical security layer** that makes remote attacks impossible. Even if an attacker compromises:
- ✅ Your admin password
- ✅ Your TPM measurements
- ✅ Your device fingerprint

They still cannot access protected files without physically stealing your USB drive. This is ideal for:
- Financial records
- Legal documents
- Trade secrets
- Personal health information
- Cryptocurrency wallets
- Password databases
