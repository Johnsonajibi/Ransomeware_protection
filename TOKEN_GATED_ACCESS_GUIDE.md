# Token-Gated Access Control - Usage Guide

## Problem Fixed

The protection system was only **detecting** threats but not actually **blocking access** to files/folders. Now the system:

1. **Blocks access** to protected files/folders using Windows ACLs
2. **Requires token validation** (TPM + fingerprint + optional USB) before granting access
3. **Prevents any process** (including admin) from accessing protected content without valid authentication

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│  User tries to access protected folder/file            │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  Windows ACL: ACCESS DENIED                             │
│  - Everyone: DENIED                                     │
│  - SYSTEM: DENIED                                       │
│  - Administrators: DENIED                               │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  User must run token validation                         │
│  python token_gated_access.py grant <path>              │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  Token Validation:                                      │
│  1. Check token exists                                  │
│  2. Verify TPM PCR values                              │
│  3. Validate device fingerprint                        │
│  4. Check USB token (if required)                      │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
        ┌─────────┴─────────┐
        │                   │
        ▼                   ▼
    ❌ FAIL             ✅ SUCCESS
   Access Denied      ACLs removed
                     Access granted
```

## Setup Process

### Step 1: Generate Authentication Token (Run as Administrator)

```powershell
# Generate tri-factor authentication token
python trifactor_auth_manager.py

# Or use the GUI
.\dist\AntiRansomware-TriFactor.exe
```

This creates a token file in `.trifactor_tokens/` that includes:
- TPM sealed data (PCR measurements)
- Device fingerprint hash
- PQC USB signature (if USB present)

### Step 2: Protect Files/Folders (Run as Administrator)

```powershell
# Protect a single file
python token_gated_access.py protect "C:\Important\document.txt"

# Protect an entire folder
python token_gated_access.py protect "C:\SecretFiles"

# Protect folder without TPM requirement (for systems without TPM)
python token_gated_access.py protect "C:\Data" --no-tpm

# Protect with USB requirement
python token_gated_access.py protect "C:\TopSecret" --require-usb
```

### Step 3: Try to Access Protected Content

```powershell
# Try to open the protected file - WILL FAIL
notepad "C:\Important\document.txt"
# Result: Access Denied

# Try to list protected folder - WILL FAIL
dir "C:\SecretFiles"
# Result: Access Denied

# Try to access as admin - STILL FAILS
# Even administrators cannot access without token validation
```

### Step 4: Grant Access with Token Validation

```powershell
# Validate token and grant access (Run as Administrator)
python token_gated_access.py grant "C:\Important\document.txt"
```

The system will:
1. Find the token file in `.trifactor_tokens/`
2. Verify TPM PCR values match current boot state
3. Verify device fingerprint matches hardware
4. Verify USB token if required
5. Remove ACL restrictions if validation succeeds
6. Grant access to the current user

Now you can access the file:
```powershell
notepad "C:\Important\document.txt"  # ✅ Opens successfully
```

## Commands Reference

### Protect Path
```powershell
python token_gated_access.py protect <path> [options]

Options:
  --no-tpm              Don't require TPM validation
  --no-fingerprint      Don't require device fingerprint
  --require-usb         Require USB token presence

Examples:
  python token_gated_access.py protect "C:\Data"
  python token_gated_access.py protect "C:\Secrets" --require-usb
  python token_gated_access.py protect "file.txt" --no-tpm
```

### Grant Access
```powershell
python token_gated_access.py grant <path>

Example:
  python token_gated_access.py grant "C:\Data"
```

### Remove Protection
```powershell
python token_gated_access.py remove <path>

Example:
  python token_gated_access.py remove "C:\Data"
```

### List Protected Paths
```powershell
python token_gated_access.py list

Output:
  🛡️ PROTECTED PATHS:
  ============================================================
  📂 C:\Data
     TPM: True, Fingerprint: True, USB: False
  📂 C:\Secrets
     TPM: True, Fingerprint: True, USB: True
```

## Security Features

### Multi-Layer Access Denial

1. **Windows ACL Denials:**
   - Deny Everyone: `(F,M,RX,R,W)` - All permissions blocked
   - Deny SYSTEM: Blocks even system processes
   - Deny Administrators: Even admin accounts cannot access

2. **Inheritance for Folders:**
   - `(OI)(CI)` flags ensure child files inherit denials
   - New files created in protected folders are auto-protected

3. **File Attributes:**
   - System (`+S`): Marks as system file
   - Hidden (`+H`): Hides from normal view
   - Read-only (`+R`): Prevents modification

### Token Validation

1. **TPM Verification:**
   - Reads PCR 0, 1, 2, 7 from hardware TPM chip
   - Validates sealed data matches current boot state
   - Fails if platform state changed (firmware update, boot config)

2. **Device Fingerprint:**
   - BLAKE2b hash of 6-8 hardware identifiers
   - CPU serial, BIOS UUID, MAC address, disk serial, etc.
   - Fails if hardware components changed

3. **USB Token (Optional):**
   - Dilithium3 post-quantum signature on removable drive
   - 3309-byte signature prevents forgery
   - Requires physical USB device presence

## Testing

### Test Script

```powershell
# Create test folder
mkdir C:\TestProtection
echo "Secret data" > C:\TestProtection\secret.txt

# Protect it (requires admin)
python token_gated_access.py protect "C:\TestProtection"

# Try to access (should fail)
type C:\TestProtection\secret.txt
# Error: Access is denied

# Generate token (requires admin)
python trifactor_auth_manager.py

# Grant access (requires admin + valid token)
python token_gated_access.py grant "C:\TestProtection"

# Now access works
type C:\TestProtection\secret.txt
# Output: Secret data
```

## Integration with Desktop App

Update `desktop_app.py` to use token-gated access:

```python
from token_gated_access import TokenGatedAccessControl

# In protection manager
self.access_controller = TokenGatedAccessControl()

# When adding folder to protection
def add_protected_folder(self, folder_path):
    # Add to database
    self.db.add_protected_folder(folder_path)
    
    # Apply token-gated access control
    self.access_controller.add_protected_path(
        folder_path,
        require_tpm=True,
        require_fingerprint=True,
        require_usb=False  # Make USB optional
    )
```

## Troubleshooting

### "Access Denied" when running commands

**Problem:** Commands require administrator privileges

**Solution:** Run PowerShell as Administrator
```powershell
Right-click PowerShell → "Run as Administrator"
```

### "Token validation failed"

**Problem:** No token file found or token expired

**Solution:** Generate new token
```powershell
python trifactor_auth_manager.py
```

### "TPM verification failed"

**Problem:** System rebooted or firmware updated (PCR values changed)

**Solution:** Regenerate token after reboot
```powershell
python trifactor_auth_manager.py
```

### "Device fingerprint mismatch"

**Problem:** Hardware components changed

**Solution:** Regenerate token on new hardware configuration
```powershell
python trifactor_auth_manager.py
```

### Cannot remove protection

**Problem:** ACLs locked even for admin

**Solution:** Take ownership first
```powershell
takeown /F "C:\Path" /R /A
icacls "C:\Path" /reset /T /C
```

## Production Deployment

1. **Initial Setup:**
   - Install on Windows Server with TPM 2.0
   - Run as administrator
   - Generate master authentication token

2. **Protect Critical Folders:**
   ```powershell
   python token_gated_access.py protect "C:\SQLData"
   python token_gated_access.py protect "C:\BackupData"
   python token_gated_access.py protect "C:\ConfigFiles"
   ```

3. **Service Integration:**
   - Create Windows Service that validates token on startup
   - Service grants access to database files during normal operations
   - Access automatically revoked when service stops

4. **Scheduled Token Renewal:**
   - Create scheduled task to regenerate tokens every 24 hours
   - Ensures fresh PCR measurements
   - Updates device fingerprint

5. **Monitoring:**
   - Check audit logs: `.audit_logs/audit_YYYYMMDD.jsonl`
   - Monitor for unauthorized access attempts
   - Alert on token validation failures

## Security Notes

⚠️ **Important Security Considerations:**

1. **Token Storage:** Token files contain sensitive cryptographic material. Store in secure location with appropriate file permissions.

2. **Administrator Access:** System requires admin privileges to modify ACLs. Protect admin credentials.

3. **TPM Reset:** Clearing TPM will invalidate all sealed tokens. Backup important data before TPM maintenance.

4. **Hardware Changes:** Replacing CPU, motherboard, or network card will cause device fingerprint mismatch.

5. **Emergency Access:** Keep emergency recovery credentials in secure offline storage in case of token loss.

6. **Backup Tokens:** Store backup tokens on encrypted USB drives in physically secure location.

## Comparison: Before vs After

### Before (Detection Only)
- ❌ Files could be opened without token
- ❌ Ransomware could encrypt files
- ❌ Admin could access without validation
- ❌ Only logged suspicious activity
- ❌ Reactive protection (after damage)

### After (Prevention)
- ✅ Files cannot be opened without token validation
- ✅ Ransomware blocked at OS level (ACCESS DENIED)
- ✅ Even admin requires token + TPM + fingerprint
- ✅ Blocks access before any damage occurs
- ✅ Proactive protection (prevents damage)

## Next Steps

1. Integrate with desktop GUI application
2. Add automatic token renewal service
3. Implement audit log viewer for access attempts
4. Create emergency recovery procedure
5. Build installer package for easy deployment
