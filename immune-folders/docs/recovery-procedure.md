# Recovery Procedures - Immune Folders

## Emergency Recovery Scenarios

### Scenario 1: Lost USB Token

**Symptoms:**
- USB token is lost, stolen, or damaged
- Cannot access immune folders
- System shows "Token not found" error

**Recovery Steps:**

1. **Locate Recovery Materials**
   ```
   Required:
   - Recovery QR code (printed during setup)
   - Recovery passphrase (written separately)
   - Access to Windows machine with Immune Folders
   ```

2. **Initiate Recovery Mode**
   ```powershell
   # Run as Administrator
   .\immune-folders\client\main.py --recovery-mode
   ```

3. **Scan Recovery QR**
   - Use phone camera or QR scanner
   - Enter QR payload into recovery dialog
   - Verify folder ID matches

4. **Enter Recovery Passphrase**
   - Type exact passphrase (case-sensitive)
   - System will reconstruct Folder Master Key
   - Mount container temporarily

5. **Generate New Token**
   ```powershell
   # Creates new USB token with same FMK
   .\immune-folders\client\main.py --retoken --usb-drive E:
   ```

6. **Print New Recovery QR**
   - System generates new QR with rotated secrets
   - Print and store in secure location
   - Destroy old QR if found

**Verification:**
- Test new USB token unlocks folders
- Verify auto-lock still functions
- Check audit logs show recovery event

---

### Scenario 2: Ransomware Attack (System Compromise)

**Symptoms:**
- Files on system are encrypted by ransomware
- Desktop shows ransom note
- System may be unstable or slow

**Recovery Steps:**

1. **Verify Immune Folder Status**
   ```powershell
   # Check if containers are still encrypted
   Get-ChildItem "C:\ImmuneFolders\*.vc" | Test-Path
   ```

2. **Boot from Recovery Media** (if needed)
   - Boot from Windows PE or Linux live USB
   - Mount system drive as secondary
   - Locate immune container files

3. **Install Recovery Tools**
   ```powershell
   # On clean system or recovery environment
   .\infra\installer.ps1 -RecoveryMode
   ```

4. **Unlock Immune Folders**
   - Insert USB token or use QR recovery
   - Containers should mount normally
   - Files inside are unencrypted and intact

5. **Backup Critical Data**
   ```powershell
   # Copy from mounted immune folders to external drive
   robocopy X:\ D:\backup\ /E /R:3 /W:5
   ```

6. **System Restoration**
   - Format and reinstall Windows
   - Restore from immune folder backups
   - Reinstall immune folders service

**Verification:**
- All immune folder data is intact
- No files show ransomware extensions
- Audit logs show no unauthorized access

---

### Scenario 3: Forgotten Recovery Passphrase

**Symptoms:**
- Have recovery QR code but forgot passphrase
- USB token is also lost/unavailable
- Cannot access immune folders

**Recovery Options:**

1. **Passphrase Recovery Hints** (if configured)
   ```
   Check these locations for hints:
   - Password manager entries
   - Encrypted notes in other systems
   - Paper backup in safe/vault
   ```

2. **Administrative Override** (if enabled)
   ```powershell
   # Requires admin credentials + hardware token
   .\immune-folders\client\main.py --admin-recovery --verify-identity
   ```

3. **Brute Force Protection**
   ```
   WARNING: After 10 failed passphrase attempts:
   - Recovery QR becomes invalid
   - Must use backup recovery method
   - Audit alerts are triggered
   ```

4. **Last Resort Options**
   - Contact system administrator
   - Use enterprise key escrow (if configured)
   - Data may be permanently inaccessible

---

### Scenario 4: Hardware Failure (TPM/Motherboard)

**Symptoms:**
- DPAPI cannot decrypt device keys
- "Hardware security module error"
- USB token shows as invalid

**Recovery Steps:**

1. **Export Before Failure** (preventive)
   ```powershell
   # Creates portable backup of device keys
   .\immune-folders\client\main.py --export-keys --secure-backup
   ```

2. **Recovery on New Hardware**
   ```powershell
   # Import keys to new machine
   .\immune-folders\client\main.py --import-keys --backup-file backup.dat
   ```

3. **QR Recovery Method**
   - Use recovery QR + passphrase
   - Bypasses hardware-bound keys
   - Generates new device binding

4. **Professional Data Recovery**
   - Contact certified data recovery service
   - Provide recovery materials
   - May require hardware forensics

---

### Scenario 5: Service Corruption/Uninstall

**Symptoms:**
- Immune Folders service won't start
- Error messages about missing components
- Containers cannot be mounted

**Recovery Steps:**

1. **Service Diagnostics**
   ```powershell
   # Check service status
   Get-Service "ImmuneFoldersService" | Format-List *
   
   # Check event logs
   Get-WinEvent -LogName Application | Where-Object {$_.ProviderName -eq "ImmuneFolders"}
   ```

2. **Reinstall Service**
   ```powershell
   # Preserve existing containers and keys
   .\infra\installer.ps1 -Repair -PreserveData
   ```

3. **Manual Container Mount**
   ```powershell
   # Direct VeraCrypt mounting
   & "C:\Program Files\VeraCrypt\VeraCrypt.exe" /mount C:\ImmuneFolders\folder1.vc /letter X /password "recovered_password"
   ```

4. **Data Extraction**
   - Mount containers manually
   - Copy data to safe location
   - Recreate immune folders with new setup

---

## Recovery Best Practices

### Preparation
- **Test recovery procedures quarterly**
- **Store recovery materials in multiple secure locations**
- **Document all passphrases and store separately from QR codes**
- **Maintain offline backups of critical data**

### During Recovery
- **Use isolated/clean systems when possible**
- **Verify integrity of recovery materials**
- **Document all recovery actions taken**
- **Generate new tokens/QR codes after recovery**

### After Recovery
- **Rotate all secrets (tokens, passphrases, QR codes)**
- **Review audit logs for suspicious activity**
- **Update recovery documentation**
- **Test new setup thoroughly**

---

## Emergency Contacts

**Internal:**
- System Administrator: [Contact Info]
- Security Team: [Contact Info]
- IT Help Desk: [Contact Info]

**External:**
- Data Recovery Service: [Contact Info]
- Cybersecurity Incident Response: [Contact Info]
- Legal/Compliance: [Contact Info]

---

## Recovery Checklist

### Lost USB Token Recovery
- [ ] Locate recovery QR code and passphrase
- [ ] Run recovery mode
- [ ] Scan QR and enter passphrase
- [ ] Generate new USB token
- [ ] Print new recovery QR
- [ ] Test new token
- [ ] Update documentation

### Ransomware Recovery
- [ ] Verify immune containers are intact
- [ ] Boot from clean media if needed
- [ ] Unlock immune folders
- [ ] Backup critical data
- [ ] Format and reinstall system
- [ ] Restore from immune folder backups
- [ ] Reinstall immune folders service
- [ ] Review security posture
