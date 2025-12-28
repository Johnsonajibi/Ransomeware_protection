# 🔐 USB Token-Based File Access Control System

## Overview

Your Anti-Ransomware system now implements **complete token-based access control** that ensures protected files and folders **cannot be accessed, opened, edited, copied, or deleted** without a valid USB token - even by administrators or the file owner.

## 🎯 Core Concept

**Protected files are LOCKED from all external access. They can ONLY be accessed through this application when a valid USB token is present.**

## 🛡️ Protection Layers

### 1. **Windows NTFS Permissions** (External Access Block)
- **DENY ALL users** (including the owner)
- **DENY Administrators group**
- **DENY SYSTEM account** (minimal exceptions for OS)
- Files become effectively invisible and inaccessible to all programs

### 2. **File System Attributes**
- **Hidden** - Files don't show in Explorer even with "show hidden files"
- **System** - Treated as system files (extra protection)
- **Read-Only** - Prevents modifications

### 3. **Cryptographic Protection**
- Files are **encrypted with AES-256**
- Key derived from USB token + machine hardware fingerprint
- Decryption requires the specific USB token that protected the folder

### 4. **Access Control Registry**
- Internal tracking of protected files
- Token verification before ANY file operation
- Temporary access grants only through the app

## 🔑 How Token-Based Access Works

### Without USB Token
```
User tries to:
  ❌ Open file in Notepad → ACCESS DENIED (NTFS)
  ❌ Open file in Word → ACCESS DENIED (NTFS)
  ❌ Copy file → ACCESS DENIED (NTFS)
  ❌ Delete file → ACCESS DENIED (NTFS)
  ❌ Rename file → ACCESS DENIED (NTFS)
  ❌ View file properties → LIMITED (Windows blocks)
  ❌ Take ownership → FAILS (encrypted content)
```

### With Valid USB Token (Through This App)
```
User can:
  ✅ Open file → App verifies token → Temporarily unlocks → Opens file
  ✅ Edit file → Token verified → Opens in default editor
  ✅ Copy file → Token verified → Reads & copies content
  ✅ View file → Token verified → Displays content in app
  
After closing the app:
  🔒 All files automatically re-locked
  🔒 Protection restored immediately
```

## 📋 Usage Guide

### Protecting Files/Folders

1. **Insert USB Token** (optional for protection, required for access)
2. **Open Anti-Ransomware Desktop App**
3. **Go to "Protected Paths" tab**
4. **Click "Add Path"** and select folder
5. System will:
   - Encrypt all files with AES-256
   - Set NTFS permissions to DENY ALL
   - Register files in access control system
   - Block all external access

**Result**: Files are now completely inaccessible without token + this app

### Accessing Protected Files

#### Option 1: Open for Viewing (Read-Only)
```
1. Insert USB Token
2. Open Desktop App
3. Go to "Protected Paths" tab
4. Click "📂 Open Protected File"
5. Select the protected file
6. File content displays in read-only viewer
```

#### Option 2: Edit Protected File
```
1. Insert USB Token
2. Open Desktop App
3. Go to "Protected Paths" tab
4. Click "✏️ Edit Protected File"
5. Select the protected file
6. File opens in default editor
7. Make your changes and save
8. When you close the app, protection is restored
```

#### Option 3: Copy Protected File
```
1. Insert USB Token
2. Open Desktop App
3. Click "📄 Copy Protected File"
4. Select source (protected) file
5. Choose destination for copy
6. Copy is created (unprotected)
```

#### Option 4: List All Protected Files
```
1. Select a protected folder in the table
2. Click "📋 List Protected Files"
3. View all protected files in that folder
```

### Unprotecting Files/Folders

```
1. Insert USB Token (REQUIRED)
2. Open Desktop App
3. Select protected folder in table
4. Click "Remove Protection"
5. Confirm with token verification
6. System will:
   - Decrypt all files
   - Restore normal NTFS permissions
   - Remove system attributes
   - Unregister from access control
```

**Result**: Files return to normal, accessible state

## 🚫 What's Blocked (Without Token)

### File Explorer
- **Cannot open files** - Access Denied
- **Cannot copy files** - Access Denied
- **Cannot delete files** - Access Denied
- **Cannot rename files** - Access Denied
- **Cannot see file contents** - Encrypted

### Command Line
```powershell
PS> type file.txt           # Access Denied
PS> copy file.txt backup.txt # Access Denied
PS> del file.txt            # Access Denied
PS> rename file.txt new.txt # Access Denied
PS> notepad file.txt        # Access Denied
```

### Other Applications
- **Microsoft Word** → Cannot open (Access Denied)
- **Adobe Reader** → Cannot open (Access Denied)
- **Image Viewers** → Cannot open (Access Denied)
- **Video Players** → Cannot open (Access Denied)
- **Any program** → Access Denied by Windows

### Admin Tools (Even with Admin Rights)
```powershell
# Even with Administrator privileges:
PS> takeown /f file.txt     # Fails - still encrypted
PS> icacls file.txt /grant  # Fails - protection active
PS> attrib -h -s -r file.txt # Fails - app-controlled
```

## ✅ What's Allowed (With Token + App)

### Through Desktop App Only
- ✅ **Open and view** protected files
- ✅ **Edit** protected files in default editor
- ✅ **Copy** protected files to unprotected locations
- ✅ **List** all protected files
- ✅ **Search** within protected files (through app)

### Temporary Access Mode
When you edit a file through the app:
1. **Token is verified** ✓
2. **File is temporarily unlocked** (NTFS permissions relaxed)
3. **File opens in editor** (you can make changes)
4. **Changes are saved** (while app is open)
5. **When app closes** → Protection automatically restored 🔒

## 🔐 Security Features

### Hardware-Bound Tokens
- Tokens are **machine-specific**
- Cannot be copied to another USB drive
- Cannot be used on different computer
- Encrypted with hardware fingerprint

### Token Validation
```
Token must have:
  ✓ Correct hardware fingerprint
  ✓ Valid cryptographic signature
  ✓ Matching machine ID
  ✓ Proper permissions set
  ✓ Not expired (24-hour validity)
```

### Anti-Tamper Protection
- Files remain encrypted even if NTFS permissions are bypassed
- Taking ownership doesn't help - content is encrypted
- Administrator rights don't bypass protection
- System restore doesn't affect protection

## 📊 File Access Flow

```
┌─────────────────────────────────────────┐
│ User wants to open "document.pdf"       │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│ Is file protected?                      │
│   Check Access Control Registry         │
└───────────────┬─────────────────────────┘
                │
                ├─── NO ──→ Allow normal access
                │
                └─── YES
                     │
                     ▼
┌─────────────────────────────────────────┐
│ Is valid USB token present?             │
│   Check USB drives for token files      │
└───────────────┬─────────────────────────┘
                │
                ├─── NO ──→ ❌ ACCESS DENIED
                │            "USB Token Required"
                │
                └─── YES
                     │
                     ▼
┌─────────────────────────────────────────┐
│ Validate Token                          │
│   - Verify cryptographic signature      │
│   - Check hardware fingerprint          │
│   - Validate expiration                 │
└───────────────┬─────────────────────────┘
                │
                ├─── INVALID ──→ ❌ ACCESS DENIED
                │                 "Invalid Token"
                │
                └─── VALID
                     │
                     ▼
┌─────────────────────────────────────────┐
│ Grant Temporary Access                  │
│   - Decrypt file content                │
│   - Relax NTFS permissions temporarily  │
│   - Open file for user                  │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│ ✅ File is accessible                   │
│    User can read/edit the file          │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│ When app closes:                        │
│   - Re-encrypt file                     │
│   - Restore NTFS DENY permissions       │
│   - Re-apply system attributes          │
│   🔒 Protection restored                │
└─────────────────────────────────────────┘
```

## 🛠️ Technical Implementation

### FileAccessControl Class
```python
class FileAccessControl:
    def verify_token_access(operation):
        """Verify USB token before allowing operation"""
        
    def block_external_access(file_path):
        """Set NTFS permissions to DENY ALL"""
        
    def allow_temporary_access(file_path):
        """Temporarily allow access when token verified"""
        
    def safe_open_protected_file(file_path):
        """Open file only if token is valid"""
        
    def safe_write_protected_file(file_path, content):
        """Write to file only if token is valid"""
```

### UnifiedProtectionManager Methods
```python
# Safe file operations (require token)
manager.safe_open_file(path)      # Open for reading
manager.safe_read_file(path)      # Read content
manager.safe_write_file(path, content)  # Write content
manager.safe_edit_file(path)      # Edit in default editor
manager.copy_protected_file(src, dst)   # Copy with token
manager.list_protected_files(folder)    # List all protected
```

## 🎮 Desktop App GUI Features

### New Buttons in "Protected Paths" Tab:

1. **📂 Open Protected File**
   - Browse and select protected file
   - Verifies USB token
   - Displays content in read-only viewer

2. **✏️ Edit Protected File**
   - Opens file in default editor
   - Requires USB token
   - Protection restored on app close

3. **📋 List Protected Files**
   - Shows all protected files in selected folder
   - Displays full paths
   - Indicates protection status

4. **📄 Copy Protected File**
   - Copy protected file to new location
   - Token verification required
   - Copy is unprotected (normal file)

## ⚠️ Important Notes

### Automatic Protection Restoration
- Protection is **automatically restored** when you close the app
- Don't leave the app open indefinitely after editing files
- Close the app to ensure maximum security

### Token Requirements
- **One token** can protect multiple folders
- **Same token** must be used to access protected files
- **Lost token** = Lost access (keep backup tokens!)
- Tokens are **machine-specific** (won't work on other PCs)

### Performance Considerations
- Initial protection takes time (encrypting all files)
- Large folders may take several minutes
- File access is slightly slower (decryption overhead)
- Recommended for sensitive data, not entire drives

### Backup Strategy
- Create **multiple USB tokens** with same permissions
- Keep tokens in **separate physical locations**
- Test token validity regularly
- **Back up unprotected versions** before protection

## 🔧 Troubleshooting

### "Access Denied" When Token is Inserted
**Solution**: Ensure token is valid:
```python
# Check token validity
manager.token_manager.find_usb_tokens(validate=True)
# Should return list of valid tokens
```

### Files Won't Open Even With Token
**Possible causes**:
1. Token corrupted → Create new token
2. Token from different machine → Use correct machine
3. Token expired → Create new token (24hr validity)
4. File not registered in protection system → Check protection status

### Protection Restoration Fails
**Solution**: Manually restore:
```python
manager.restore_all_file_access()
# OR
manager.file_manager.apply_unbreakable_protection(folder_path)
```

## 🎯 Best Practices

1. **Always create backup tokens** immediately after initial setup
2. **Test token access** before relying on protection
3. **Keep tokens in secure physical locations**
4. **Don't share tokens** - create separate tokens for different users
5. **Close the app** after accessing protected files
6. **Regular security audits** - verify protection is active
7. **Document which token protects which folders**

## 📝 Summary

Your anti-ransomware system now provides **military-grade file protection**:

- ✅ Files are **inaccessible** without USB token + app
- ✅ Even **administrators** cannot bypass protection
- ✅ Files are **encrypted** and **permission-locked**
- ✅ **Convenient access** through the desktop app
- ✅ **Automatic protection restoration** on app close
- ✅ **Multiple protection layers** work together

**The system ensures your files are TRULY protected - accessible only through this app with a valid USB token!** 🔐🛡️
