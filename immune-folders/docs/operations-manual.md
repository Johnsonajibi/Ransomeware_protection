# Operations Manual - Immune Folders

## Daily Operations

### Starting Your Workday

1. **Insert USB Token**
   - Plug in your Immune Folders USB token
   - Wait for Windows to recognize the device
   - System tray shows "Token Detected" notification

2. **Automatic Unlock**
   - Immune folders automatically mount within 30 seconds
   - Desktop shortcuts appear for protected folders
   - Notification confirms folders are accessible

3. **Verify Protection Status**
   ```
   System Tray Indicators:
   🔒 Green Lock: All folders protected and accessible
   🔓 Yellow Lock: Some folders accessible, others locked
   ❌ Red X: No protected folders accessible
   ```

### Working with Protected Data

1. **Accessing Files**
   - Use folders normally through Windows Explorer
   - All file operations work transparently
   - Performance may be slightly slower due to encryption

2. **Creating New Files**
   - Save directly into immune folders
   - Files are automatically encrypted
   - No special procedures required

3. **File Sharing**
   ```
   Safe Methods:
   - Copy files OUT of immune folders to share
   - Use secure sharing services for copies
   - Never share the immune folder directly
   
   Prohibited:
   - Network sharing of immune folder paths
   - Giving others access to your USB token
   - Copying immune container files
   ```

### Ending Your Workday

1. **Safe Shutdown Procedure**
   - Close all applications using immune folders
   - Right-click system tray icon → "Safely Lock All Folders"
   - Wait for "All folders locked" confirmation
   - Remove USB token
   - Folders become inaccessible

2. **Emergency Lock**
   ```
   Hotkey: Ctrl+Alt+L (customizable)
   - Immediately locks all immune folders
   - Closes applications accessing protected data
   - Removes desktop shortcuts
   - Shows "Emergency lock activated" notification
   ```

---

## Weekly Operations

### Security Maintenance

1. **Monday: Token Verification**
   - Insert token and verify all folders unlock
   - Check system tray for any error indicators
   - Review weekend audit logs for suspicious activity

2. **Wednesday: Backup Verification**
   - Verify immune folder containers are being backed up
   - Check backup integrity (automated test)
   - Ensure recovery materials are accessible

3. **Friday: Security Update**
   - Install any Immune Folders service updates
   - Review security alerts and notifications
   - Update recovery documentation if needed

### Performance Monitoring

1. **Check Disk Usage**
   ```powershell
   # View immune folder container sizes
   Get-ChildItem "C:\ImmuneFolders\*.vc" | Select-Object Name, @{Name="Size(GB)";Expression={[math]::Round($_.Length/1GB,2)}}
   ```

2. **Monitor System Resources**
   - Watch for high CPU usage during encryption
   - Monitor disk I/O performance
   - Check available disk space for containers

3. **Review Audit Logs**
   ```
   Key Events to Monitor:
   - Failed token authentication attempts
   - Unusual access time patterns
   - Large file operations
   - Service start/stop events
   ```

---

## Monthly Operations

### Security Review

1. **Access Log Analysis**
   - Review all folder mount/unmount events
   - Identify unusual access patterns
   - Verify all access was authorized

2. **Token Health Check**
   - Test USB token on different computers
   - Verify token LED indicator functions
   - Check for physical damage or wear

3. **Recovery Test**
   - Practice QR code recovery procedure
   - Verify recovery passphrase is correct
   - Test backup token (if available)

### System Maintenance

1. **Container Defragmentation**
   ```powershell
   # Optimize immune folder containers
   .\immune-folders\util\maintenance.py --defrag-containers
   ```

2. **Key Rotation** (quarterly)
   ```powershell
   # Rotate folder encryption keys
   .\immune-folders\client\main.py --rotate-keys --verify-backup
   ```

3. **Update Recovery Materials**
   - Generate new recovery QR codes
   - Update printed recovery instructions
   - Store new materials in secure location

---

## Incident Response Procedures

### Suspected Compromise

1. **Immediate Actions**
   ```
   Priority 1: Protect Data
   - Emergency lock all folders (Ctrl+Alt+L)
   - Remove USB token immediately
   - Disconnect from network if possible
   ```

2. **Assessment**
   ```
   Check for:
   - Unusual processes accessing immune folders
   - Modified files in protected directories
   - Failed authentication attempts in logs
   - Network connections to immune folder processes
   ```

3. **Containment**
   ```
   - Keep USB token separate from potentially compromised system
   - Create forensic image of immune folder containers
   - Document all observed indicators
   - Contact security team/administrator
   ```

### System Malfunction

1. **Service Won't Start**
   ```powershell
   # Check service status and logs
   Get-Service "ImmuneFoldersService"
   Get-WinEvent -LogName Application -Source "ImmuneFolders"
   
   # Restart service
   Restart-Service "ImmuneFoldersService" -Force
   ```

2. **Folders Won't Mount**
   ```
   Troubleshooting Steps:
   1. Verify USB token is detected
   2. Check if containers exist and aren't corrupted
   3. Test with backup token (if available)
   4. Use QR recovery method
   5. Contact administrator if all else fails
   ```

3. **Performance Issues**
   ```
   Common Causes:
   - Insufficient disk space
   - Antivirus interference
   - Hardware problems (bad RAM, disk errors)
   - Network storage conflicts
   ```

---

## User Training

### New User Onboarding

1. **Setup Process**
   - Administrator creates immune folders
   - User receives USB token and recovery materials
   - Practice unlock/lock procedures
   - Complete security awareness training

2. **Security Briefing**
   ```
   Critical Points:
   - Never share USB token with anyone
   - Keep recovery QR and passphrase separate
   - Report suspicious activity immediately
   - Follow proper lock/unlock procedures
   ```

3. **Practical Exercises**
   - Normal unlock and work session
   - Emergency lock scenario
   - Lost token recovery simulation
   - Backup and recovery verification

### Ongoing Training

1. **Monthly Security Reminders**
   - Email updates on security best practices
   - Reminders about proper token handling
   - Updates on new threats and protections

2. **Quarterly Drills**
   - Simulated ransomware incident
   - Lost token recovery exercise
   - System failure response
   - Security awareness quiz

3. **Annual Review**
   - Update security training materials
   - Review incident response procedures
   - Assess user compliance and understanding
   - Update operational procedures

---

## Troubleshooting Guide

### Common Issues

1. **"Token Not Recognized"**
   ```
   Solutions:
   - Try different USB port
   - Restart Immune Folders service
   - Check Windows Device Manager
   - Verify token isn't physically damaged
   ```

2. **"Folder Already Mounted"**
   ```
   Solutions:
   - Close all applications using the folder
   - Use "Force Unmount" option
   - Restart computer if necessary
   - Check for hidden processes
   ```

3. **"Authentication Failed"**
   ```
   Solutions:
   - Verify correct USB token
   - Check system time is accurate
   - Try backup token if available
   - Use QR recovery method
   ```

4. **Slow Performance**
   ```
   Solutions:
   - Check available disk space
   - Exclude immune folders from antivirus scans
   - Increase container size if fragmented
   - Consider hardware upgrade
   ```

### Advanced Diagnostics

1. **Enable Debug Logging**
   ```powershell
   .\immune-folders\util\debug.py --enable-verbose-logging
   ```

2. **Container Integrity Check**
   ```powershell
   .\immune-folders\util\verify.py --check-containers --repair
   ```

3. **Token Diagnostics**
   ```powershell
   .\immune-folders\util\token-test.py --comprehensive-test
   ```

---

## Configuration Management

### User Settings

1. **Auto-Lock Timeout**
   ```
   Default: 30 minutes of inactivity
   Range: 5 minutes to 4 hours
   Configuration: System tray → Settings → Security
   ```

2. **Emergency Lock Hotkey**
   ```
   Default: Ctrl+Alt+L
   Customizable: System Settings → Hotkeys
   Note: Cannot be disabled for security
   ```

3. **Notification Preferences**
   ```
   Options:
   - Show all notifications (default)
   - Critical notifications only
   - Silent mode (not recommended)
   ```

### Administrator Settings

1. **Policy Configuration**
   ```
   Location: C:\ImmuneFolders\config\policy.json
   
   Key Settings:
   - Maximum idle time before auto-lock
   - Failed authentication attempt limits
   - Audit log retention period
   - Recovery method availability
   ```

2. **Enterprise Features**
   ```
   - Centralized key management
   - Group policy integration
   - Remote lock capabilities
   - Compliance reporting
   ```

---

## Compliance and Auditing

### Audit Trail

1. **Events Logged**
   ```
   Security Events:
   - Token insertion/removal
   - Folder mount/unmount
   - Authentication success/failure
   - Configuration changes
   - Emergency lock activation
   
   Operational Events:
   - Service start/stop
   - Container creation/deletion
   - Backup operations
   - Maintenance activities
   ```

2. **Log Format**
   ```
   Timestamp | Event Type | User | Details | Result
   2024-01-15 09:30:15 | MOUNT | user1 | Folder: Documents | SUCCESS
   2024-01-15 09:30:45 | AUTH_FAIL | user1 | Invalid token | DENIED
   ```

3. **Log Protection**
   - Tamper-evident cryptographic signatures
   - Stored in separate immune container
   - Automatic backup to secure location
   - Retention based on compliance requirements

### Compliance Reports

1. **Weekly Access Report**
   - Summary of all folder access
   - Failed authentication attempts
   - Emergency lock activations
   - Performance metrics

2. **Monthly Security Report**
   - Security incidents and responses
   - System vulnerabilities and patches
   - User training completion status
   - Recovery test results

3. **Annual Audit Report**
   - Comprehensive security assessment
   - Compliance with regulations
   - Risk analysis and mitigation
   - Recommendations for improvement
