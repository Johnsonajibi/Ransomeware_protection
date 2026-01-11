# Anti-Ransomware Executables

## Built Packages

Successfully packaged Python applications to standalone Windows executables:

### 1. AntiRansomware-TriFactor.exe (23.5 MB)
- **Source:** trifactor_auth_manager.py
- **Type:** Console application
- **Features:**
  - Tri-factor authentication manager
  - TPM 2.0 integration
  - Device fingerprinting (6-8 hardware layers)
  - Post-quantum USB authentication (Dilithium3)
  - Token generation and management
  - Audit logging system
- **Requirements:** Administrator privileges for TPM access
- **Usage:** Command-line tool for managing authentication tokens

### 2. AntiRansomware-GUI.exe (52.1 MB)
- **Source:** desktop_app.py
- **Type:** Windowed application (PyQt6)
- **Features:**
  - Modern graphical user interface
  - Real-time protection monitoring
  - File system event tracking
  - Protection statistics dashboard
  - System tray integration
  - Configuration management
- **Requirements:** Administrator privileges
- **Usage:** Desktop GUI for ransomware protection management

## Running the Applications

### Tri-Factor Authentication Manager
```powershell
# Run as administrator
.\dist\AntiRansomware-TriFactor.exe

# View available commands
.\dist\AntiRansomware-TriFactor.exe --help
```

### Desktop GUI
```powershell
# Double-click to run, or:
.\dist\AntiRansomware-GUI.exe
```

## Distribution

Both executables are standalone and include all dependencies:
- Python runtime
- Cryptography libraries
- Windows API bindings (pywin32)
- TPM/WMI integration
- GUI framework (PyQt6 for GUI version)

No Python installation required on target system.

## Deployment

1. Copy executables to target Windows 10/11 system
2. Right-click → "Run as administrator"
3. Windows Defender SmartScreen may show warning (expected for unsigned executables)
4. Click "More info" → "Run anyway"

## Security Notes

- Executables require UAC elevation (administrator rights)
- Test signing required for kernel driver component
- TPM functionality requires admin privileges
- Built with PyInstaller 6.16.0

## Build Information

- **Build Date:** December 27, 2025
- **Python Version:** 3.11.9
- **Platform:** Windows 10/11 x64
- **Build Tool:** PyInstaller 6.16.0
- **Compression:** Single-file executables (--onefile)

## File Verification

To verify executables:
```powershell
# Check file hashes
Get-FileHash .\dist\AntiRansomware-TriFactor.exe -Algorithm SHA256
Get-FileHash .\dist\AntiRansomware-GUI.exe -Algorithm SHA256
```

## Rebuilding

To rebuild executables:
```powershell
# Build specific component
python build_exe.py trifactor_auth
python build_exe.py desktop_gui
python build_exe.py admin_dashboard

# Build all components
python build_exe.py all
```
