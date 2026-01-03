# WDK Kernel Driver Setup & Compilation Guide

## Overview
This guide provides step-by-step instructions to compile the kernel minifilter driver (`antiransomware_minifilter.c`) into a Windows system driver file (`.sys`).

**Estimated Time:** 2-3 hours (mostly downloads)
**Difficulty:** Intermediate (following steps exactly)
**Operating System:** Windows 10 or Windows 11
**User Rights:** Administrator required

---

## Phase 1: System Prerequisites (15 minutes)

### Check Your System
```powershell
# Run as Administrator in PowerShell
$winver = [Environment]::OSVersion.Version
Write-Host "Windows Version: $winver"

# You need Windows 10 Version 2004+ or Windows 11
if ($winver.Build -ge 19041) {
    Write-Host "✓ System compatible for WDK"
} else {
    Write-Host "✗ Please update Windows first"
}
```

### Disk Space Required
- Visual Studio 2022: ~25 GB (with C++ workload)
- Windows Driver Kit 11: ~8 GB
- Temporary build files: ~2 GB
- **Total: 35+ GB free space required**

Check available space:
```powershell
# Check C: drive space
Get-Volume -DriveLetter C | Select-Object SizeRemaining
```

---

## Phase 2: Install Visual Studio 2022 (45 minutes)

### Step 1: Download Visual Studio Community 2022
1. Go to https://visualstudio.microsoft.com/downloads/
2. Click **"Download Visual Studio Community 2022"**
3. Run the installer (`VisualStudioSetup.exe`)

### Step 2: Configure Installation
In the Visual Studio Installer:
1. Click **"Modify"** (if already installed) or proceed with installation
2. Go to **"Workloads"** tab
3. Check: **"Desktop development with C++"**
   - This includes MSVC compiler, Windows SDK, and CMake
4. Check: **"Windows application development"** (optional but recommended)
5. Click **"Install"** (bottom right)
6. Accept all licenses and wait for installation (~30 min)

### Step 3: Verify Installation
```powershell
# Check Visual Studio installation
$vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community"
if (Test-Path $vsPath) {
    Write-Host "✓ Visual Studio 2022 installed at: $vsPath"
} else {
    Write-Host "✗ Visual Studio 2022 not found"
}

# Verify C++ compiler
$clPath = "$vsPath\VC\Tools\MSVC"
if (Test-Path $clPath) {
    Write-Host "✓ MSVC C++ compiler found"
}
```

---

## Phase 3: Install Windows Driver Kit 11 (30 minutes)

### Step 1: Download WDK 11
1. Go to https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
2. Download **"Windows Driver Kit Version 11"**
3. Run the installer (`WDK11Setup.exe`)

### Step 2: Configure WDK Installation
In the WDK Installer:
1. Select installation path (default: `C:\Program Files (x86)\Windows Kits\11`)
2. Check **"Windows Driver Kit"** (main component)
3. Uncheck **"Debugging Tools"** (optional)
4. Click **"Install"**
5. Wait for installation (~20 min)

### Step 3: Verify WDK Installation
```powershell
# Check WDK installation
$wdkPath = "C:\Program Files (x86)\Windows Kits\11"
if (Test-Path $wdkPath) {
    Write-Host "✓ Windows Driver Kit installed at: $wdkPath"
} else {
    Write-Host "✗ Windows Driver Kit not found"
}

# Check Filter Driver headers
$filterPath = "$wdkPath\Include\10.0.22621.0\fltKernel"
if (Test-Path $filterPath) {
    Write-Host "✓ Filter Driver headers available"
}
```

---

## Phase 4: Setup Visual Studio Project (10 minutes)

### Step 1: Create New Driver Project
1. Open **Visual Studio 2022**
2. Click **"Create a new project"**
3. Search for: **"Windows Driver Kit"**
4. Select: **"Kernel Mode Driver, Empty (KMDF)"** or **"Windows Filtering Platform Driver"**
5. Click **"Next"**
6. Project Name: `AntiRansomwareFilter`
7. Location: `C:\Users\ajibi\Music\Anti-Ransomeware\`
8. Click **"Create"**

### Step 2: Add Source File
1. In Solution Explorer (right side), right-click **"Source Files"**
2. Select **"Add" → "Existing Item"**
3. Browse to `antiransomware_minifilter.c`
4. Click **"Add"**
5. Delete the default `driver.c` file if created

### Step 3: Verify Project Configuration
1. Right-click **"AntiRansomwareFilter"** project
2. Select **"Properties"**
3. Verify:
   - Configuration: **Release**
   - Platform: **x64**
   - Windows SDK Version: **10.0.22621.0** (or latest available)

---

## Phase 5: Configure Project Settings (5 minutes)

### Step 1: Include Paths
1. Right-click project → **"Properties"**
2. Go to **"C/C++"** → **"General"**
3. Verify **"Additional Include Directories"** contains:
   ```
   C:\Program Files (x86)\Windows Kits\11\Include\10.0.22621.0\km
   C:\Program Files (x86)\Windows Kits\11\Include\10.0.22621.0\shared
   ```
   (Should be auto-added by WDK template)

### Step 2: Linker Settings
1. Go to **"Linker"** → **"General"**
2. Verify **"Additional Library Directories"** contains:
   ```
   C:\Program Files (x86)\Windows Kits\11\Lib\10.0.22621.0\km\x64
   ```

---

## Phase 6: Compile the Driver (5 minutes)

### Option A: Compile in Visual Studio (Easiest)
1. In Visual Studio menu: **"Build"** → **"Configuration Manager"**
2. Select **"Release"** and **"x64"**
3. Menu: **"Build"** → **"Build Solution"** (or **Ctrl+Shift+B**)
4. Watch the output window for compilation

**Output location:**
```
C:\Users\ajibi\Music\Anti-Ransomeware\x64\Release\AntiRansomwareFilter.sys
```

### Option B: Compile via Command Line (Advanced)
```powershell
# In PowerShell as Administrator
cd "C:\Users\ajibi\Music\Anti-Ransomeware"

# Setup build environment
$vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community"
& "$vsPath\VC\Auxiliary\Build\vcvars64.bat"

# Build using MSBuild
$msbuild = "$vsPath\MSBuild\Current\Bin\MSBuild.exe"
& $msbuild "AntiRansomwareFilter.vcxproj" /p:Configuration=Release /p:Platform=x64
```

### Verify Compilation Success
```powershell
# Check if .sys file was created
$sysFile = "C:\Users\ajibi\Music\Anti-Ransomeware\x64\Release\AntiRansomwareFilter.sys"
if (Test-Path $sysFile) {
    $size = (Get-Item $sysFile).Length
    Write-Host "✓ Driver compiled successfully"
    Write-Host "  File: $sysFile"
    Write-Host "  Size: $size bytes"
} else {
    Write-Host "✗ Compilation failed - .sys file not found"
}
```

---

## Phase 7: Code Signing (Windows 11 Only - IMPORTANT)

### For Windows 11
Windows 11 requires code signing for kernel drivers. Without signing, the driver cannot be loaded.

#### Option A: Test Signing (Development Only)
```powershell
# Enable Test Mode (allows unsigned drivers)
bcdedit /set testsigning on

# Reboot required
Restart-Computer -Force
```

After reboot, verify:
```powershell
# Check if test mode is on
bcdedit | Find "testsigning"
# Should show: testsigning Yes
```

#### Option B: Proper Code Signing (Production)
This requires an EV (Extended Validation) code signing certificate from Microsoft or a CA.
1. Purchase EV certificate from authorized CA
2. Use `signtool.exe` to sign the driver
3. Run as Administrator

---

## Phase 8: Deploy the Driver (5 minutes)

### Step 1: Copy Driver File
```powershell
# Run as Administrator
$sysFile = "C:\Users\ajibi\Music\Anti-Ransomeware\x64\Release\AntiRansomwareFilter.sys"
$driverDir = "C:\Windows\System32\drivers\"

if (Test-Path $sysFile) {
    Copy-Item -Path $sysFile -Destination $driverDir -Force
    Write-Host "✓ Driver copied to: $driverDir"
} else {
    Write-Host "✗ .sys file not found at: $sysFile"
}
```

### Step 2: Load the Driver
The `kernel_driver_loader.py` will automatically load the driver from `C:\Windows\System32\drivers\` when your application starts.

---

## Phase 9: Verify Driver Loading

### Check Driver Status
```powershell
# Run this in your Python application
python -c "
from kernel_driver_loader import get_kernel_driver
driver = get_kernel_driver()
status = driver.get_driver_status()
print(f'Driver Status: {status}')
"
```

### Check Windows Event Log
```powershell
# View driver-related events
Get-EventLog -LogName System -Source "AntiRansomwareFilter" -Newest 10
```

---

## Troubleshooting

### Problem: "fltKernel.h not found" during compilation
**Solution:**
1. Reinstall Windows Driver Kit
2. Verify WDK installation path in Visual Studio:
   - File → Options → Projects and Solutions → VC++ Directories
   - Make sure Include Directories point to WDK headers

### Problem: Compilation errors about undefined macros
**Solution:**
1. Check that project is set to **Release** and **x64**
2. Verify `#include <fltkernel.h>` is present (case-sensitive on some systems)
3. Update Windows SDK version to match WDK (usually 10.0.22621.0)

### Problem: "Driver load failed" when running application
**Solution:**
1. Verify .sys file exists in `C:\Windows\System32\drivers\`
2. Check Windows Event Log for detailed error
3. On Windows 11, ensure test signing is enabled (see Phase 7)
4. Restart computer to clear any stuck driver state

### Problem: "Access Denied" when loading driver
**Solution:**
1. Run application as Administrator
2. Verify file permissions on .sys file
3. Check that System account can read the driver file

---

## Integration with Application

Once the driver is compiled and deployed, it will automatically be used:

1. `kernel_driver_loader.py` detects the .sys file in `C:\Windows\System32\drivers\`
2. `four_layer_protection.py` attempts to load it as the primary Layer 1
3. If loading succeeds, your protected files are protected by kernel-level driver
4. If loading fails, it automatically falls back to Python kernel blocker
5. Fallback to NTFS + CFA + Encryption if needed

---

## Comparison: This Approach vs Python Alternative

| Feature | WDK Driver | Python Blocker |
|---------|-----------|-----------------|
| **Performance** | ⭐⭐⭐⭐⭐ Fastest | ⭐⭐⭐ Good |
| **Reliability** | ⭐⭐⭐⭐⭐ Most reliable | ⭐⭐⭐⭐ Reliable |
| **Stealth** | ⭐⭐⭐⭐⭐ Hidden from userspace | ⭐⭐⭐ Visible as process |
| **Setup Time** | 2-3 hours | 0 minutes (already done) |
| **Expertise** | Advanced (requires WDK) | Intermediate (Python) |
| **Official Support** | Microsoft supported | Python + Windows APIs |
| **License Compliance** | ✓ Full compliance | ✓ Full compliance |
| **Production Ready** | ✓ Yes (with code signing) | ✓ Yes (for development) |

---

## Next Steps

1. ✓ **Install Visual Studio 2022** (Phase 1-2)
2. ✓ **Install WDK 11** (Phase 3)
3. ✓ **Create project and compile** (Phase 4-6)
4. ✓ **Sign driver (if Windows 11)** (Phase 7)
5. ✓ **Deploy .sys file** (Phase 8)
6. ✓ **Run application** - driver auto-loads
7. ✓ **Verify loading** - check status

---

## Questions?

The `kernel_driver_loader.py` has detailed logging. Run with:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
from kernel_driver_loader import get_kernel_driver
```

This will show exactly what's happening during driver load.
