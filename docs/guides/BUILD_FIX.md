# How to Fix Build Errors

## Problem
Your Visual Studio 2022 installation is missing the C++ standard library headers (iostream, string, vector, etc.)

## Solution: Install Visual Studio C++ Components

### Option 1: Visual Studio Installer (Recommended)

1. Open **Visual Studio Installer**
2. Click **Modify** on Visual Studio 2022
3. Check **"Desktop development with C++"**
4. Make sure these components are selected:
   - MSVC v143 - VS 2022 C++ x64/x86 build tools
   - Windows 10 SDK (10.0.26100.0)
   - C++ ATL for latest v143 build tools
   - C++ MFC for latest v143 build tools
5. Click **Modify** and wait for installation

###Option 2: Install Build Tools Only

Download and install: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022

Select "Desktop development with C++"

## After Installation

Run the compile script again:
```powershell
.\compile.bat
```

## Quick Test

This should work after proper installation:
```cmd
"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
cl /?
```

If you see the compiler help, you're ready to build.

## Alternative: Use the Original File

The original `RealAntiRansomwareManager.cpp` (529 lines) is simpler and might work with minimal setup.

Try:
```cmd
cl RealAntiRansomwareManager.cpp setupapi.lib newdev.lib cfgmgr32.lib /Fe:RealAntiRansomwareManager.exe
```
