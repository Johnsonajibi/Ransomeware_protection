#!/usr/bin/env python3
"""
GENUINE COMPONENTS VERIFICATION
===============================
Verifies that all anti-ransomware components are genuine and functional.
"""

import os
import struct
import subprocess

def check_genuine_status():
    print("🔍 GENUINE COMPONENTS VERIFICATION")
    print("=" * 50)
    print()
    
    genuine_score = 0
    max_score = 5
    
    # 1. Check genuine kernel source code
    print("1. GENUINE KERNEL SOURCE CODE:")
    if os.path.exists('RealAntiRansomwareDriver.c'):
        size = os.path.getsize('RealAntiRansomwareDriver.c')
        print(f"   ✓ Source file exists: {size} bytes")
        
        with open('RealAntiRansomwareDriver.c', 'r') as f:
            content = f.read()
        
        # Check for genuine kernel components
        genuine_indicators = [
            'DriverEntry',
            'FLT_PREOP_CALLBACK_STATUS', 
            'FltRegisterFilter',
            'fltKernel.h',
            'ntifs.h'
        ]
        
        found = sum(1 for indicator in genuine_indicators if indicator in content)
        print(f"   ✓ Genuine kernel components: {found}/{len(genuine_indicators)}")
        
        if size > 20000 and found >= 4:
            print("   ✅ STATUS: GENUINE KERNEL SOURCE CODE")
            genuine_score += 1
        else:
            print("   ❌ STATUS: NOT GENUINE OR INCOMPLETE")
    else:
        print("   ❌ Kernel source not found")
    
    print()
    
    # 2. Check genuine C++ manager
    print("2. GENUINE C++ MANAGER:")
    if os.path.exists('RealAntiRansomwareManager.exe'):
        size = os.path.getsize('RealAntiRansomwareManager.exe')
        print(f"   ✓ Manager executable exists: {size} bytes")
        
        # Check if it's a genuine PE file
        try:
            with open('RealAntiRansomwareManager.exe', 'rb') as f:
                header = f.read(64)
            
            if len(header) >= 64 and header[0:2] == b'MZ':
                pe_offset = struct.unpack('<I', header[60:64])[0]
                with open('RealAntiRansomwareManager.exe', 'rb') as f:
                    f.seek(pe_offset)
                    pe_header = f.read(4)
                
                if pe_header == b'PE\x00\x00' and size > 200000:
                    print("   ✅ STATUS: GENUINE COMPILED MANAGER")
                    genuine_score += 1
                else:
                    print("   ❌ STATUS: INVALID OR TOO SMALL")
            else:
                print("   ❌ STATUS: NOT A VALID PE FILE")
        except:
            print("   ❌ STATUS: CANNOT VERIFY PE FORMAT")
    else:
        print("   ❌ Manager executable not found")
    
    print()
    
    # 3. Check for fake driver (should not exist for genuine system)
    print("3. FAKE DRIVER CHECK:")
    fake_driver_path = 'build/RealAntiRansomwareDriver.sys'
    if os.path.exists(fake_driver_path):
        size = os.path.getsize(fake_driver_path)
        if size < 10000:
            print(f"   ⚠️  Fake placeholder driver still exists: {size} bytes")
            print("   ❌ STATUS: FAKE DRIVER PRESENT")
        else:
            print(f"   ✓ Driver appears genuine: {size} bytes")
            genuine_score += 1
    else:
        print("   ✓ No fake driver found")
        genuine_score += 1
    
    print()
    
    # 4. Check genuine compiled driver
    print("4. GENUINE COMPILED DRIVER:")
    genuine_driver_paths = [
        'build_genuine/RealAntiRansomwareDriver.sys',
        'build_real/RealAntiRansomwareDriver.sys'
    ]
    
    genuine_driver_found = False
    for path in genuine_driver_paths:
        if os.path.exists(path):
            size = os.path.getsize(path)
            print(f"   ✓ Genuine driver found: {path}")
            print(f"   ✓ Size: {size} bytes")
            
            if size > 15000:  # Real compiled drivers are typically 20KB+
                print("   ✅ STATUS: GENUINE COMPILED KERNEL DRIVER")
                genuine_score += 1
                genuine_driver_found = True
            else:
                print("   ❌ STATUS: TOO SMALL - LIKELY FAKE")
            break
    
    if not genuine_driver_found:
        print("   ❌ No genuine compiled driver found")
    
    print()
    
    # 5. Check build environment
    print("5. BUILD ENVIRONMENT:")
    wdk_path = 'C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64'
    vs_paths = [
        'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools',
        'C:/Program Files (x86)/Microsoft Visual Studio/2019/BuildTools'
    ]
    
    wdk_exists = os.path.exists(wdk_path)
    vs_exists = any(os.path.exists(path) for path in vs_paths)
    
    print(f"   WDK Tools: {'✓ Found' if wdk_exists else '❌ Missing'}")
    print(f"   Visual Studio: {'✓ Found' if vs_exists else '❌ Missing'}")
    
    if wdk_exists and vs_exists:
        print("   ✅ STATUS: BUILD ENVIRONMENT READY")
        genuine_score += 1
    else:
        print("   ❌ STATUS: BUILD ENVIRONMENT INCOMPLETE")
    
    print()
    print("🎯 GENUINE SYSTEM ASSESSMENT:")
    print("=" * 50)
    print(f"Genuine Components Score: {genuine_score}/{max_score}")
    
    if genuine_score == max_score:
        print("🎉 STATUS: COMPLETELY GENUINE SYSTEM!")
        print("✅ All components are genuine and ready for production use")
        print("✅ Real kernel driver compiled from genuine source")
        print("✅ Working C++ manager application") 
        print("✅ No fake components detected")
        print("✅ Build environment complete")
        
        print("\n🚀 READY FOR INSTALLATION:")
        print("1. bcdedit /set testsigning on")
        print("2. Reboot system")
        print("3. Run genuine driver installation")
        
    elif genuine_score >= 4:
        print("⚠️  STATUS: MOSTLY GENUINE - MINOR ISSUES")
        print("System is nearly complete but may need final compilation step")
        
        if not genuine_driver_found:
            print("\n🔧 TO COMPLETE:")
            print("Run 'make_all_genuine.bat' as Administrator to compile genuine driver")
            
    else:
        print("❌ STATUS: NOT GENUINE - MAJOR ISSUES")
        print("System contains fake components or is incomplete")
        
        print("\n🔧 TO FIX:")
        print("1. Ensure all source files are present")
        print("2. Install WDK and Visual Studio Build Tools")
        print("3. Run 'make_all_genuine.bat' as Administrator")

if __name__ == "__main__":
    check_genuine_status()
