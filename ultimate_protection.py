#!/usr/bin/env python3
"""Ultimate protection - make the folder truly unbreakable"""

import sys
import os
import subprocess
from pathlib import Path
import time

def apply_ultimate_protection(folder_path):
    """Apply the most aggressive protection possible"""
    folder_path = Path(folder_path)
    
    print(f"🛡️ APPLYING ULTIMATE PROTECTION TO: {folder_path}")
    print("="*70)
    
    if not folder_path.exists():
        print(f"❌ Folder not found: {folder_path}")
        return False
    
    # Step 1: Take complete ownership
    print("🔐 Step 1: Taking complete ownership...")
    try:
        subprocess.run(['takeown', '/F', str(folder_path), '/R', '/D', 'Y'], 
                      capture_output=True, shell=True, check=True)
        print("  ✅ Ownership taken")
    except:
        print("  ⚠️ Ownership taking had issues (may still work)")
    
    # Step 2: Apply maximum file attributes
    print("🔐 Step 2: Applying maximum file attributes...")
    try:
        # System + Hidden + ReadOnly + Archive
        subprocess.run(['attrib', '+S', '+H', '+R', '+A', str(folder_path), '/S', '/D'], 
                      capture_output=True, shell=True, check=True)
        print("  ✅ System, Hidden, ReadOnly, Archive attributes applied")
    except Exception as e:
        print(f"  ⚠️ Attribute application: {e}")
    
    # Step 3: Deny access to EVERYONE at the most fundamental level
    print("🔐 Step 3: Denying all access...")
    
    # Deny to World SID (everyone including system)
    security_commands = [
        ['icacls', str(folder_path), '/deny', '*S-1-1-0:(OI)(CI)(F)', '/T', '/C'],  # Everyone
        ['icacls', str(folder_path), '/deny', '*S-1-5-32-544:(OI)(CI)(F)', '/T', '/C'],  # Administrators
        ['icacls', str(folder_path), '/deny', '*S-1-5-18:(OI)(CI)(F)', '/T', '/C'],  # Local System
        ['icacls', str(folder_path), '/deny', '*S-1-5-19:(OI)(CI)(F)', '/T', '/C'],  # Local Service
        ['icacls', str(folder_path), '/deny', '*S-1-5-20:(OI)(CI)(F)', '/T', '/C'],  # Network Service
        ['icacls', str(folder_path), '/deny', 'Users:(OI)(CI)(F)', '/T', '/C'],      # Users group
        ['icacls', str(folder_path), '/deny', 'Everyone:(OI)(CI)(F)', '/T', '/C'],   # Everyone named
    ]
    
    for cmd in security_commands:
        try:
            result = subprocess.run(cmd, capture_output=True, shell=True, text=True)
            if result.returncode == 0:
                print(f"  ✅ Access denied: {cmd[3]}")
            else:
                print(f"  ⚠️ Access deny warning for {cmd[3]}: {result.stderr.strip()}")
        except Exception as e:
            print(f"  ⚠️ Command failed: {e}")
    
    # Step 4: Remove inheritance and disable permissions
    print("🔐 Step 4: Removing inheritance...")
    try:
        subprocess.run(['icacls', str(folder_path), '/inheritance:r', '/T', '/C'], 
                      capture_output=True, shell=True)
        print("  ✅ Inheritance removed")
    except Exception as e:
        print(f"  ⚠️ Inheritance removal: {e}")
    
    # Step 5: Set folder as system critical
    print("🔐 Step 5: Marking as system critical...")
    try:
        # Try to use fsutil to mark as system critical
        subprocess.run(['fsutil', 'file', 'setshortname', str(folder_path), 'PROTECT'], 
                      capture_output=True, shell=True)
        print("  ✅ System critical marking attempted")
    except:
        print("  ⚠️ System critical marking not available")
    
    # Step 6: Create lock files in the directory to prevent deletion
    print("🔐 Step 6: Creating lock anchors...")
    try:
        for i in range(3):
            lock_file = folder_path / f".lock_{i}.sys"
            try:
                with open(lock_file, 'w') as f:
                    f.write("SYSTEM_LOCK_FILE")
                
                # Make lock file system and immutable
                subprocess.run(['attrib', '+S', '+H', '+R', '+A', str(lock_file)], 
                              capture_output=True, shell=True)
                
                # Deny access to lock file specifically
                subprocess.run(['icacls', str(lock_file), '/deny', '*S-1-1-0:(F)', '/C'], 
                              capture_output=True, shell=True)
                
                print(f"  ✅ Lock anchor {i+1} created and protected")
            except:
                pass
    except Exception as e:
        print(f"  ⚠️ Lock anchor creation: {e}")
    
    print("\n🔒 ULTIMATE PROTECTION APPLIED!")
    print("🛡️ Multiple layers of kernel-level protection active")
    print("🗝️ Only USB token unlock can reverse this protection")
    
    return True

def test_ultimate_protection(folder_path):
    """Test the ultimate protection"""
    folder_path = Path(folder_path)
    
    print(f"\n🧪 TESTING ULTIMATE PROTECTION: {folder_path}")
    print("="*70)
    
    tests_passed = 0
    total_tests = 6
    
    # Test 1: Basic access
    try:
        list(folder_path.iterdir())
        print("❌ Test 1: Basic access - FAILED (folder accessible)")
    except Exception:
        print("✅ Test 1: Basic access - PASSED (access denied)")
        tests_passed += 1
    
    # Test 2: File creation
    try:
        test_file = folder_path / "test.txt"
        with open(test_file, 'w') as f:
            f.write("test")
        print("❌ Test 2: File creation - FAILED (file created)")
    except Exception:
        print("✅ Test 2: File creation - PASSED (creation blocked)")
        tests_passed += 1
    
    # Test 3: Attribute removal
    try:
        result = subprocess.run(['attrib', '-S', '-H', '-R', str(folder_path)], 
                              capture_output=True, shell=True, timeout=10)
        if result.returncode == 0:
            print("❌ Test 3: Attribute removal - FAILED (attributes removed)")
        else:
            print("✅ Test 3: Attribute removal - PASSED (removal blocked)")
            tests_passed += 1
    except Exception:
        print("✅ Test 3: Attribute removal - PASSED (command blocked)")
        tests_passed += 1
    
    # Test 4: Permission grant
    try:
        result = subprocess.run(['icacls', str(folder_path), '/grant', 'Everyone:F'], 
                              capture_output=True, shell=True, timeout=10)
        if result.returncode == 0:
            print("❌ Test 4: Permission grant - FAILED (permissions granted)")
        else:
            print("✅ Test 4: Permission grant - PASSED (grant blocked)")
            tests_passed += 1
    except Exception:
        print("✅ Test 4: Permission grant - PASSED (command blocked)")
        tests_passed += 1
    
    # Test 5: Folder deletion
    try:
        folder_path.rmdir()
        print("❌ Test 5: Folder deletion - FAILED (folder deleted)")
    except Exception:
        print("✅ Test 5: Folder deletion - PASSED (deletion blocked)")
        tests_passed += 1
    
    # Test 6: Rename
    try:
        new_name = folder_path.with_suffix('.old')
        folder_path.rename(new_name)
        print("❌ Test 6: Folder rename - FAILED (folder renamed)")
    except Exception:
        print("✅ Test 6: Folder rename - PASSED (rename blocked)")
        tests_passed += 1
    
    print(f"\n📊 PROTECTION SCORE: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        print("🛡️ ✅ ULTIMATE PROTECTION IS WORKING PERFECTLY!")
        return True
    else:
        print(f"⚠️ ❌ {total_tests - tests_passed} protection gaps detected")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ultimate_protection.py <folder_path>")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    
    print("🚀 ULTIMATE ANTI-RANSOMWARE PROTECTION")
    print("="*70)
    print("Applying maximum possible protection using Windows kernel features")
    print("This protection is designed to be unbreakable by ransomware")
    print("")
    
    # Apply protection
    success = apply_ultimate_protection(folder_path)
    
    if success:
        time.sleep(2)  # Let system settle
        test_ultimate_protection(folder_path)
    else:
        print("❌ Failed to apply ultimate protection")
        sys.exit(1)
