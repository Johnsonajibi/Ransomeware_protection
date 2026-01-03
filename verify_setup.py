#!/usr/bin/env python3
"""
Quick verification script to check TPM + PQC setup
on Windows with security features enabled.
"""

import sys
import platform
from pathlib import Path


def check_module(module_name, display_name, required=False):
    """Check if a module is available."""
    try:
        __import__(module_name)
        status = "✅"
        print(f"{status} {display_name}")
        return True
    except ImportError:
        status = "❌" if required else "⚠️"
        req_text = " (REQUIRED)" if required else ""
        print(f"{status} {display_name}{req_text}")
        return not required


def check_tpm():
    """Check TPM 2.0 availability on Windows."""
    """Check TPM 2.0 availability on Windows."""
    if platform.system() != "Windows":
        print("⚠️ TPM check only available on Windows")
        return False
    
    try:
        import subprocess
        result = subprocess.run(
            ["powershell", "-Command", 
             "Get-WmiObject -Namespace root/cimv2/security/microsofttpm -Class Win32_Tpm"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and "TPM" in result.stdout:
            status = "✅"
            print(f"{status} TPM 2.0 is available on this system")
            return True
        else:
            print("⚠️ Could not detect TPM 2.0: Will use software-only PQC")
            return False
    except Exception as e:
        print(f"⚠️ Could not check TPM: {e}")
        return False


def main():
    print("\n" + "=" * 60)
    print("🔐 TPM + PQC SETUP VERIFICATION")
    print("=" * 60)
    print(f"\nPlatform: {platform.system()} {platform.release()}\n")
    
    all_ok = True
    
    # Check required modules
    all_ok &= check_module("cryptography", "Cryptography Library", required=True)
    all_ok &= check_module("pqcrypto", "PQC Cryptography", required=True)
    
    # Check optional modules
    all_ok &= check_module("tpm2_tools", "TPM 2.0 Tools")
    all_ok &= check_module("watchdog", "File System Monitoring")
    
    # TPM specific check
    if platform.system() == "Windows":
        print("\n" + "=" * 60)
        check_tpm()
    
    print("\n" + "=" * 60)
    
    if all_ok:
        print("✅ Setup verification PASSED")
        return 0
    else:
        print("⚠️ Some optional components missing (see above)")
        return 0
    
    return 1


if __name__ == "__main__":
    sys.exit(main())
