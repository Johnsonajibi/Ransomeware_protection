#!/usr/bin/env python3
"""
TPM Status Checker
Tests if TPM is accessible and provides diagnostic information
"""

import sys
import subprocess
import platform

def check_admin():
    """Check if running with admin privileges"""
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        return bool(is_admin)
    except:
        return False

def check_tpm_powershell():
    """Check TPM using PowerShell Get-Tpm"""
    print("━" * 60)
    print("1. PowerShell Get-Tpm Command")
    print("━" * 60)
    
    try:
        result = subprocess.run(
            ['powershell', '-Command', 
             'Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, TpmOwned | Format-List'],
            capture_output=True, 
            text=True, 
            timeout=5
        )
        
        if result.returncode == 0:
            print(result.stdout)
            return True
        else:
            print(f"❌ Error: {result.stderr}")
            if "Administrator privilege" in result.stderr:
                print("\n⚠️  TPM access requires Administrator privileges!")
                print("   Right-click PowerShell and select 'Run as Administrator'")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Command timed out")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def check_tpm_wmi():
    """Check TPM using WMI"""
    print("\n━" * 60)
    print("2. WMI Win32_Tpm Class")
    print("━" * 60)
    
    try:
        import wmi
        
        # Try to connect to TPM namespace
        c = wmi.WMI(namespace='root\\cimv2\\Security\\MicrosoftTpm')
        tpm_list = c.Win32_Tpm()
        
        if tpm_list:
            tpm = tpm_list[0]
            print(f"✓ TPM Found!")
            print(f"  IsActivated: {tpm.IsActivated_InitialValue}")
            print(f"  IsEnabled:   {tpm.IsEnabled_InitialValue}")
            print(f"  IsOwned:     {tpm.IsOwned_InitialValue}")
            
            # Try to get spec version
            try:
                spec_version = tpm.SpecVersion
                print(f"  Spec Version: {spec_version}")
            except:
                pass
                
            return True
        else:
            print("❌ No TPM device found in WMI")
            return False
            
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Error: {error_msg}")
        
        if "Access is denied" in error_msg or "Access denied" in error_msg:
            print("\n⚠️  WMI access denied - need Administrator privileges")
        elif "Invalid namespace" in error_msg or "namespace" in error_msg.lower():
            print("\n⚠️  TPM WMI namespace not available")
            print("   Possible reasons:")
            print("   - TPM not enabled in BIOS")
            print("   - TPM drivers not installed")
            print("   - Windows version doesn't support TPM")
        
        return False

def check_tpm_libraries():
    """Check available TPM Python libraries"""
    print("\n━" * 60)
    print("3. Python TPM Libraries")
    print("━" * 60)
    
    libraries = {
        'tpm2-pytss': 'tpm2_pytss',
        'python-tpm': 'tpm',
        'pytpm': 'pytpm',
        'wmi': 'wmi'
    }
    
    available = []
    
    for name, module in libraries.items():
        try:
            __import__(module)
            print(f"✓ {name}: Installed")
            available.append(name)
        except ImportError:
            print(f"✗ {name}: Not installed")
    
    if not available:
        print("\n⚠️  No TPM libraries installed")
        print("   Install with: pip install tpm2-pytss")
    
    return len(available) > 0

def check_tpm2_tools():
    """Check if tpm2-tools are available"""
    print("\n━" * 60)
    print("4. TPM2 Tools (Command Line)")
    print("━" * 60)
    
    try:
        result = subprocess.run(
            ['tpm2_getcap', 'properties-fixed'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            print("✓ tpm2-tools installed and working")
            print(result.stdout[:500])  # First 500 chars
            return True
        else:
            print("✗ tpm2-tools installed but not working")
            return False
            
    except FileNotFoundError:
        print("✗ tpm2-tools not installed")
        print("   Download from: https://github.com/tpm2-software/tpm2-tools")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def main():
    print("╔" + "═" * 58 + "╗")
    print("║" + " TPM STATUS CHECKER ".center(58) + "║")
    print("╚" + "═" * 58 + "╝")
    print()
    
    # Check admin status
    is_admin = check_admin()
    print(f"Running as Administrator: {'✓ YES' if is_admin else '✗ NO'}")
    
    if not is_admin:
        print("⚠️  WARNING: Many TPM operations require Administrator privileges")
        print("   For full testing, right-click and 'Run as Administrator'\n")
    
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Python: {sys.version.split()[0]}")
    print()
    
    # Run checks
    results = {
        'powershell': check_tpm_powershell(),
        'wmi': check_tpm_wmi(),
        'libraries': check_tpm_libraries(),
        'tools': check_tpm2_tools()
    }
    
    # Summary
    print("\n" + "━" * 60)
    print("SUMMARY")
    print("━" * 60)
    
    if results['powershell'] or results['wmi']:
        print("✓ TPM is available on this system")
        
        if not is_admin:
            print("⚠️  Run as Administrator for full access")
        else:
            print("✓ Running with sufficient privileges")
            
        if not results['libraries']:
            print("⚠️  Install TPM Python library: pip install tpm2-pytss")
            
        print("\n🎯 NEXT STEPS:")
        print("   1. Run trifactor_auth_manager.py as Administrator")
        print("   2. TPM should show: TpmAvailable: True")
        print("   3. Security Level should reach: HIGH or MAXIMUM")
        
    else:
        print("✗ TPM not accessible")
        print("\n🔧 TROUBLESHOOTING:")
        print("   1. Enable TPM in BIOS/UEFI settings")
        print("   2. Run this script as Administrator")
        print("   3. Update TPM drivers from manufacturer")
        print("   4. Check Windows TPM Management (tpm.msc)")
        print("\n   If no TPM hardware exists:")
        print("   - Current MEDIUM security (DeviceFP + USB) is still strong")
        print("   - Software fallback is already working")
    
    print("\n" + "━" * 60)

if __name__ == "__main__":
    main()
