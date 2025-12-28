"""
Build script for creating Anti-Ransomware .exe packages
Handles multiple entry points and dependencies
"""
import PyInstaller.__main__
import os
import shutil
from pathlib import Path

# Build configurations for different components
BUILD_CONFIGS = {
    'trifactor_auth': {
        'script': 'trifactor_auth_manager.py',
        'name': 'AntiRansomware-TriFactor',
        'icon': None,
        'console': True,
        'admin': True,
    },
    'desktop_gui': {
        'script': 'desktop_app.py',
        'name': 'AntiRansomware-GUI',
        'icon': None,
        'console': False,
        'admin': True,
    },
    'admin_dashboard': {
        'script': 'admin_dashboard.py',
        'name': 'AntiRansomware-Admin',
        'icon': None,
        'console': False,
        'admin': True,
    },
}

def build_exe(config_name):
    """Build executable for given configuration"""
    config = BUILD_CONFIGS[config_name]
    
    print(f"\n{'='*60}")
    print(f"Building: {config['name']}")
    print(f"{'='*60}\n")
    
    # Base PyInstaller arguments
    args = [
        config['script'],
        f"--name={config['name']}",
        '--onefile',  # Single executable
        '--clean',    # Clean cache
        '--noconfirm',  # Overwrite without asking
    ]
    
    # Console/windowed mode
    if not config['console']:
        args.append('--windowed')
    else:
        args.append('--console')
    
    # Add icon if specified
    if config['icon']:
        args.append(f"--icon={config['icon']}")
    
    # Add hidden imports for common modules
    hidden_imports = [
        'psutil',
        'cryptography',
        'win32api',
        'win32con',
        'win32security',
        'wmi',
        'pqcdualusb',
        'sqlite3',
        'json',
        'pathlib',
        'subprocess',
        'threading',
    ]
    
    for module in hidden_imports:
        args.append(f'--hidden-import={module}')
    
    # Add data files
    data_files = [
        ('config.json', '.'),
        ('admin_config.json', '.'),
    ]
    
    for src, dest in data_files:
        if os.path.exists(src):
            args.append(f'--add-data={src};{dest}')
    
    # UAC admin rights for Windows
    if config['admin']:
        args.append('--uac-admin')
    
    # Build
    try:
        PyInstaller.__main__.run(args)
        print(f"\n[SUCCESS] {config['name']}.exe created in dist/")
        return True
    except Exception as e:
        print(f"\n[ERROR] Build failed: {e}")
        return False

def build_all():
    """Build all executables"""
    print("\n" + "="*60)
    print("Anti-Ransomware .exe Builder")
    print("="*60)
    
    results = {}
    for config_name in BUILD_CONFIGS:
        results[config_name] = build_exe(config_name)
    
    # Summary
    print("\n" + "="*60)
    print("Build Summary")
    print("="*60)
    for name, success in results.items():
        status = "[OK]" if success else "[FAIL]"
        print(f"{status} {BUILD_CONFIGS[name]['name']}")
    
    print("\n[INFO] Executables are in the 'dist' folder")
    
    return all(results.values())

def build_single(target):
    """Build single executable"""
    if target not in BUILD_CONFIGS:
        print(f"[ERROR] Unknown target: {target}")
        print(f"Available targets: {', '.join(BUILD_CONFIGS.keys())}")
        return False
    
    return build_exe(target)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if target == 'all':
            build_all()
        else:
            build_single(target)
    else:
        print("\nUsage:")
        print("  python build_exe.py all              # Build all executables")
        print("  python build_exe.py trifactor_auth   # Build tri-factor auth")
        print("  python build_exe.py desktop_gui      # Build GUI app")
        print("  python build_exe.py admin_dashboard  # Build admin dashboard")
        print("\nBuilding all by default...\n")
        build_all()
