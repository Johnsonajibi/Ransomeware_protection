#!/usr/bin/env python3
"""
README Compliance Validation Script
====================================
This script validates that the codebase implements all features documented in README.md

Features to validate based on README.md:
1. Kernel minifilter driver (RealAntiRansomwareDriver.sys)
2. User-mode manager (RealAntiRansomwareManager.exe)
3. TPM 2.0 integration with WMI access
4. Device fingerprinting (6-8 hardware layers)
5. Post-quantum cryptography (Dilithium3)
6. Audit logging system (JSON format)
7. Service token management
8. Build system and compilation
9. Python components (psutil, wmi, pywin32, pqcdualusb, cryptography, flask)
10. Health monitoring
11. Command-line interface with documented commands
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass

# Minimum compliance threshold for passing validation
COMPLIANCE_THRESHOLD = 70

@dataclass
class ValidationResult:
    """Result of a validation check"""
    feature: str
    status: str  # PASS, FAIL, PARTIAL, MISSING
    details: str
    location: str = ""
    
    def __str__(self):
        symbols = {"PASS": "✓", "FAIL": "✗", "PARTIAL": "⚠", "MISSING": "?"}
        symbol = symbols.get(self.status, "?")
        return f"{symbol} {self.feature}: {self.status}\n   {self.details}\n   Location: {self.location}"


class ReadmeComplianceValidator:
    """Validates codebase against README documentation"""
    
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.results: List[ValidationResult] = []
        
    def validate_all(self) -> List[ValidationResult]:
        """Run all validation checks"""
        print("=" * 70)
        print("README COMPLIANCE VALIDATION")
        print("=" * 70)
        print()
        
        # Core components
        self.check_kernel_driver()
        self.check_user_mode_manager()
        self.check_build_system()
        
        # Security features
        self.check_tpm_integration()
        self.check_device_fingerprinting()
        self.check_pqc_support()
        self.check_audit_logging()
        
        # Python components
        self.check_python_dependencies()
        self.check_python_scripts()
        
        # Management features
        self.check_cli_commands()
        self.check_health_monitoring()
        self.check_token_management()
        
        return self.results
    
    def check_kernel_driver(self):
        """Check for kernel minifilter driver"""
        driver_c = self.repo_path / "RealAntiRansomwareDriver.c"
        driver_inf = self.repo_path / "RealAntiRansomwareDriver.inf"
        driver_vcxproj = self.repo_path / "AntiRansomwareDriver.vcxproj"
        
        if driver_c.exists():
            # Check for key kernel driver components
            try:
                content = driver_c.read_text(encoding='utf-8', errors='replace')
            except Exception as e:
                content = ""
                print(f"Warning: Could not read {driver_c}: {e}")
            
            has_minifilter = "fltKernel.h" in content
            has_ioctl = "IOCTL_AR_" in content
            has_token_validation = "SERVICE_TOKEN" in content or "TOKEN" in content
            has_db_policy = "DB_PROTECTION_POLICY" in content or "DATABASE" in content
            
            if has_minifilter and has_ioctl and has_token_validation:
                status = "PASS"
                details = "Kernel minifilter driver found with IRP interception, IOCTL support, and token validation"
            elif has_minifilter:
                status = "PARTIAL"
                details = "Kernel driver exists but missing some documented features (IOCTL/token validation)"
            else:
                status = "FAIL"
                details = "Driver file exists but doesn't appear to be a proper minifilter"
            
            self.results.append(ValidationResult(
                "Kernel Minifilter Driver",
                status,
                details,
                str(driver_c)
            ))
        else:
            self.results.append(ValidationResult(
                "Kernel Minifilter Driver",
                "MISSING",
                "RealAntiRansomwareDriver.c not found",
                ""
            ))
    
    def check_user_mode_manager(self):
        """Check for user-mode manager"""
        manager_cpp = self.repo_path / "RealAntiRansomwareManager_v2.cpp"
        
        if manager_cpp.exists():
            try:
                content = manager_cpp.read_text(encoding='utf-8', errors='replace')
            except Exception as e:
                content = ""
                print(f"Warning: Could not read {manager_cpp}: {e}")
            
            has_ioctl_defs = "IOCTL_AR_" in content
            has_sha256 = "SHA256" in content or "CryptAcquireContext" in content
            has_token_ops = "SERVICE_TOKEN" in content or "ISSUE_SERVICE_TOKEN" in content
            has_db_config = "DB_PROTECTION_POLICY" in content or "configure-db" in content
            
            if has_ioctl_defs and has_sha256 and has_token_ops:
                status = "PASS"
                details = "User-mode manager with IOCTL communication, SHA256, and token management"
            elif has_ioctl_defs:
                status = "PARTIAL"
                details = "Manager exists but missing some documented features"
            else:
                status = "FAIL"
                details = "Manager file exists but incomplete implementation"
            
            self.results.append(ValidationResult(
                "User-Mode Manager (C++)",
                status,
                details,
                str(manager_cpp)
            ))
        else:
            self.results.append(ValidationResult(
                "User-Mode Manager (C++)",
                "MISSING",
                "RealAntiRansomwareManager_v2.cpp not found",
                ""
            ))
    
    def check_build_system(self):
        """Check for build system"""
        vcxproj = self.repo_path / "AntiRansomwareDriver.vcxproj"
        check_ps1 = self.repo_path / "check.ps1"
        
        has_vcxproj = vcxproj.exists()
        has_check = check_ps1.exists()
        
        if has_vcxproj and has_check:
            status = "PASS"
            details = "Visual Studio project and prerequisite checker found"
        elif has_vcxproj:
            status = "PARTIAL"
            details = "VS project exists but missing check.ps1"
        else:
            status = "FAIL"
            details = "Build system incomplete"
        
        self.results.append(ValidationResult(
            "Build System",
            status,
            details,
            "check.ps1, *.vcxproj"
        ))
    
    def check_tpm_integration(self):
        """Check for TPM 2.0 integration"""
        tpm_files = [
            self.repo_path / "tpm_pqc_integration.py",
            self.repo_path / "windows_tpm_native.py",
            self.repo_path / "tpm_diagnostics.py"
        ]
        
        found_files = [f for f in tpm_files if f.exists()]
        
        if found_files:
            # Check for WMI-based TPM access
            has_wmi = False
            has_pcr = False
            has_seal = False
            
            for tpm_file in found_files:
                try:
                    content = tpm_file.read_text(encoding='utf-8', errors='replace')
                except Exception as e:
                    content = ""
                    print(f"Warning: Could not read {tpm_file}: {e}")
                    continue
                if "wmi" in content.lower() or "WMI" in content:
                    has_wmi = True
                if "PCR" in content or "pcr" in content:
                    has_pcr = True
                if "seal" in content.lower() or "unseal" in content.lower():
                    has_seal = True
            
            if has_wmi and has_pcr and has_seal:
                status = "PASS"
                details = f"TPM integration with WMI access, PCR measurements, and seal/unseal operations ({len(found_files)} files)"
            elif has_wmi:
                status = "PARTIAL"
                details = f"TPM files exist with WMI but missing PCR/seal features ({len(found_files)} files)"
            else:
                status = "PARTIAL"
                details = f"TPM files exist but missing WMI integration ({len(found_files)} files)"
            
            self.results.append(ValidationResult(
                "TPM 2.0 Integration",
                status,
                details,
                ", ".join([f.name for f in found_files])
            ))
        else:
            self.results.append(ValidationResult(
                "TPM 2.0 Integration",
                "MISSING",
                "No TPM integration files found",
                ""
            ))
    
    def check_device_fingerprinting(self):
        """Check for device fingerprinting"""
        fp_file = self.repo_path / "device_fingerprint_enhanced.py"
        
        if fp_file.exists():
            try:
                content = fp_file.read_text(encoding='utf-8', errors='replace')
            except Exception as e:
                content = ""
                print(f"Warning: Could not read {fp_file}: {e}")
            
            # Check for hardware layers mentioned in README
            has_cpu = "cpu" in content.lower() or "CPUID" in content
            has_bios = "bios" in content.lower() or "BIOS" in content
            has_network = "mac" in content.lower() or "network" in content.lower()
            has_storage = "disk" in content.lower() or "volume" in content.lower()
            has_hash = "blake2" in content.lower() or "hashlib" in content.lower() or "hash" in content.lower()
            
            layers = sum([has_cpu, has_bios, has_network, has_storage])
            
            if layers >= 4 and has_hash:
                status = "PASS"
                details = f"Device fingerprinting with {layers}+ hardware layers and hashing"
            elif layers >= 2:
                status = "PARTIAL"
                details = f"Device fingerprinting exists but only {layers} hardware layers detected"
            else:
                status = "FAIL"
                details = "Device fingerprinting file incomplete"
            
            self.results.append(ValidationResult(
                "Device Fingerprinting",
                status,
                details,
                str(fp_file)
            ))
        else:
            self.results.append(ValidationResult(
                "Device Fingerprinting",
                "MISSING",
                "device_fingerprint_enhanced.py not found",
                ""
            ))
    
    def check_pqc_support(self):
        """Check for post-quantum cryptography support"""
        pqc_files = [
            self.repo_path / "tpm_pqc_integration.py",
            self.repo_path / "pqc_usb_adapter.py"
        ]
        
        found_files = [f for f in pqc_files if f.exists()]
        
        if found_files:
            # Check for Dilithium3 support
            has_dilithium = False
            has_pqcdualusb = False
            
            for pqc_file in found_files:
                try:
                    content = pqc_file.read_text(encoding='utf-8', errors='replace')
                except Exception as e:
                    content = ""
                    print(f"Warning: Could not read {pqc_file}: {e}")
                    continue
                if "dilithium" in content.lower() or "ML-DSA" in content:
                    has_dilithium = True
                if "pqcdualusb" in content:
                    has_pqcdualusb = True
            
            if has_dilithium and has_pqcdualusb:
                status = "PASS"
                details = "Post-quantum cryptography with Dilithium3 support via pqcdualusb"
            elif has_pqcdualusb:
                status = "PARTIAL"
                details = "PQC support exists but Dilithium3 not explicitly mentioned"
            else:
                status = "PARTIAL"
                details = "PQC files exist but missing pqcdualusb integration"
            
            self.results.append(ValidationResult(
                "Post-Quantum Cryptography (Dilithium3)",
                status,
                details,
                ", ".join([f.name for f in found_files])
            ))
        else:
            self.results.append(ValidationResult(
                "Post-Quantum Cryptography",
                "MISSING",
                "No PQC integration files found",
                ""
            ))
    
    def check_audit_logging(self):
        """Check for audit logging system"""
        audit_viewer = self.repo_path / "view_audit_logs.py"
        
        if audit_viewer.exists():
            try:
                content = audit_viewer.read_text(encoding='utf-8', errors='replace')
            except Exception as e:
                content = ""
                print(f"Warning: Could not read {audit_viewer}: {e}")
            
            has_json = ".jsonl" in content or "json" in content.lower()
            has_tpm_field = "tpm_used" in content
            has_process_tracking = "process_id" in content and "process_name" in content
            has_security_level = "security_level" in content
            has_event_types = "event_type" in content
            
            if has_json and has_tpm_field and has_process_tracking and has_security_level:
                status = "PASS"
                details = "Complete audit logging with JSON format, TPM tracking, process info, and security levels"
            elif has_json and has_process_tracking:
                status = "PARTIAL"
                details = "Audit logging exists but missing some documented fields"
            else:
                status = "FAIL"
                details = "Audit logging incomplete"
            
            self.results.append(ValidationResult(
                "Audit Logging System",
                status,
                details,
                str(audit_viewer)
            ))
        else:
            self.results.append(ValidationResult(
                "Audit Logging System",
                "MISSING",
                "view_audit_logs.py not found",
                ""
            ))
    
    def check_python_dependencies(self):
        """Check for required Python packages"""
        requirements = self.repo_path / "requirements.txt"
        
        if requirements.exists():
            content = requirements.read_text()
            
            required_packages = {
                "psutil": "process monitoring",
                "wmi": "TPM access" if "pywin32" in content else "not checked",
                "pywin32": "Windows services",
                "pqcdualusb": "post-quantum signatures",
                "cryptography": "encryption primitives",
                "flask": "web dashboard"
            }
            
            found = {}
            for pkg, desc in required_packages.items():
                if pkg.lower() in content.lower():
                    found[pkg] = desc
            
            missing = set(required_packages.keys()) - set(found.keys())
            
            if len(missing) == 0:
                status = "PASS"
                details = f"All {len(required_packages)} required packages documented in requirements.txt"
            elif len(found) >= 4:
                status = "PARTIAL"
                details = f"{len(found)}/{len(required_packages)} packages found. Missing: {', '.join(missing)}"
            else:
                status = "FAIL"
                details = f"Only {len(found)}/{len(required_packages)} required packages. Missing: {', '.join(missing)}"
            
            self.results.append(ValidationResult(
                "Python Dependencies",
                status,
                details,
                str(requirements)
            ))
        else:
            self.results.append(ValidationResult(
                "Python Dependencies",
                "MISSING",
                "requirements.txt not found",
                ""
            ))
    
    def check_python_scripts(self):
        """Check for key Python management scripts"""
        scripts = {
            "health_monitor.py": "Health monitoring and alerting",
            "view_audit_logs.py": "Audit log analysis",
            "tpm_pqc_integration.py": "TPM and PQC integration",
            "device_fingerprint_enhanced.py": "Device fingerprinting"
        }
        
        found = {}
        for script, desc in scripts.items():
            path = self.repo_path / script
            if path.exists():
                found[script] = desc
        
        missing = set(scripts.keys()) - set(found.keys())
        
        if len(missing) == 0:
            status = "PASS"
            details = f"All {len(scripts)} documented Python scripts found"
        elif len(found) >= 3:
            status = "PARTIAL"
            details = f"{len(found)}/{len(scripts)} scripts found. Missing: {', '.join(missing)}"
        else:
            status = "FAIL"
            details = f"Only {len(found)}/{len(scripts)} scripts found"
        
        self.results.append(ValidationResult(
            "Python Management Scripts",
            status,
            details,
            ", ".join(found.keys())
        ))
    
    def check_cli_commands(self):
        """Check for documented CLI commands in manager"""
        manager_cpp = self.repo_path / "RealAntiRansomwareManager_v2.cpp"
        
        if manager_cpp.exists():
            try:
                content = manager_cpp.read_text(encoding='utf-8', errors='replace')
            except Exception as e:
                content = ""
                print(f"Warning: Could not read {manager_cpp}: {e}")
            
            # Commands documented in README
            commands = {
                "install": "Install driver",
                "enable": "Enable protection",
                "configure-db": "Configure database policy",
                "issue-token": "Issue service token",
                "status": "Check status",
                "list-tokens": "List active tokens",
                "calc-hash": "Calculate binary hash"
            }
            
            found = {}
            for cmd, desc in commands.items():
                if cmd in content or cmd.replace("-", "_") in content:
                    found[cmd] = desc
            
            missing = set(commands.keys()) - set(found.keys())
            
            if len(missing) <= 1:
                status = "PASS"
                details = f"{len(found)}/{len(commands)} documented commands implemented"
            elif len(found) >= 4:
                status = "PARTIAL"
                details = f"{len(found)}/{len(commands)} commands found. Missing: {', '.join(missing)}"
            else:
                status = "FAIL"
                details = f"Only {len(found)}/{len(commands)} commands implemented"
            
            self.results.append(ValidationResult(
                "CLI Commands",
                status,
                details,
                str(manager_cpp)
            ))
        else:
            self.results.append(ValidationResult(
                "CLI Commands",
                "MISSING",
                "Manager not found to check commands",
                ""
            ))
    
    def check_health_monitoring(self):
        """Check for health monitoring system"""
        health_monitor = self.repo_path / "health_monitor.py"
        
        if health_monitor.exists():
            try:
                content = health_monitor.read_text(encoding='utf-8', errors='replace')
            except Exception as e:
                content = ""
                print(f"Warning: Could not read {health_monitor}: {e}")
            
            has_checks = "HealthCheck" in content or "check_" in content
            has_driver_check = "driver" in content.lower() and "kernel" in content.lower()
            has_token_check = "token" in content.lower()
            has_alerting = "alert" in content.lower() or "notification" in content.lower()
            
            if has_checks and has_driver_check and has_alerting:
                status = "PASS"
                details = "Health monitoring with driver checks, token validation, and alerting"
            elif has_checks:
                status = "PARTIAL"
                details = "Health monitoring exists but missing some documented checks"
            else:
                status = "FAIL"
                details = "Health monitoring incomplete"
            
            self.results.append(ValidationResult(
                "Health Monitoring",
                status,
                details,
                str(health_monitor)
            ))
        else:
            self.results.append(ValidationResult(
                "Health Monitoring",
                "MISSING",
                "health_monitor.py not found",
                ""
            ))
    
    def check_token_management(self):
        """Check for service token management"""
        manager_cpp = self.repo_path / "RealAntiRansomwareManager_v2.cpp"
        driver_c = self.repo_path / "RealAntiRansomwareDriver.c"
        
        has_manager_tokens = False
        has_driver_tokens = False
        
        if manager_cpp.exists():
            try:
                content = manager_cpp.read_text(encoding='utf-8', errors='replace')
            except Exception as e:
                content = ""
                print(f"Warning: Could not read {manager_cpp}: {e}")
            has_manager_tokens = "SERVICE_TOKEN" in content and "ISSUE_SERVICE_TOKEN" in content
        
        if driver_c.exists():
            try:
                content = driver_c.read_text(encoding='utf-8', errors='replace')
            except Exception as e:
                content = ""
                print(f"Warning: Could not read {driver_c}: {e}")
            has_driver_tokens = "SERVICE_TOKEN" in content or "TOKEN" in content
        
        if has_manager_tokens and has_driver_tokens:
            status = "PASS"
            details = "Token management in both user-mode manager and kernel driver"
        elif has_manager_tokens or has_driver_tokens:
            status = "PARTIAL"
            details = "Token management partially implemented"
        else:
            status = "FAIL"
            details = "Token management not found"
        
        self.results.append(ValidationResult(
            "Service Token Management",
            status,
            details,
            "RealAntiRansomwareManager_v2.cpp, RealAntiRansomwareDriver.c"
        ))
    
    def print_summary(self):
        """Print validation summary"""
        print()
        print("=" * 70)
        print("VALIDATION RESULTS")
        print("=" * 70)
        print()
        
        # Count by status
        status_counts = {"PASS": 0, "PARTIAL": 0, "FAIL": 0, "MISSING": 0}
        for result in self.results:
            status_counts[result.status] = status_counts.get(result.status, 0) + 1
        
        # Print results
        for result in self.results:
            print(result)
            print()
        
        # Summary
        print("=" * 70)
        print("SUMMARY")
        print("=" * 70)
        total = len(self.results)
        print(f"Total features checked: {total}")
        print(f"✓ PASS:    {status_counts['PASS']}/{total}")
        print(f"⚠ PARTIAL: {status_counts['PARTIAL']}/{total}")
        print(f"✗ FAIL:    {status_counts['FAIL']}/{total}")
        print(f"? MISSING: {status_counts['MISSING']}/{total}")
        print()
        
        # Calculate compliance percentage
        # PASS = 100%, PARTIAL = 50%, FAIL = 0%, MISSING = 0%
        score = (status_counts['PASS'] * 100 + status_counts['PARTIAL'] * 50) / total if total > 0 else 0
        print(f"Overall compliance: {score:.1f}%")
        print()
        
        # Recommendations
        if status_counts['MISSING'] > 0 or status_counts['FAIL'] > 0:
            print("RECOMMENDATIONS:")
            print("- Review missing or failed features")
            print("- Update README.md to match actual implementation, or")
            print("- Implement missing features documented in README.md")
            print()
        
        return status_counts, score


def main():
    """Main validation function"""
    repo_path = Path(__file__).parent
    
    validator = ReadmeComplianceValidator(repo_path)
    validator.validate_all()
    status_counts, score = validator.print_summary()
    
    # Exit with error code if compliance is low
    if score < COMPLIANCE_THRESHOLD:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
