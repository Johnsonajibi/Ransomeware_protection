"""
Enhanced Device Fingerprinting
Uses device fingerprinting to identify protection status and persist security state
Integrates with TPM and Secure Boot for hardware-bound cryptography
"""

import hashlib
import json
from typing import Dict, Optional
from dataclasses import dataclass

# Try importing device fingerprinting modules
try:
    from tpm_integration import TPMManager
    HAS_TPM = True
except ImportError:
    HAS_TPM = False


@dataclass
class DeviceFingerprint:
    """Device fingerprint using hardware characteristics"""
    
    fingerprint_id: str
    use_pro: bool = HAS_TPM
    include_hardware: bool = True
    include_bios: bool = HAS_TPM
    include_tpm: bool = HAS_TPM
    include_secure_boot: bool = True


class EnhancedDeviceFingerprintingPro:
    """Pro-grade device fingerprinting for hardware-bound security"""
    
    def __init__(self):
        self.use_pro = HAS_TPM
        self.fingerprint_cache = None
        
        if self.use_pro:
            try:
                self.tpm = TPMManager(include_hardware=True, include_bios=True)
                self.HAS_DEVICE_FINGERPRINTING_PRO = True
            except ImportError:
                self.HAS_DEVICE_FINGERPRINTING_PRO = False
                self.tpm = None
        else:
            self.HAS_DEVICE_FINGERPRINTING_PRO = False
            self.tpm = None
    
    def generate_fingerprint(self) -> str:
        """Generate hardware-bound device fingerprint"""
        if self.fingerprint_cache:
            return self.fingerprint_cache
        
        components = []
        
        # Hardware fingerprint
        if self.dfp.include_hardware and HAS_TPM:
            try:
                hw_data = self.tpm.get_hardware_fingerprint()
                components.append(hw_data)
            except Exception as e:
                print(f"⚠️ hardware fingerprinting failed: {e}")
        
        # BIOS/Firmware fingerprint
        if self.dfp.include_bios and HAS_TPM:
            try:
                bios_data = self.tpm.get_firmware_fingerprint()
                components.append(bios_data)
            except Exception as e:
                print(f"⚠️ BIOS fingerprinting failed: {e}")
        
        # TPM fingerprint
        if self.dfp.include_tpm and HAS_TPM:
            try:
                tpm_data = self.tpm.get_tpm_fingerprint()
                components.append(tpm_data)
            except Exception as e:
                print(f"⚠️ TPM fingerprinting failed: {e}")
        
        # Secure Boot state
        if self.dfp.include_secure_boot:
            try:
                sb_data = self._get_secure_boot_state()
                components.append(sb_data)
            except Exception as e:
                print(f"⚠️ Secure Boot fingerprinting failed: {e}")
        
        # Hash all components
        combined = "".join(str(c) for c in components)
        fingerprint = hashlib.sha256(combined.encode()).hexdigest()
        
        self.fingerprint_cache = fingerprint
        return fingerprint
    
    def _get_secure_boot_state(self) -> str:
        """Get Secure Boot state on Windows"""
        import subprocess
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-SecureBootUEFI"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip()
        except Exception:
            return "unknown"
    
    def verify_fingerprint(self, stored_fingerprint: str) -> bool:
        """Verify device fingerprint matches stored value"""
        current = self.generate_fingerprint()
        return current == stored_fingerprint
    
    def store_fingerprint(self, path: str = "device_fingerprint.json") -> None:
        """Store fingerprint to file"""
        fingerprint = self.generate_fingerprint()
        data = {
            "fingerprint": fingerprint,
            "hardware_bound": HAS_TPM,
            "secure_boot": self.dfp.include_secure_boot
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"✅ Device fingerprint stored")
