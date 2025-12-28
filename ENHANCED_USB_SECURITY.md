# Enhanced USB Security Features

## Overview

Implementations 1 and 2 from [USB_SPOOFING_ANALYSIS.md](USB_SPOOFING_ANALYSIS.md) - **Immediate Improvements (Easy)**:

✅ **1. VID/PID Checking** - Hardware vendor and product identification  
✅ **2. USB Connection History** - Disconnection detection and event logging

## Features

### 1. VID/PID (Vendor ID / Product ID) Checking

**What it does:**
- Extracts hardware identifiers from USB controller
- Uses Windows WMI to query PNPDeviceID
- Adds VID/PID to device_id for stronger binding

**Format:**
```python
# Without VID/PID (old):
device_id = "USB_E:\_12345678"

# With VID/PID (new):
device_id = "USB_E:\_12345678_VID0781_PID5581"
```

**Example VID/PID values:**
- VID 0781 = SanDisk
- VID 0930 = Toshiba  
- VID 13FE = Kingston
- VID 090C = Silicon Motion

**Security benefit:** Attacker must spoof both serial number AND vendor/product IDs, requiring matching USB controller hardware.

### 2. USB Connection History Tracking

**What it tracks:**
- First time USB was detected
- Last time USB was seen
- Total connection count
- Event log with timestamps

**Features:**
- ⚠️ **Disconnection Warning**: If USB was removed for >5 minutes, displays warning on next detection
- 📊 **Event Logging**: Records all USB events (detected, authenticated, token_issued, etc.)
- 🕒 **Timestamps**: ISO 8601 format with milliseconds
- 💾 **Persistent**: History stored in memory across multiple detections

**Connection history structure:**
```json
{
  "first_seen": 1766883358.426597,
  "last_seen": 1766883360.661173,
  "connection_count": 2,
  "events": [
    {
      "timestamp": 1766883358.426597,
      "event": "detected",
      "datetime": "2025-12-28T00:55:58.426597"
    },
    {
      "timestamp": 1766883360.661173,
      "event": "detected",
      "datetime": "2025-12-28T00:56:00.661173"
    }
  ]
}
```

## Implementation Details

### Changes to `PQCUSBAuthenticator` class:

#### New Attributes:
```python
self.usb_connection_history = {}  # Track USB connection history
self.wmi_connection = None         # WMI connection for VID/PID detection
```

#### New Methods:

**`get_enhanced_drive_info(drive: str) -> Dict`**
- Calls original `get_drive_info()` from pqcdualusb
- Adds VID/PID using WMI Win32_DiskDrive queries
- Parses PNPDeviceID format: `USB\VID_0781&PID_5581\...`

**`log_usb_connection(device_id: str, event: str)`**
- Creates or updates connection history entry
- Checks for disconnections (>5 minutes since last seen)
- Appends event with timestamp and ISO datetime
- Keeps last 100 events per device

**`detect_pqc_usb_token() -> Optional[Dict]`** (Enhanced)
- Calls `get_enhanced_drive_info()` instead of `get_drive_info()`
- Builds device_id with VID/PID if available
- Logs connection with `log_usb_connection()`
- Returns enhanced USB info dict with connection_history

## Usage

### Basic Detection
```python
from trifactor_auth_manager import PQCUSBAuthenticator

auth = PQCUSBAuthenticator()
usb_info = auth.detect_pqc_usb_token()

if usb_info:
    print(f"Device ID: {usb_info['device_id']}")
    print(f"Serial: {usb_info['serial']}")
    print(f"VID: {usb_info['vendor_id']}")
    print(f"PID: {usb_info['product_id']}")
    print(f"Connection count: {usb_info['connection_history']['connection_count']}")
```

### Manual Connection Logging
```python
auth = PQCUSBAuthenticator()

# Log custom events
auth.log_usb_connection("USB_E:\_12345678_VID0781_PID5581", "token_issued")
auth.log_usb_connection("USB_E:\_12345678_VID0781_PID5581", "authenticated")

# Get history
history = auth.usb_connection_history["USB_E:\_12345678_VID0781_PID5581"]
print(f"Events: {len(history['events'])}")
```

### Disconnection Detection
```python
auth = PQCUSBAuthenticator()

# First detection
usb_info1 = auth.detect_pqc_usb_token()
# User removes USB for 6 minutes

# Second detection
usb_info2 = auth.detect_pqc_usb_token()
# Output: ⚠️ WARNING: USB USB_E:\_12345678 was disconnected for 6 minutes
```

## Testing

Run the test suite:
```bash
python test_enhanced_usb.py
```

**Test coverage:**
1. USB detection with enhanced features
2. VID/PID extraction (if available)
3. Connection history tracking
4. Multiple detections (connection count increment)
5. Event logging
6. Connection history API

## Security Impact

### Attack Resistance

**Before (Serial Only):**
```
Attacker needs to spoof: Serial number
Difficulty: MEDIUM (custom firmware)
```

**After (Serial + VID/PID):**
```
Attacker needs to spoof: Serial number + Vendor ID + Product ID
Difficulty: MEDIUM-HIGH (custom firmware + matching hardware)
```

### Detection Capabilities

**Disconnection Detection:**
- Detects if USB was removed/reinserted
- Useful for detecting USB swap attacks
- 5-minute threshold (configurable)

**Event Auditing:**
- Complete history of USB interactions
- Forensic evidence for security investigations
- Compliance logging

## Configuration

### Adjust Disconnection Warning Threshold

In `trifactor_auth_manager.py`, line in `log_usb_connection()`:
```python
# Default: 5 minutes (300 seconds)
if current_time - last_seen > 300:
    print(f"⚠️ WARNING: USB {device_id} was disconnected...")

# Change to 10 minutes:
if current_time - last_seen > 600:
    print(f"⚠️ WARNING: USB {device_id} was disconnected...")
```

### Adjust Event History Limit

In `trifactor_auth_manager.py`, line in `log_usb_connection()`:
```python
# Default: Keep last 100 events
if len(self.usb_connection_history[device_id]['events']) > 100:
    self.usb_connection_history[device_id]['events'] = \
        self.usb_connection_history[device_id]['events'][-100:]

# Change to 1000 events:
if len(self.usb_connection_history[device_id]['events']) > 1000:
    ...
```

## Limitations

### VID/PID Detection

**May not work if:**
- USB drive is not connected via standard USB interface
- WMI is disabled/restricted
- USB drive uses proprietary interface
- Running on non-Windows system (Linux/macOS support pending)

**Fallback behavior:**
- If VID/PID not detected, device_id falls back to serial-only format
- System continues to function normally
- Only serial number used for authentication

### Connection History

**Limitations:**
- History stored in memory only (not persistent across reboots)
- 5-minute threshold may have false positives if system sleeps
- Event log limited to last 100 events per device

**Future enhancements:**
- Persist history to disk (JSON file)
- Adjust threshold based on system sleep/hibernate events
- Add configurable event retention policies

## Integration with Token-Gated Access

The enhanced USB features integrate seamlessly with `token_gated_access.py`:

```python
# When protecting a path with USB requirement
python token_gated_access.py protect "C:\Sensitive" --require-usb

# System now checks:
# 1. USB serial number (original)
# 2. USB VID/PID (new - if available)
# 3. Connection history (new - warns if disconnected)

# When granting access
python token_gated_access.py grant "C:\Sensitive" --token token_file.bin

# Validation includes:
# - TPM verification
# - Device fingerprint
# - USB device_id (with VID/PID if present)
# - Connection history check (disconnection warning)
```

## Troubleshooting

### VID/PID Not Detected

**Symptom:** `vendor_id` and `product_id` are empty strings

**Causes:**
1. WMI not available: `pip install wmi`
2. USB not USB interface (SD card reader, etc.)
3. Insufficient permissions (run as admin)
4. USB controller doesn't report VID/PID

**Verification:**
```powershell
# Check if USB is detected by WMI
Get-WmiObject Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' } | Select-Object PNPDeviceID
```

### Connection History Not Persisting

**Symptom:** Connection count resets after restart

**Cause:** History stored in memory only (by design)

**Solution:** For persistent history, see "Future Enhancements" section

### Disconnection Warnings Not Showing

**Symptom:** No warning after USB removal

**Causes:**
1. USB removed for <5 minutes (threshold not reached)
2. System clock changed
3. New `PQCUSBAuthenticator` instance created

**Verification:**
```python
auth = PQCUSBAuthenticator()
usb_info1 = auth.detect_pqc_usb_token()
time.sleep(301)  # Wait 5+ minutes
usb_info2 = auth.detect_pqc_usb_token()  # Should show warning
```

## Next Steps

See [USB_SPOOFING_ANALYSIS.md](USB_SPOOFING_ANALYSIS.md) for additional security enhancements:

**Medium-Term (Next Priority):**
- [ ] 3. Challenge-response validation
- [ ] 4. USB firmware version checking

**Long-Term:**
- [ ] 5. Hardware security tokens (YubiKey)
- [ ] 6. Secure USB with cryptographic chip

## References

- [USB_SPOOFING_ANALYSIS.md](USB_SPOOFING_ANALYSIS.md) - Security analysis and recommendations
- [USB_TOKEN_GUIDE.md](USB_TOKEN_GUIDE.md) - USB token workflow
- [USB_TOKEN_GENERATION.md](USB_TOKEN_GENERATION.md) - Token generation details
- [TOKEN_GATED_ACCESS_GUIDE.md](TOKEN_GATED_ACCESS_GUIDE.md) - Access control guide

## Changelog

**December 28, 2025** - Enhanced USB Security v1.0
- ✅ Added VID/PID checking via WMI
- ✅ Implemented connection history tracking
- ✅ Added disconnection detection (5-minute threshold)
- ✅ Created event logging system
- ✅ Added `get_enhanced_drive_info()` method
- ✅ Added `log_usb_connection()` method
- ✅ Enhanced `detect_pqc_usb_token()` with new features
- ✅ Created test suite (`test_enhanced_usb.py`)
- ✅ Created documentation (this file)
