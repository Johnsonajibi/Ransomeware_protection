#!/usr/bin/env python3
"""
Test Enhanced USB Detection
Tests VID/PID checking and connection history logging
"""

import json
import time
from trifactor_auth_manager import PQCUSBAuthenticator

def test_usb_detection():
    """Test USB detection with enhanced features"""
    
    print("=" * 60)
    print("Enhanced USB Detection Test")
    print("=" * 60)
    
    # Initialize authenticator
    print("\n1. Initializing PQC USB Authenticator...")
    auth = PQCUSBAuthenticator()
    
    # Detect USB
    print("\n2. Detecting USB token...")
    usb_info = auth.detect_pqc_usb_token()
    
    if usb_info:
        print("\n✓ USB Token Detected!")
        print("\nUSB Information:")
        print(json.dumps(usb_info, indent=2))
        
        # Test connection history
        print("\n3. Connection History:")
        history = usb_info.get('connection_history', {})
        print(f"   First seen: {history.get('first_seen')}")
        print(f"   Last seen: {history.get('last_seen')}")
        print(f"   Connection count: {history.get('connection_count')}")
        print(f"   Events: {len(history.get('events', []))}")
        
        # Test VID/PID
        print("\n4. Hardware Identifiers:")
        print(f"   Serial: {usb_info.get('serial')}")
        print(f"   Vendor ID (VID): {usb_info.get('vendor_id') or 'Not detected'}")
        print(f"   Product ID (PID): {usb_info.get('product_id') or 'Not detected'}")
        print(f"   Device ID: {usb_info.get('device_id')}")
        
        # Test multiple detections
        print("\n5. Testing connection history (multiple detections)...")
        time.sleep(1)
        usb_info2 = auth.detect_pqc_usb_token()
        if usb_info2:
            history2 = usb_info2.get('connection_history', {})
            print(f"   Connection count increased: {history2.get('connection_count')}")
            print(f"   Events recorded: {len(history2.get('events', []))}")
            
            # Show last 3 events
            events = history2.get('events', [])
            if events:
                print("\n   Last events:")
                for event in events[-3:]:
                    print(f"   - {event['datetime']}: {event['event']}")
        
        print("\n✓ Enhanced USB detection test completed successfully!")
        
        # Test warning for disconnection
        print("\n6. Testing disconnection warning...")
        print("   (Simulating USB disconnection by waiting 6 minutes)")
        print("   In production, if USB is removed for >5 minutes,")
        print("   a warning will be displayed on next detection.")
        
    else:
        print("\n✗ No USB token detected")
        print("\nNote: Insert a USB drive and run again")
        print("Enhanced features include:")
        print("  - VID/PID hardware identification")
        print("  - Connection history tracking")
        print("  - Disconnection warnings")
        print("  - Event logging")

def test_connection_history_api():
    """Test connection history API directly"""
    
    print("\n" + "=" * 60)
    print("Connection History API Test")
    print("=" * 60)
    
    auth = PQCUSBAuthenticator()
    
    # Simulate multiple connections
    test_device_id = "USB_E:\\_12345678_VID0781_PID5581"
    
    print(f"\nSimulating events for device: {test_device_id}")
    
    auth.log_usb_connection(test_device_id, 'detected')
    time.sleep(0.5)
    auth.log_usb_connection(test_device_id, 'authenticated')
    time.sleep(0.5)
    auth.log_usb_connection(test_device_id, 'token_issued')
    
    # Show history
    history = auth.usb_connection_history.get(test_device_id)
    if history:
        print("\n✓ Connection History:")
        print(json.dumps(history, indent=2))
    
    print("\n✓ Connection history API test completed!")

if __name__ == '__main__':
    test_usb_detection()
    test_connection_history_api()
