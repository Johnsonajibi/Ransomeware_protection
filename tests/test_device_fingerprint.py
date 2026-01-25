#!/usr/bin/env python3
"""
Test the enhanced device fingerprinting implementation
"""

import sys
import os
import tempfile
from device_fingerprint_enhanced import EnhancedDeviceFingerprintingPro

def test_device_fingerprinting():
    """Test device fingerprinting functionality"""
    print("Testing Enhanced Device Fingerprinting")
    print("=" * 60)
    print()
    
    # Create fingerprint engine
    fp_engine = EnhancedDeviceFingerprintingPro()
    
    # Generate fingerprint
    print("Generating device fingerprint...")
    fingerprint = fp_engine.generate_fingerprint()
    print(f"✓ Fingerprint: {fingerprint}")
    print(f"  Length: {len(fingerprint)} characters")
    print()
    
    # Get detailed fingerprint info
    print("Hardware Layer Details:")
    details = fp_engine.get_fingerprint_details()
    print(f"  Layer Count: {details.layer_count}")
    for layer in details.hardware_layers:
        print(f"  - {layer[:80]}...")  # Truncate long values
    print()
    
    # Test verification
    print("Testing fingerprint verification...")
    is_valid = fp_engine.verify_fingerprint(fingerprint)
    print(f"  Verification: {'✓ PASS' if is_valid else '✗ FAIL'}")
    print()
    
    # Test storage - use cross-platform temp directory
    print("Testing fingerprint storage...")
    temp_dir = tempfile.gettempdir()
    test_path = os.path.join(temp_dir, "test_device_fingerprint.json")
    fp_engine.store_fingerprint(test_path)
    
    # Verify stored file
    import json
    with open(test_path, 'r') as f:
        stored_data = json.load(f)
    
    print(f"  Stored fingerprint: {stored_data['fingerprint']}")
    print(f"  Algorithm: {stored_data['algorithm']}")
    print(f"  Layer count: {stored_data['layer_count']}")
    print()
    
    # Verify consistency
    print("Testing consistency...")
    fingerprint2 = fp_engine.generate_fingerprint()
    is_consistent = (fingerprint == fingerprint2)
    print(f"  Consistency check: {'✓ PASS' if is_consistent else '✗ FAIL'}")
    print()
    
    print("=" * 60)
    print("✓ All device fingerprinting tests completed")
    
    return True

if __name__ == "__main__":
    try:
        test_device_fingerprinting()
        sys.exit(0)
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
