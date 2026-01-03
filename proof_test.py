#!/usr/bin/env python3
"""Quick proof that protection works"""
import os
import sys
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kernel_level_blocker import get_kernel_blocker

# Create test file
test_dir = os.path.join(tempfile.gettempdir(), 'proof_test')
os.makedirs(test_dir, exist_ok=True)
test_file = os.path.join(test_dir, 'protected.txt')

with open(test_file, 'w') as f:
    f.write('This file should be protected')

print("=" * 60)
print("PROOF TEST: Python Kernel Blocker")
print("=" * 60)

# Start protection
blocker = get_kernel_blocker()
blocker.add_protected_path(test_dir)
blocker.start_blocking()

time.sleep(1)

# Try to access the file
print("\nAttempting to read protected file...")
try:
    with open(test_file, 'r') as f:
        content = f.read()
    print("✗ FAILED - File was readable (protection not working)")
    result = False
except (PermissionError, OSError) as e:
    print(f"✓ SUCCESS - File access blocked: {type(e).__name__}")
    result = True

# Stop protection
blocker.stop_blocking()

print("\nProtection stopped, file should be accessible again...")
try:
    with open(test_file, 'r') as f:
        content = f.read()
    print(f"✓ File now readable: {len(content)} bytes")
except Exception as e:
    print(f"⚠️  File still locked: {e}")

print("\n" + "=" * 60)
if result:
    print("RESULT: Python Kernel Blocker WORKS ✓")
else:
    print("RESULT: Protection test FAILED ✗")
print("=" * 60)
