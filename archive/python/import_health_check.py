"""Import sanity check for deployment environment."""

import importlib
import sys

modules = [
    "nacl",            # PyNaCl imports as nacl
    "cryptography",
    "grpc",
    "google.protobuf",
    "yaml",
    "smartcard",       # pyscard imports as smartcard
    "pqcdualusb",
    "fido2",
    "watchdog",
    "psutil",
]

failed = []
for m in modules:
    try:
        importlib.import_module(m)
        print(f"[ok] {m}")
    except Exception as e:
        failed.append((m, e))
        print(f"[fail] {m}: {e}", file=sys.stderr)

if failed:
    sys.exit(1)
