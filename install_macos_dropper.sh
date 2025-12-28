#!/usr/bin/env bash
set -euo pipefail

# Install and load macOS token dropper launchd service.
# Usage: sudo ./install_macos_dropper.sh /Library/AntiRansomware

PREFIX=${1:-/Library/AntiRansomware}
PLIST_DEST=/Library/LaunchDaemons/com.antiransomware.tokendropper.plist

install -d "$PREFIX"
install -m 0644 macos_token_dropper.py "$PREFIX"/macos_token_dropper.py
install -m 0644 keygen.py "$PREFIX"/keygen.py
install -m 0644 requirements.txt "$PREFIX"/requirements.txt
install -m 0644 com.antiransomware.tokendropper.plist "$PLIST_DEST"

launchctl unload "$PLIST_DEST" 2>/dev/null || true
launchctl load -w "$PLIST_DEST"

echo "Installed and loaded com.antiransomware.tokendropper"
