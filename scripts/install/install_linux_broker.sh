#!/usr/bin/env bash
set -euo pipefail

# Install and enable the anti-ransomware netlink broker as a systemd service.
# Usage: sudo ./install_linux_broker.sh /opt/antiransomware

PREFIX=${1:-/opt/antiransomware}
SERVICE=linux_broker.service

install -d "$PREFIX"
install -d "$PREFIX/keys"
install -m 0644 linux_broker.py "$PREFIX"/linux_broker.py
install -m 0644 keygen.py "$PREFIX"/keygen.py
install -m 0644 requirements.txt "$PREFIX"/requirements.txt
install -m 0644 import_health_check.py "$PREFIX"/import_health_check.py

# Copy service and adjust paths
cat > /etc/systemd/system/$SERVICE <<EOF
[Unit]
Description=Anti-Ransomware Netlink Broker (PQC-enforced)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PREFIX
ExecStart=/usr/bin/python3 $PREFIX/linux_broker.py --key $PREFIX/keys/ed25519_private.key --ttl 300 --ops 4294967295 --quota 1000000000
Restart=on-failure
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=$PREFIX

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now $SERVICE

echo "Installed and started $SERVICE (prefix: $PREFIX)"
