#!/bin/bash
# Removes ONLY Direct VPN Lab artifacts. Does not touch Outline, Docker,
# WireGuard, aiden-tunnel, nginx, or unrelated firewall tables.
set -euo pipefail

systemctl disable --now direct-vpn-lab.service 2>/dev/null || true
rm -f /etc/systemd/system/direct-vpn-lab.service
systemctl daemon-reload

nft delete table inet direct_vpn_lab 2>/dev/null || true
userdel dvpnlab 2>/dev/null || true
rm -rf /opt/direct-vpn-lab

echo "REMOVED_DIRECT_VPN_LAB_ONLY"
