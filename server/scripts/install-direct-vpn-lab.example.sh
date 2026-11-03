#!/bin/bash
# EXAMPLE bootstrap for an isolated Direct VPN Lab sing-box instance.
# Review every step before use on a production host.
# Does NOT include real credentials. Generate keys on the server.
#
# Safety constraints (must remain true):
# - Do not restart/stop Outline / Shadowbox / Docker networks
# - Do not modify wg0/wg1/wg2 or default route
# - Do not flush iptables/nft existing tables
# - Use dedicated ports and dedicated systemd unit names only
set -euo pipefail

LAB=/opt/direct-vpn-lab
VER=1.14.4
TGZ="sing-box-${VER}-linux-amd64.tar.gz"
URL="https://github.com/SagerNet/sing-box/releases/download/v${VER}/${TGZ}"
# Official asset digest for linux-amd64 (verify before install):
SHA256_EXPECT="699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"

echo "This is an EXAMPLE script. Fill config generation with your own secrets."
echo "Refusing to run automatically. Edit and remove the exit below after review."
exit 2

# --- intended flow (manual) ---
# 1) Create system user dvpnlab
# 2) Download + sha256sum -c sing-box binary into $LAB/bin
# 3) Generate private CA + leaf cert (or use your domain cert)
# 4) Generate UUIDs/passwords/REALITY/WG keys via: sing-box generate ...
# 5) Write $LAB/config/config.json with independent inbounds on free ports
# 6) sing-box check -c $LAB/config/config.json
# 7) Install systemd unit direct-vpn-lab.service (User=dvpnlab)
# 8) Optional additive nft table inet direct_vpn_lab only
# 9) systemctl enable --now direct-vpn-lab.service
# 10) Verify protected services still active; default route unchanged
