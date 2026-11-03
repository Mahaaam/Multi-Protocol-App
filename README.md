# Direct VPN Lab

Windows multi-protocol connectivity tester (NL direct path lab).

## Run
1. Build: `dotnet publish src/DirectVpnLab -c Release -r win-x64 --self-contained false -o publish`
2. Run `publish/DirectVpnLab.exe` (Administrator for TUN)
3. Connect = Discovery → rank → TUN connect with verified exit IP

## Server
Isolated lab under `/opt/direct-vpn-lab` on `82.23.248.121`.
Uninstall: `bash /opt/direct-vpn-lab/scripts/uninstall.sh`

## Safety
Does not touch Outline/Docker/WG/aiden-tunnel/nginx.
Secrets stay out of git (`client/secrets`, Assets/certs).

## Status labels
See delivery reports in `TMP/` after local verification.
