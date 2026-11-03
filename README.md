# Direct VPN Lab

Windows multi-protocol **direct** connectivity tester (engineering lab).

Repository: https://github.com/Mahaaam/Multi-Protocol-App

## What it does

- Discovers which proxy methods actually pass HTTPS + exit-IP checks  
- Ranks successful methods  
- Attempts Windows TUN connect with the best candidate  
- Speed Test (DIRECT vs VPN) + Live Connection Log  

This is an experimental tool, not a commercial VPN product.

## Requirements

- Windows 10/11 x64  
- .NET 9 SDK (to build)  
- Official `sing-box` 1.14.4 Windows amd64 binary + `wintun.dll` (local assets)  
- Private lab credentials (never commit real secrets)

## Build EXE

Framework-dependent:

```powershell
dotnet publish src\DirectVpnLab\DirectVpnLab.csproj -c Release -r win-x64 --self-contained false -o publish
```

Output: `publish\DirectVpnLab.exe`

Standalone (~200MB class size; do **not** commit):

```powershell
dotnet publish src\DirectVpnLab\DirectVpnLab.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish-standalone
```

Or use:

```powershell
.\scripts\build-windows.ps1
.\scripts\build-windows.ps1 -Standalone
```

## Local secrets layout

```text
samples/credentials.example.json   # committed template
client/secrets/credentials.json    # private (gitignored)
src/DirectVpnLab/Assets/certs/     # private certs + credentials (gitignored)
src/DirectVpnLab/Assets/sing-box/  # sing-box.exe + wintun.dll (gitignored)
```

## Server lab

Isolated install lives under `/opt/direct-vpn-lab` with unit `direct-vpn-lab.service`.

- Example installer notes: `server/scripts/install-direct-vpn-lab.example.sh`  
- Uninstall lab only: `server/scripts/uninstall-direct-vpn-lab.sh`  

Do not disturb Outline, WireGuard, or unrelated firewall state.

## Docs & reports

- Architecture: `docs/ARCHITECTURE.md`  
- Live project status: `PROJECT_STATUS.md`  
- Delivery flags: `reports/DELIVERY_STATUS.txt`  
- Method results: `reports/METHODS_REPORT.txt`  
- Server change log: `reports/SERVER_CHANGES.txt`  

## Safety note

Proxy PASS is evidence for an isolated local-proxy test only.  
System-wide VPN success requires TUN verification (`DIRECT_VPN_VERIFIED`).
