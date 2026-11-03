# Architecture — Direct VPN Lab

Experimental Windows multi-protocol connectivity tester for **direct** paths
to a foreign lab server (no Iran intermediate hop in the test matrix).

## Components

1. **Lab server (Linux)**  
   Isolated `sing-box` userspace proxy/endpoints under `/opt/direct-vpn-lab`.  
   Must not disturb existing Outline/WG/Iran-link services.

2. **Windows client (`src/DirectVpnLab`)**  
   .NET 9 WPF app:
   - Discovery: per-method temporary local mixed proxy on loopback
   - Verification: real HTTPS through that proxy + exit IP check
   - Ranking: success rate, latency, jitter, connect time
   - Connect: TUN via sing-box + Wintun (Administrator)
   - Health monitor + failover across PASS methods
   - Speed Test (DIRECT vs VPN) and Live Log

## Connection states (strict)

| State | Meaning |
|-------|---------|
| Proxy PASS | Forced HTTPS via tested outbound succeeded and exit IP matched lab |
| TUN Connected | Windows TUN up + internet verification + exit IP (system path) |
| Failed | Evidence of failure; button stays non-green |

Green **Connected** requires TUN-path verification, not merely core process start.

## sing-box

- Stable lab version: **1.14.4**
- Client/server binaries from official GitHub releases with SHA-256 verification
- MASQUE server endpoints require >= 1.15 → marked SKIPPED on 1.14.4

## Secrets

Runtime credentials live only in local untracked paths (`client/secrets`,
`Assets/certs`). Repository ships `samples/credentials.example.json` only.
