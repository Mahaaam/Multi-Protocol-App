# Project Status — Direct VPN Lab

Last updated: 2026-11-03 (critical validation fixes applied; VPN PASS not claimed)

## Versions

| Component | Version |
|-----------|---------|
| sing-box (lab + client target) | 1.14.4 |
| .NET / WPF app | net9.0-windows |
| Target OS | Windows 10/11 x64 |

## Architecture (summary)

Windows WPF client drives official `sing-box` for:

1. **Discovery (proxy-isolated)** — no Windows default-route change  
2. **Ranking** of PASS methods  
3. **TUN connect** attempt in rank order with HTTPS + exit-IP verification  
4. **Speed Test** and **Live Log**

Server side is an isolated `direct-vpn-lab` systemd unit. Existing Outline /
WireGuard / Iran-link services are out of scope for mutation.

See `docs/ARCHITECTURE.md`.

## Method matrix size

**24 target methods** defined (A01–F04).

| Status | Count | Methods |
|--------|------:|---------|
| PASS (proxy evidence) | 7 | A01, A02, A03, B01, B04, C01, C03 |
| FAIL (proxy evidence) | 2 | E01, E03 |
| SKIPPED | 2 | F01, F02 (sing-box ≥ 1.15 required) |
| INSTALLED_NOT_BATCH_PROBED | 9 | A04, A05, B02, B03, B05, B06, C02, D01, D02 |
| UNVERIFIED (endpoint/TUN) | 3 | E04, F03, F04 |
| Likely same as FAIL UDP | 1 | E02 (installed; not separately proven) |

Evidence detail: `reports/METHODS_REPORT.txt`.

## Proxy validation method

For each probed method:

1. Build method-specific client outbound config  
2. Start sing-box with **loopback mixed inbound** only  
3. Force HTTPS via that proxy (`1.1.1.1/cdn-cgi/trace` + `api.ipify.org`)  
4. Require success response and exit IP matching lab server  
5. Tear down process  

This is **DIRECT_PROXY_VERIFIED** evidence when PASS.

## TUN / system VPN status

| Item | Status |
|------|--------|
| TUN config generation in app | Implemented |
| Wintun bundling expectation | Implemented (local asset; not in git) |
| Administrator requirement | Enforced / warned |
| End-to-end TUN verification on workstation | **PENDING** |
| `WINDOWS_TUN_VERIFIED` | **PENDING** |
| `DIRECT_VPN_VERIFIED` | **PENDING** |

**Important:** Proxy PASS ≠ system-wide VPN PASS.

## Iran network test

| Flag | Status |
|------|--------|
| `IRAN_NETWORK_TEST_PENDING` | Partial / pending formal geo attribution |
| `DIRECT_CONNECTION_FROM_IRAN_CONFIRMED` | **NOT claimed** |

UDP methods E01/E03 failed on the operator client path; interpret as path-
specific results only.

## Known limitations

- MASQUE skipped on stable 1.14.4  
- Endpoint methods (WG/OpenVPN) need TUN-stage proof  
- Full Kill Switch not claimed  
- Standalone EXE (~207MB) is built locally; not stored in git  
- Lab credentials must be supplied privately via sample file copy  

## Critical fixes applied (post-review)

- Discovery: standard HTTPS validation; PASS requires ≥2/3 probes + exact exit IP  
- Discovery: endpoint methods never auto-PASS without data-path proof  
- Connect: only `TestStatus.Pass` candidates; TUN interface + HTTPS + exact exit IP required  
- Lifecycle: Closing waits for cleanup; orphan PID recovery; health-check overlap gate  
- Speed Test: failed HTTP is not treated as Mbps=0 success  
- Live Log: real secret redaction  

Operator must still manually verify VPN/TUN before any `VPN_VERIFIED` / final PASS claim.

## Incomplete / next work

1. Operator TUN/VPN manual verification checklist  
2. Batch-probe remaining installed TCP/UDP methods  
3. Formal Iran network confirmation with country evidence  
4. Optional move to sing-box 1.15+ for MASQUE experiments on a safe path  


## Delivery flags (current)

```text
SERVER_CONFIGURED
SERVER_VERIFIED
WINDOWS_APP_BUILT
DIRECT_PROXY_VERIFIED
WINDOWS_TUN_VERIFIED          PENDING
DIRECT_VPN_VERIFIED           PENDING
IRAN_NETWORK_TEST_PENDING
DIRECT_CONNECTION_FROM_IRAN_CONFIRMED   NOT YET
NEW_SERVER_REQUIRED           NO
```
