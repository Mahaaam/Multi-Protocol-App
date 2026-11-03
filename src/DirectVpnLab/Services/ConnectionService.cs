using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using DirectVpnLab.Models;

namespace DirectVpnLab.Services;

public sealed class ConnectionService
{
    public const string TunInterfaceName = "DirectVpnLab";

    private readonly LiveLogService _log;
    private readonly LabCredentials _cred;
    private SingBoxProcess? _tunProcess;
    private ProtocolMethod? _active;
    private bool _verifiedConnected;
    private bool _pathVerified;
    private string? _netBeforePath;
    private ProcessOwnership? _ownership;

    public ProtocolMethod? ActiveMethod => _active;
    public bool TunnelPathVerified => _pathVerified;

    public bool IsConnected =>
        _verifiedConnected &&
        _pathVerified &&
        _tunProcess?.IsRunning == true &&
        _active != null &&
        TunInterfaceUp();

    public ConnectionService(LiveLogService log, LabCredentials cred)
    {
        _log = log;
        _cred = cred;
    }

    public async Task RecoverOrphansAsync()
    {
        var marker = Path.Combine(AppPaths.StateDir, "active-method.txt");
        var ownFile = OwnershipPath();
        if (!File.Exists(marker) && !File.Exists(ownFile) && !File.Exists(Path.Combine(AppPaths.StateDir, "tun-pid.txt")))
        {
            return;
        }

        _log.Warn("Previous session marker found — recovering application-owned resources");
        var (killed, detail) = await KillOwnedSingBoxAsync();
        if (!killed && !string.IsNullOrWhiteSpace(detail))
        {
            _log.Warn($"Orphan process handling: {detail}");
        }

        TryDelete(marker);
        TryDelete(ownFile);
        TryDelete(Path.Combine(AppPaths.StateDir, "tun-pid.txt"));
        TryDelete(Path.Combine(AppPaths.StateDir, "net-before.json"));
        _verifiedConnected = false;
        _pathVerified = false;
        _active = null;
        _log.Info("Orphan cleanup finished for Direct VPN Lab markers");
    }

    public async Task<(bool ok, string message)> ConnectBestAsync(
        IEnumerable<ProtocolMethod> rankedPass,
        CancellationToken ct)
    {
        var fatal = CheckFatalPrerequisites();
        if (fatal != null)
        {
            _log.Fail(fatal);
            return (false, fatal);
        }

        var candidates = rankedPass
            .Where(m => m.Status == TestStatus.Pass)
            .OrderBy(m => m.Rank == 0 ? int.MaxValue : m.Rank)
            .ThenByDescending(m => m.QualityScore)
            .ToList();

        if (candidates.Count == 0)
        {
            return (false, "CONNECTION FAILED - no PASS methods available. Run TEST ALL first.");
        }

        WarnIfOtherVpn();

        string? lastFail = null;
        foreach (var m in candidates)
        {
            ct.ThrowIfCancellationRequested();

            // Re-check fatal gates between candidates (admin revoked, wintun removed)
            fatal = CheckFatalPrerequisites();
            if (fatal != null)
            {
                _log.Fail(fatal);
                _verifiedConnected = false;
                _pathVerified = false;
                return (false, fatal);
            }

            _log.Info($"Starting Windows tunnel with {m.Id} {m.DisplayName}");
            await CleanupTunnelAsync(verifyInternetRestored: false);
            var (ok, msg) = await TryConnectMethodAsync(m, ct);
            if (ok)
            {
                _active = m;
                _verifiedConnected = true;
                return (true, msg);
            }

            lastFail = $"{m.Id}: {msg}";
            _log.Warn($"Tunnel candidate failed: {lastFail}");
            _verifiedConnected = false;
            _pathVerified = false;
            await CleanupTunnelAsync(verifyInternetRestored: false);

            // Fatal class errors stop the whole cascade
            if (IsFatalConnectError(msg))
            {
                return (false, msg);
            }
        }

        _verifiedConnected = false;
        _pathVerified = false;
        return (false, lastFail != null
            ? $"CONNECTION FAILED — last error: {lastFail}"
            : "CONNECTION FAILED");
    }

    public string? CheckFatalPrerequisites()
    {
        if (!IsAdministrator())
        {
            return "Windows Permission Error — Administrator required for TUN. UAC elevation was denied or unavailable.";
        }

        if (!File.Exists(AppPaths.WintunDll) && !File.Exists(Path.Combine(
                Path.GetDirectoryName(AppPaths.SingBoxExe) ?? "", "wintun.dll")))
        {
            return "TUN Driver Error — wintun.dll missing from application package.";
        }

        if (!File.Exists(AppPaths.SingBoxExe))
        {
            return "Engine Error — sing-box.exe missing.";
        }

        return null;
    }

    private static bool IsFatalConnectError(string msg) => IsFatalMessage(msg);

    public static bool IsFatalMessage(string msg)
    {
        var d = msg.ToLowerInvariant();
        return d.Contains("administrator") ||
               d.Contains("permission") ||
               d.Contains("wintun") ||
               d.Contains("tun driver") ||
               d.Contains("elevation") ||
               d.Contains("legacy inbound") ||
               d.Contains("removed in sing-box") ||
               d.Contains("initialize inbound") ||
               d.Contains("tun config invalid") ||
               d.Contains("shared tun") ||
               (d.Contains("sing-box check") && d.Contains("inbound"));
    }

    public async Task<(bool ok, string message)> DisconnectAsync()
    {
        _log.Info("Disconnect requested");
        _verifiedConnected = false;
        _pathVerified = false;
        var (cleanOk, cleanMsg) = await CleanupTunnelAsync(verifyInternetRestored: true);
        _active = null;
        if (!cleanOk)
        {
            _log.Fail($"Disconnect cleanup incomplete: {cleanMsg}");
            return (false, cleanMsg);
        }

        _log.Info("Disconnected - application-owned resources cleaned; normal path check OK");
        return (true, "Disconnected and network cleanup verified");
    }

    private async Task<(bool ok, string message)> TryConnectMethodAsync(ProtocolMethod m, CancellationToken ct)
    {
        try
        {
            if (!IsAdministrator())
            {
                _log.Warn("Windows Permission Error: Administrator required for TUN");
                return (false, "Windows Permission Error - run as Administrator for TUN");
            }

            // Build + validate BEFORE any Windows route/DNS mutation (sing-box start)
            var cfg = ConfigFactory.BuildTunConfig(_cred, m, AppPaths.WorkDir);
            var (checkOk, checkDetail) = await ValidateTunConfigAsync(cfg, ct);
            if (!checkOk)
            {
                _log.Fail($"TUN config check failed for {m.Id}: {checkDetail}");
                if (IsSharedTunConfigFailure(checkDetail))
                {
                    return (false, $"TUN Config Invalid (shared/fatal): {TrimErr(checkDetail)}");
                }
                return (false, $"TUN Config Invalid: {TrimErr(checkDetail)}");
            }
            _log.Info($"TUN config validated (sing-box check) for {m.Id}");

            _netBeforePath = Path.Combine(AppPaths.StateDir, "net-before.json");
            File.WriteAllText(_netBeforePath, CaptureNetSnapshotJson());
            _log.Info("Captured baseline interfaces + routes + DNS");

            _tunProcess = new SingBoxProcess(_log);
            await _tunProcess.StartAsync(cfg, ct);
            _ownership = new ProcessOwnership
            {
                Pid = _tunProcess.ProcessId ?? 0,
                ExePath = _tunProcess.ExecutablePath ?? Path.GetFullPath(AppPaths.SingBoxExe),
                StartedAtUtc = _tunProcess.StartedAtUtc ?? DateTime.UtcNow,
                ConfigPath = _tunProcess.ConfigPath ?? cfg
            };
            WriteOwnershipFile(_ownership);

            for (var i = 0; i < 10 && !TunInterfaceUp(); i++)
            {
                await Task.Delay(300, ct);
            }

            if (!TunInterfaceUp())
            {
                return (false, "TUN Error: DirectVpnLab interface not active");
            }
            _log.Info("TUN interface active: DirectVpnLab");

            _log.Info("Verifying effective Windows route uses DirectVpnLab");
            var (pathOk, pathDetail) = VerifyTrafficUsesTun(new[] { "1.1.1.1", "8.8.8.8" });
            if (!pathOk)
            {
                _pathVerified = false;
                return (false, $"Route Path Error: {pathDetail}");
            }
            _pathVerified = true;
            _log.Info($"Effective route verified via DirectVpnLab ({pathDetail})");

            _log.Info("Checking DNS / HTTPS via TUN (system proxy disabled)");
            var (httpsOk, exitIp, detail) = await VerifyInternetAsync(ct);
            if (!httpsOk)
            {
                _pathVerified = false;
                return (false, $"Internet Verification Failed: {detail}");
            }

            if (!IsExactExpectedExit(exitIp))
            {
                _pathVerified = false;
                return (false, $"Exit IP Mismatch: got {exitIp} expected {_cred.server_ip}");
            }

            // Re-check path after traffic (still TUN)
            var (pathOk2, pathDetail2) = VerifyTrafficUsesTun(new[] { "1.1.1.1" });
            if (!pathOk2 || !TunInterfaceUp())
            {
                _pathVerified = false;
                return (false, $"Route Path Error after HTTPS: {pathDetail2}");
            }

            _log.Info($"Exit IP verified: {exitIp}");
            _log.Pass($"CONNECTED - {m.Id} {m.DisplayName}");
            m.ExitIp = exitIp;
            File.WriteAllText(Path.Combine(AppPaths.StateDir, "active-method.txt"), m.Id);
            return (true, $"CONNECTED via {m.DisplayName}");
        }
        catch (Exception ex)
        {
            _pathVerified = false;
            var msg = ex.Message;
            if (IsSharedTunConfigFailure(msg) || IsFatalMessage(msg))
                msg = "TUN Config Invalid (shared/fatal): " + TrimErr(msg);
            else if (msg.Contains("tun", StringComparison.OrdinalIgnoreCase))
                msg = "TUN Error: " + msg;
            else if (msg.Contains("route", StringComparison.OrdinalIgnoreCase))
                msg = "Route Error: " + msg;
            return (false, msg);
        }
    }

    private async Task<(bool ok, string detail)> ValidateTunConfigAsync(string cfgPath, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = AppPaths.SingBoxExe,
                Arguments = $"check -c \"{cfgPath}\"",
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(AppPaths.SingBoxExe) ?? AppPaths.BaseDir
            };
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("sing-box check failed to start");
            var errTask = p.StandardError.ReadToEndAsync(ct);
            var outTask = p.StandardOutput.ReadToEndAsync(ct);
            await p.WaitForExitAsync(ct);
            var err = (await errTask).Trim();
            _ = await outTask;
            if (p.ExitCode != 0)
            {
                return (false, string.IsNullOrWhiteSpace(err) ? $"sing-box check exit={p.ExitCode}" : err);
            }
            return (true, "ok");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    public static bool IsSharedTunConfigFailure(string detail)
    {
        var d = (detail ?? "").ToLowerInvariant();
        return d.Contains("legacy inbound") ||
               d.Contains("removed in sing-box") ||
               d.Contains("initialize inbound") ||
               d.Contains("migrate-legacy-inbound") ||
               (d.Contains("inbound") && (d.Contains("deprecated") || d.Contains("unknown field") || d.Contains("decode")));
    }

    private static string TrimErr(string s) =>
        string.IsNullOrWhiteSpace(s) ? "" : (s.Length <= 220 ? s.Trim() : s.Trim()[..220]);

    private async Task<(bool ok, string? exitIp, string detail)> VerifyInternetAsync(CancellationToken ct)
    {
        var handler = new HttpClientHandler
        {
            UseProxy = false,
            Proxy = null,
            AllowAutoRedirect = true
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };

        var destinations = new[]
        {
            "https://1.1.1.1/cdn-cgi/trace",
            "https://api.ipify.org",
            "https://www.cloudflare.com/cdn-cgi/trace"
        };

        string? ip = null;
        var successes = 0;
        string lastErr = "no destination succeeded";
        foreach (var url in destinations)
        {
            try
            {
                using var resp = await client.GetAsync(url, ct);
                if (!resp.IsSuccessStatusCode)
                {
                    lastErr = $"HTTP {(int)resp.StatusCode} for {url}";
                    continue;
                }
                var body = await resp.Content.ReadAsStringAsync(ct);
                successes++;
                if (url.Contains("ipify", StringComparison.OrdinalIgnoreCase))
                {
                    ip = body.Trim();
                }
                else
                {
                    foreach (var line in body.Split('\n'))
                    {
                        if (line.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
                        {
                            ip ??= line[3..].Trim();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                lastErr = ex.Message;
            }
        }

        if (successes >= 2 && IsExactExpectedExit(ip))
        {
            return (true, ip, "ok");
        }
        if (successes >= 2 && !IsExactExpectedExit(ip))
        {
            return (false, ip, "Exit IP incomplete/mismatch after HTTPS success");
        }
        return (false, ip, lastErr);
    }

    public async Task<(bool ok, string? exitIp, string detail)> VerifyHealthAsync(CancellationToken ct)
    {
        if (_tunProcess?.IsRunning != true || !TunInterfaceUp() || !_pathVerified)
        {
            return (false, null, "TUN/path not active");
        }

        var (pathOk, pathDetail) = VerifyTrafficUsesTun(new[] { "1.1.1.1" });
        if (!pathOk)
        {
            _pathVerified = false;
            return (false, null, pathDetail);
        }

        return await VerifyInternetAsync(ct);
    }

    private bool IsExactExpectedExit(string? ip) =>
        !string.IsNullOrWhiteSpace(ip) &&
        string.Equals(ip.Trim(), _cred.server_ip.Trim(), StringComparison.Ordinal);

    private async Task<(bool ok, string message)> CleanupTunnelAsync(bool verifyInternetRestored)
    {
        _verifiedConnected = false;
        _pathVerified = false;
        if (_tunProcess != null)
        {
            await _tunProcess.StopAsync();
            await _tunProcess.DisposeAsync();
            _tunProcess = null;
        }

        var (killed, killDetail) = await KillOwnedSingBoxAsync();
        if (!killed && killDetail.Contains("refused", StringComparison.OrdinalIgnoreCase))
        {
            return (false, killDetail);
        }

        TryDelete(Path.Combine(AppPaths.StateDir, "active-method.txt"));
        TryDelete(OwnershipPath());
        TryDelete(Path.Combine(AppPaths.StateDir, "tun-pid.txt"));
        _ownership = null;

        try
        {
            foreach (var f in Directory.EnumerateFiles(AppPaths.WorkDir, "tun-*.json"))
            {
                TryDelete(f);
            }
        }
        catch { /* ignore */ }

        for (var i = 0; i < 10 && TunInterfaceUp(); i++)
        {
            await Task.Delay(250);
        }

        if (TunInterfaceUp())
        {
            return (false, "Cleanup Error: DirectVpnLab TUN interface still present");
        }

        var (pathClear, pathMsg) = VerifyTrafficUsesTun(new[] { "1.1.1.1", "8.8.8.8" });
        if (pathClear)
        {
            // Still routing via our TUN after stop => failure
            return (false, "Cleanup Error: effective route still uses DirectVpnLab");
        }
        _log.Info($"Post-cleanup route check: {pathMsg}");

        if (verifyInternetRestored)
        {
            var restored = await ProbeDirectInternetAsync();
            if (!restored.ok)
            {
                return (false, $"Cleanup Error: normal internet path not restored ({restored.detail})");
            }
            _log.Info("Normal internet path probe succeeded after disconnect");
        }

        if (_netBeforePath != null)
        {
            TryDelete(_netBeforePath);
            _netBeforePath = null;
        }

        return (true, "cleanup verified");
    }

    private async Task<(bool ok, string detail)> ProbeDirectInternetAsync()
    {
        try
        {
            var handler = new HttpClientHandler { UseProxy = false, Proxy = null };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            using var resp = await client.GetAsync("https://1.1.1.1/cdn-cgi/trace", cts.Token);
            if (!resp.IsSuccessStatusCode)
            {
                return (false, $"HTTP {(int)resp.StatusCode}");
            }
            return (true, "ok");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    private void WriteOwnershipFile(ProcessOwnership own)
    {
        var json = JsonSerializer.Serialize(own, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(OwnershipPath(), json);
        // legacy pid file for older recover paths
        File.WriteAllText(Path.Combine(AppPaths.StateDir, "tun-pid.txt"), own.Pid.ToString());
    }

    private static string OwnershipPath() => Path.Combine(AppPaths.StateDir, "tun-ownership.json");

    private async Task<(bool killedOrAbsent, string detail)> KillOwnedSingBoxAsync()
    {
        ProcessOwnership? own = _ownership;
        try
        {
            var path = OwnershipPath();
            if (own == null && File.Exists(path))
            {
                own = JsonSerializer.Deserialize<ProcessOwnership>(File.ReadAllText(path));
            }
        }
        catch (Exception ex)
        {
            return (false, $"ownership parse failed: {ex.Message}");
        }

        // migrate legacy pid-only file: refuse kill without path/start evidence
        var legacyPid = Path.Combine(AppPaths.StateDir, "tun-pid.txt");
        if (own == null && File.Exists(legacyPid))
        {
            TryDelete(legacyPid);
            return (true, "legacy pid-only marker discarded without kill (insufficient ownership proof)");
        }

        if (own == null || own.Pid <= 0)
        {
            return (true, "no owned process recorded");
        }

        try
        {
            Process p;
            try
            {
                p = Process.GetProcessById(own.Pid);
            }
            catch (ArgumentException)
            {
                return (true, "owned pid already absent");
            }

            using (p)
            {
                if (!p.ProcessName.Contains("sing-box", StringComparison.OrdinalIgnoreCase))
                {
                    return (false, $"refused kill: pid {own.Pid} name is '{p.ProcessName}', not sing-box");
                }

                string? livePath = null;
                try { livePath = p.MainModule?.FileName; } catch { /* access denied */ }
                var expected = Path.GetFullPath(own.ExePath);
                var bundled = Path.GetFullPath(AppPaths.SingBoxExe);
                if (!string.IsNullOrWhiteSpace(livePath))
                {
                    var liveFull = Path.GetFullPath(livePath);
                    if (!PathsEqual(liveFull, expected) && !PathsEqual(liveFull, bundled))
                    {
                        return (false, $"refused kill: exe path mismatch live='{liveFull}' expected='{expected}'");
                    }
                }
                else
                {
                    // Without readable module path, require start-time window match only is weaker — refuse
                    return (false, "refused kill: cannot read process executable path for ownership proof");
                }

                DateTime startUtc;
                try { startUtc = p.StartTime.ToUniversalTime(); }
                catch
                {
                    return (false, "refused kill: cannot read process start time");
                }

                var delta = (startUtc - own.StartedAtUtc).Duration();
                if (delta > TimeSpan.FromSeconds(15))
                {
                    return (false, $"refused kill: start time delta {delta.TotalSeconds:F0}s exceeds ownership window");
                }

                _log.Warn($"Stopping verified owned sing-box pid={own.Pid}");
                p.Kill(entireProcessTree: true);
                await p.WaitForExitAsync();
                TryDelete(OwnershipPath());
                TryDelete(legacyPid);
                return (true, "owned process stopped");
            }
        }
        catch (Exception ex)
        {
            return (false, $"kill failed: {ex.Message}");
        }
    }

    private static bool PathsEqual(string a, string b) =>
        string.Equals(Path.GetFullPath(a).TrimEnd('\\'), Path.GetFullPath(b).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);

    private (bool usesTun, string detail) VerifyTrafficUsesTun(IEnumerable<string> destinations)
    {
        var tunIndex = GetTunInterfaceIndex();
        if (tunIndex is null)
        {
            return (false, "DirectVpnLab interface index not found");
        }

        var hits = new List<string>();
        var misses = new List<string>();
        foreach (var dest in destinations)
        {
            if (!IPAddress.TryParse(dest, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                misses.Add($"{dest}: invalid IPv4");
                continue;
            }

            var addr = BitConverter.ToUInt32(ip.GetAddressBytes(), 0);
            var rc = GetBestInterface(addr, out var bestIf);
            if (rc != 0)
            {
                misses.Add($"{dest}: GetBestInterface rc={rc}");
                continue;
            }

            if (bestIf == tunIndex.Value)
            {
                hits.Add($"{dest}->if{bestIf}");
            }
            else
            {
                var alias = FindInterfaceAliasByIndex((int)bestIf) ?? $"if{bestIf}";
                misses.Add($"{dest}->{alias}");
            }
        }

        if (hits.Count > 0 && misses.Count == 0)
        {
            return (true, string.Join(", ", hits));
        }

        return (false, misses.Count > 0
            ? string.Join("; ", misses)
            : "no route evidence");
    }

    private static int? GetTunInterfaceIndex()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!ni.Name.Contains(TunInterfaceName, StringComparison.OrdinalIgnoreCase) &&
                    !ni.Description.Contains(TunInterfaceName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                try
                {
                    return ni.GetIPProperties().GetIPv4Properties()?.Index;
                }
                catch
                {
                    // ignore
                }
            }
        }
        catch
        {
            // ignore
        }
        return null;
    }

    private static string? FindInterfaceAliasByIndex(int index)
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    if (ni.GetIPProperties().GetIPv4Properties()?.Index == index)
                    {
                        return ni.Name;
                    }
                }
                catch { /* ignore */ }
            }
        }
        catch { /* ignore */ }
        return null;
    }

    private static bool TunInterfaceUp()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!ni.Name.Contains(TunInterfaceName, StringComparison.OrdinalIgnoreCase) &&
                    !ni.Description.Contains(TunInterfaceName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                return ni.OperationalStatus == OperationalStatus.Up;
            }
        }
        catch
        {
            // ignore
        }
        return false;
    }

    private void WarnIfOtherVpn()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                var name = ni.Name + " " + ni.Description;
                if (name.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("TAP", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Wintun", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Outline", StringComparison.OrdinalIgnoreCase))
                {
                    if (!name.Contains(TunInterfaceName, StringComparison.OrdinalIgnoreCase))
                    {
                        _log.Warn($"Other VPN adapter detected: {ni.Name}. Results may be affected.");
                    }
                }
            }
        }
        catch
        {
            // ignore
        }
    }

    private static string CaptureNetSnapshotJson()
    {
        var ifaces = new List<object>();
        var dns = new List<object>();
        try
        {
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
            {
                var props = n.GetIPProperties();
                int? idx = null;
                try { idx = props.GetIPv4Properties()?.Index; } catch { /* ignore */ }
                ifaces.Add(new
                {
                    n.Name,
                    n.Description,
                    Status = n.OperationalStatus.ToString(),
                    Type = n.NetworkInterfaceType.ToString(),
                    Index = idx,
                    Id = n.Id
                });
                dns.Add(new
                {
                    n.Name,
                    Index = idx,
                    DnsServers = props.DnsAddresses.Select(a => a.ToString()).ToArray(),
                    Dhcp = props.GetIPv4Properties()?.IsDhcpEnabled
                });
            }
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { capturedAt = DateTime.UtcNow, error = ex.Message });
        }

        var routes = CaptureRoutesViaNetsh();
        return JsonSerializer.Serialize(new
        {
            capturedAt = DateTime.UtcNow,
            interfaces = ifaces,
            dns,
            routes
        }, new JsonSerializerOptions { WriteIndented = true });
    }

    private static object CaptureRoutesViaNetsh()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "interface ipv4 show route",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            using var p = Process.Start(psi);
            if (p == null) return new { error = "netsh failed to start" };
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(8000);
            // Store text snapshot (not parsed aggressively) for before/after comparison evidence
            var lines = output.Split('\n')
                .Select(l => l.TrimEnd())
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .Take(400)
                .ToArray();
            return new { source = "netsh interface ipv4 show route", lines };
        }
        catch (Exception ex)
        {
            return new { error = ex.Message };
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch { /* ignore */ }
    }

    public static bool IsAdministrator()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetBestInterface(uint dwDestAddr, out uint pdwBestIfIndex);

    private sealed class ProcessOwnership
    {
        public int Pid { get; set; }
        public string ExePath { get; set; } = "";
        public DateTime StartedAtUtc { get; set; }
        public string ConfigPath { get; set; } = "";
    }
}
