using System.Diagnostics;
using System.Net.Http;
using System.Net.NetworkInformation;
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
    private string? _netBeforePath;

    public ProtocolMethod? ActiveMethod => _active;
    public bool IsConnected =>
        _verifiedConnected &&
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
        var pidFile = Path.Combine(AppPaths.StateDir, "tun-pid.txt");
        if (!File.Exists(marker) && !File.Exists(pidFile))
        {
            return;
        }

        _log.Warn("Previous session marker found — recovering application-owned resources");
        await KillOwnedSingBoxAsync();
        TryDelete(marker);
        TryDelete(pidFile);
        TryDelete(Path.Combine(AppPaths.StateDir, "net-before.json"));
        _verifiedConnected = false;
        _active = null;
        _log.Info("Orphan cleanup completed for Direct VPN Lab resources");
    }

    public async Task<(bool ok, string message)> ConnectBestAsync(
        IEnumerable<ProtocolMethod> rankedPass,
        CancellationToken ct)
    {
        var candidates = rankedPass
            .Where(m => m.Status == TestStatus.Pass)
            .OrderBy(m => m.Rank == 0 ? int.MaxValue : m.Rank)
            .ThenByDescending(m => m.QualityScore)
            .ToList();

        if (candidates.Count == 0)
        {
            return (false, "CONNECTION FAILED - no PASS methods available");
        }

        WarnIfOtherVpn();

        foreach (var m in candidates)
        {
            ct.ThrowIfCancellationRequested();
            _log.Info($"Starting Windows tunnel with {m.Id} {m.DisplayName}");
            await CleanupTunnelAsync();
            var (ok, msg) = await TryConnectMethodAsync(m, ct);
            if (ok)
            {
                _active = m;
                _verifiedConnected = true;
                return (true, msg);
            }
            _log.Warn($"Tunnel candidate failed: {m.Id} - {msg}");
            _verifiedConnected = false;
            await CleanupTunnelAsync();
        }

        _verifiedConnected = false;
        return (false, "CONNECTION FAILED");
    }

    public async Task DisconnectAsync()
    {
        _log.Info("Disconnect requested");
        _verifiedConnected = false;
        await CleanupTunnelAsync();
        _active = null;
        _log.Info("Disconnected - application-owned resources cleaned");
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

            _netBeforePath = Path.Combine(AppPaths.StateDir, "net-before.json");
            File.WriteAllText(_netBeforePath, CaptureNetSnapshotJson());

            var cfg = ConfigFactory.BuildTunConfig(_cred, m, AppPaths.WorkDir);
            _tunProcess = new SingBoxProcess(_log);
            await _tunProcess.StartAsync(cfg, ct);
            WritePidFile(_tunProcess.ProcessId);

            // Allow TUN adapter to appear
            for (var i = 0; i < 10 && !TunInterfaceUp(); i++)
            {
                await Task.Delay(300, ct);
            }

            if (!TunInterfaceUp())
            {
                return (false, "TUN Error: DirectVpnLab interface not active");
            }
            _log.Info("TUN interface active: DirectVpnLab");

            _log.Info("Checking DNS");
            _log.Info("Verifying external connectivity via TUN (system proxy disabled)");

            var (httpsOk, exitIp, detail) = await VerifyInternetAsync(ct);
            if (!httpsOk)
            {
                return (false, $"Internet Verification Failed: {detail}");
            }

            if (!IsExactExpectedExit(exitIp))
            {
                return (false, $"Exit IP Mismatch: got {exitIp} expected {_cred.server_ip}");
            }

            if (!TunInterfaceUp())
            {
                return (false, "TUN Error: interface disappeared after verification");
            }

            _log.Info($"Exit IP verified: {exitIp}");
            _log.Pass($"CONNECTED - {m.Id} {m.DisplayName}");
            m.ExitIp = exitIp;
            File.WriteAllText(Path.Combine(AppPaths.StateDir, "active-method.txt"), m.Id);
            return (true, $"CONNECTED via {m.DisplayName}");
        }
        catch (Exception ex)
        {
            var msg = ex.Message;
            if (msg.Contains("tun", StringComparison.OrdinalIgnoreCase))
                msg = "TUN Error: " + msg;
            else if (msg.Contains("route", StringComparison.OrdinalIgnoreCase))
                msg = "Route Error: " + msg;
            return (false, msg);
        }
    }

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
            return (false, ip, $"Exit IP incomplete/mismatch after HTTPS success");
        }
        return (false, ip, lastErr);
    }

    public async Task<(bool ok, string? exitIp, string detail)> VerifyHealthAsync(CancellationToken ct)
    {
        if (_tunProcess?.IsRunning != true || !TunInterfaceUp())
        {
            return (false, null, "TUN not active");
        }
        return await VerifyInternetAsync(ct);
    }

    private bool IsExactExpectedExit(string? ip) =>
        !string.IsNullOrWhiteSpace(ip) &&
        string.Equals(ip.Trim(), _cred.server_ip.Trim(), StringComparison.Ordinal);

    private async Task CleanupTunnelAsync()
    {
        _verifiedConnected = false;
        if (_tunProcess != null)
        {
            await _tunProcess.StopAsync();
            await _tunProcess.DisposeAsync();
            _tunProcess = null;
        }

        await KillOwnedSingBoxAsync();

        TryDelete(Path.Combine(AppPaths.StateDir, "active-method.txt"));
        TryDelete(Path.Combine(AppPaths.StateDir, "tun-pid.txt"));

        // App-owned work configs
        try
        {
            foreach (var f in Directory.EnumerateFiles(AppPaths.WorkDir, "tun-*.json"))
            {
                TryDelete(f);
            }
        }
        catch { /* ignore */ }

        // Confirm TUN interface is gone (best-effort; do not touch other VPNs)
        for (var i = 0; i < 8 && TunInterfaceUp(); i++)
        {
            await Task.Delay(200);
        }
        if (TunInterfaceUp())
        {
            _log.Warn("TUN interface still present after cleanup wait");
        }
        else
        {
            _log.Info("TUN interface cleanup confirmed (DirectVpnLab absent or down)");
        }

        if (_netBeforePath != null)
        {
            TryDelete(_netBeforePath);
            _netBeforePath = null;
        }
    }

    private void WritePidFile(int? pid)
    {
        try
        {
            var path = Path.Combine(AppPaths.StateDir, "tun-pid.txt");
            if (pid is > 0)
            {
                File.WriteAllText(path, pid.Value.ToString());
            }
        }
        catch { /* ignore */ }
    }

    private async Task KillOwnedSingBoxAsync()
    {
        var pidFile = Path.Combine(AppPaths.StateDir, "tun-pid.txt");
        try
        {
            if (File.Exists(pidFile) &&
                int.TryParse(File.ReadAllText(pidFile).Trim(), out var pid) &&
                pid > 0)
            {
                try
                {
                    var p = Process.GetProcessById(pid);
                    if (p.ProcessName.Contains("sing-box", StringComparison.OrdinalIgnoreCase))
                    {
                        _log.Warn($"Stopping leftover owned sing-box pid={pid}");
                        p.Kill(entireProcessTree: true);
                        await p.WaitForExitAsync();
                    }
                }
                catch (ArgumentException)
                {
                    // process already gone
                }
            }
        }
        catch
        {
            // ignore
        }
        finally
        {
            TryDelete(pidFile);
        }
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
        try
        {
            var ifaces = NetworkInterface.GetAllNetworkInterfaces()
                .Select(n => new
                {
                    n.Name,
                    n.Description,
                    Status = n.OperationalStatus.ToString(),
                    Type = n.NetworkInterfaceType.ToString(),
                    Id = n.Id
                })
                .ToArray();
            return JsonSerializer.Serialize(new
            {
                capturedAt = DateTime.UtcNow,
                interfaces = ifaces
            }, new JsonSerializerOptions { WriteIndented = true });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { capturedAt = DateTime.UtcNow, error = ex.Message });
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
}
