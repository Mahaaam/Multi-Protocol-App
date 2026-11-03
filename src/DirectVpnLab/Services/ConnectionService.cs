using System.Diagnostics;
using System.Net.Http;
using System.Net.NetworkInformation;
using DirectVpnLab.Models;

namespace DirectVpnLab.Services;

public sealed class ConnectionService
{
    private readonly LiveLogService _log;
    private readonly LabCredentials _cred;
    private SingBoxProcess? _tunProcess;
    private ProtocolMethod? _active;

    public ProtocolMethod? ActiveMethod => _active;
    public bool IsConnected => _tunProcess?.IsRunning == true && _active != null;

    public ConnectionService(LiveLogService log, LabCredentials cred)
    {
        _log = log;
        _cred = cred;
    }

    public async Task<(bool ok, string message)> ConnectBestAsync(
        IEnumerable<ProtocolMethod> rankedPass,
        CancellationToken ct)
    {
        var candidates = rankedPass
            .Where(m => m.Status == TestStatus.Pass || m.Status == TestStatus.Unverified)
            .OrderBy(m => m.Rank == 0 ? int.MaxValue : m.Rank)
            .ThenByDescending(m => m.QualityScore)
            .ToList();

        if (candidates.Count == 0)
        {
            return (false, "CONNECTION FAILED - no successful methods");
        }

        WarnIfOtherVpn();

        foreach (var m in candidates)
        {
            ct.ThrowIfCancellationRequested();
            _log.Info($"Starting Windows tunnel with {m.Id} {m.DisplayName}");
            var (ok, msg) = await TryConnectMethodAsync(m, ct);
            if (ok)
            {
                _active = m;
                return (true, msg);
            }
            _log.Warn($"Tunnel candidate failed: {m.Id} - {msg}");
            await CleanupTunnelAsync();
        }

        return (false, "CONNECTION FAILED");
    }

    public async Task DisconnectAsync()
    {
        _log.Info("Disconnect requested");
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

            var before = CaptureNetSnapshot();
            File.WriteAllText(Path.Combine(AppPaths.StateDir, "net-before.json"), before);

            var cfg = ConfigFactory.BuildTunConfig(_cred, m, AppPaths.WorkDir);
            _tunProcess = new SingBoxProcess(_log);
            await _tunProcess.StartAsync(cfg, ct);

            _log.Info("Checking DNS");
            _log.Info("Verifying external connectivity");

            var (httpsOk, exitIp, detail) = await VerifyInternetAsync(ct);
            if (!httpsOk)
            {
                return (false, $"Internet Verification Failed: {detail}");
            }

            if (!IsExpectedExit(exitIp))
            {
                return (false, $"Exit IP Mismatch: got {exitIp}");
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
            {
                msg = "TUN Error: " + msg;
            }
            else if (msg.Contains("route", StringComparison.OrdinalIgnoreCase))
            {
                msg = "Route Error: " + msg;
            }
            return (false, msg);
        }
    }

    private async Task<(bool ok, string? exitIp, string detail)> VerifyInternetAsync(CancellationToken ct)
    {
        // Do NOT use system proxy; traffic should flow via TUN
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
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
                var body = await client.GetStringAsync(url, ct);
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

        // Require at least 2 destinations OR (1 success + exit ip)
        if (successes >= 2 || (successes >= 1 && !string.IsNullOrWhiteSpace(ip)))
        {
            return (true, ip, "ok");
        }
        return (false, ip, lastErr);
    }

    private bool IsExpectedExit(string? ip) =>
        !string.IsNullOrWhiteSpace(ip) &&
        (ip == _cred.server_ip || ip.StartsWith("82.23.248.", StringComparison.Ordinal));

    private async Task CleanupTunnelAsync()
    {
        if (_tunProcess != null)
        {
            await _tunProcess.StopAsync();
            await _tunProcess.DisposeAsync();
            _tunProcess = null;
        }
        try
        {
            var active = Path.Combine(AppPaths.StateDir, "active-method.txt");
            if (File.Exists(active)) File.Delete(active);
        }
        catch { /* ignore */ }
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
                    if (!name.Contains("DirectVpnLab", StringComparison.OrdinalIgnoreCase))
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

    private static string CaptureNetSnapshot()
    {
        try
        {
            var ifaces = NetworkInterface.GetAllNetworkInterfaces()
                .Select(n => $"{n.Name}|{n.OperationalStatus}|{n.NetworkInterfaceType}")
                .ToArray();
            return string.Join('\n', ifaces);
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
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
