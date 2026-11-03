using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using DirectVpnLab.Models;

namespace DirectVpnLab.Services;

public sealed class DiscoveryService
{
    private readonly LiveLogService _log;
    private readonly LabCredentials _cred;

    public DiscoveryService(LiveLogService log, LabCredentials cred)
    {
        _log = log;
        _cred = cred;
    }

    public async Task<IReadOnlyList<ProtocolMethod>> RunAsync(
        IReadOnlyList<ProtocolMethod> methods,
        IProgress<ProtocolMethod>? progress,
        CancellationToken ct)
    {
        _log.Info("Starting protocol discovery (TEST ALL)");
        _log.Info("Windows default route will NOT be modified during discovery");

        EnsureNaiveDependency(methods);

        foreach (var m in methods)
        {
            ct.ThrowIfCancellationRequested();
            m.IsHistorical = false;

            if (m.Id is "F01" or "F02")
            {
                m.Status = TestStatus.Skipped;
                m.FailureKind = FailureKind.Unsupported;
                m.SkipReason ??= "Unsupported: MASQUE requires sing-box >= 1.15.0 (engine is 1.14.4)";
                m.LastTestedAtUtc = DateTime.UtcNow;
                _log.Warn($"SKIPPED - {m.Id} {m.DisplayName}: {m.SkipReason}");
                progress?.Report(m);
                continue;
            }

            if (m.IsSkipped)
            {
                m.Status = TestStatus.Skipped;
                m.FailureKind = FailureKind.Unsupported;
                m.LastTestedAtUtc = DateTime.UtcNow;
                _log.Warn($"SKIPPED - {m.Id} {m.DisplayName}: {m.SkipReason}");
                progress?.Report(m);
                continue;
            }

            if ((m.Id is "D01" or "D02") && !File.Exists(AppPaths.LibCronetDll))
            {
                m.Status = TestStatus.Skipped;
                m.FailureKind = FailureKind.DependencyMissing;
                m.SkipReason = "Dependency missing: libcronet.dll (NaiveProxy)";
                m.LastError = m.SkipReason;
                m.LastTestedAtUtc = DateTime.UtcNow;
                _log.Warn($"SKIPPED - {m.Id}: {m.SkipReason}");
                progress?.Report(m);
                continue;
            }

            await TestProxyMethodAsync(m, ct);
            progress?.Report(m);
        }

        Rank(methods);
        var passed = methods.Where(x => x.Status == TestStatus.Pass).OrderBy(x => x.Rank).ToList();
        _log.Info($"Ranking complete. Successful methods: {passed.Count}");
        if (passed.Count > 0)
        {
            _log.Info($"Best candidate: {passed[0].Id} {passed[0].DisplayName}");
        }
        return methods;
    }

    /// <summary>Short live recheck for CONNECT — does not re-rank all protocols.</summary>
    public async Task<(bool ok, string detail)> QuickRecheckAsync(ProtocolMethod m, CancellationToken ct)
    {
        if (m.Id is "F01" or "F02")
        {
            return (false, "Unsupported protocol");
        }

        if ((m.Id is "D01" or "D02") && !File.Exists(AppPaths.LibCronetDll))
        {
            return (false, "libcronet.dll missing");
        }

        _log.Info($"Quick recheck {m.Id} {m.DisplayName}");
        var port = FreeTcpPort();
        string? cfg = null;
        await using var sb = new SingBoxProcess(_log);
        try
        {
            cfg = ConfigFactory.BuildDiscoveryConfig(_cred, m, port, AppPaths.WorkDir);
            await sb.StartAsync(cfg, ct);

            var ok = 0;
            string? lastErr = null;
            string? ip = null;
            for (var i = 0; i < 2; i++)
            {
                ct.ThrowIfCancellationRequested();
                var (success, _, exitIp, err) = await ProbeViaProxyAsync(port, ct);
                if (success && IsExactExpectedExit(exitIp))
                {
                    ok++;
                    ip = exitIp;
                }
                else
                {
                    lastErr = err ?? (success ? $"Exit IP mismatch: {exitIp}" : "probe failed");
                }
            }

            if (ok >= 1 && IsExactExpectedExit(ip))
            {
                m.ExitIp = ip;
                return (true, $"recheck OK exit={ip}");
            }

            return (false, lastErr ?? "quick recheck failed");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
        finally
        {
            await sb.StopAsync();
            if (cfg != null)
            {
                try { File.Delete(cfg); } catch { /* ignore */ }
            }
        }
    }

    private void EnsureNaiveDependency(IReadOnlyList<ProtocolMethod> methods)
    {
        var need = methods.Any(m => m.Id is "D01" or "D02" && !m.IsSkipped);
        if (!need) return;
        if (File.Exists(AppPaths.LibCronetDll))
        {
            _log.Info("NaiveProxy dependency libcronet.dll present");
        }
        else
        {
            _log.Warn("NaiveProxy dependency libcronet.dll missing — D01/D02 will be skipped");
        }
    }

    private async Task TestProxyMethodAsync(ProtocolMethod m, CancellationToken ct)
    {
        _log.Info($"Testing {m.Id} {m.DisplayName} on port {m.Port}");
        var swConnect = Stopwatch.StartNew();
        var port = FreeTcpPort();
        string? cfg = null;
        await using var sb = new SingBoxProcess(_log);
        try
        {
            cfg = ConfigFactory.BuildDiscoveryConfig(_cred, m, port, AppPaths.WorkDir);
            await sb.StartAsync(cfg, ct);
            swConnect.Stop();
            m.ConnectTimeMs = swConnect.Elapsed.TotalMilliseconds;

            var latencies = new List<double>();
            var verifiedIps = new List<string>();
            var ok = 0;
            for (var i = 0; i < 3; i++)
            {
                ct.ThrowIfCancellationRequested();
                var (success, latency, ip, err) = await ProbeViaProxyAsync(port, ct);
                if (success && IsExactExpectedExit(ip))
                {
                    ok++;
                    latencies.Add(latency);
                    verifiedIps.Add(ip!);
                    _log.Info($"Probe {i + 1}/3 OK latency={latency:F0}ms exit={ip}");
                }
                else if (success)
                {
                    _log.Warn($"Probe {i + 1}/3 Exit IP Mismatch: got={ip} expected={_cred.server_ip}");
                    m.LastError = $"Exit IP Mismatch: {ip}";
                }
                else
                {
                    _log.Warn($"Probe {i + 1}/3 failed: {err}");
                    m.LastError = err;
                }
            }

            m.SuccessRate = ok / 3.0;
            if (latencies.Count > 0)
            {
                m.LatencyMs = latencies.Average();
                m.JitterMs = latencies.Count > 1 ? StdDev(latencies) : 0;
            }
            m.ExitIp = verifiedIps.FirstOrDefault();
            m.LastTestedAtUtc = DateTime.UtcNow;

            if (ok >= 2 && IsExactExpectedExit(m.ExitIp))
            {
                m.Status = TestStatus.Pass;
                m.FailureKind = FailureKind.None;
                _log.Pass($"PASS - {m.Id} {m.DisplayName}");
            }
            else if (ok > 0)
            {
                m.Status = TestStatus.Unverified;
                m.LastError ??= "Incomplete verification (<2/3 probes or exit IP incomplete)";
                _log.Fail($"UNVERIFIED - {m.Id}: {m.LastError}");
            }
            else
            {
                m.Status = TestStatus.Fail;
                ClassifyFailure(m, sb.StderrSnapshot);
                _log.Fail($"FAIL - {m.Id} {m.DisplayName}: {m.LastError}");
            }
        }
        catch (Exception ex)
        {
            m.Status = TestStatus.Fail;
            m.LastError = ex.Message;
            m.LastTestedAtUtc = DateTime.UtcNow;
            ClassifyFailure(m, ex.Message + "\n" + sb.StderrSnapshot);
            _log.Fail($"FAIL - {m.Id} {m.DisplayName}: {ex.Message}");
        }
        finally
        {
            await sb.StopAsync();
            if (cfg != null)
            {
                try { File.Delete(cfg); } catch { /* ignore */ }
            }
        }
    }

    private async Task<(bool ok, double latencyMs, string? ip, string? err)> ProbeViaProxyAsync(int mixedPort, CancellationToken ct)
    {
        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy($"http://127.0.0.1:{mixedPort}"),
            UseProxy = true
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(14) };
        var sw = Stopwatch.StartNew();
        try
        {
            using var r1 = await client.GetAsync("https://1.1.1.1/cdn-cgi/trace", ct);
            if (!r1.IsSuccessStatusCode)
            {
                return (false, sw.Elapsed.TotalMilliseconds, null, $"HTTPS verification failed status={(int)r1.StatusCode}");
            }
            var body = await r1.Content.ReadAsStringAsync(ct);
            sw.Stop();

            string? ip;
            try
            {
                ip = (await client.GetStringAsync("https://api.ipify.org", ct)).Trim();
            }
            catch (Exception ex)
            {
                ip = null;
                foreach (var line in body.Split('\n'))
                {
                    if (line.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
                    {
                        ip = line[3..].Trim();
                        break;
                    }
                }
                if (ip == null)
                {
                    return (false, sw.Elapsed.TotalMilliseconds, null, $"Exit IP fetch failed: {ex.Message}");
                }
            }

            if (string.IsNullOrWhiteSpace(ip))
            {
                return (false, sw.Elapsed.TotalMilliseconds, null, "Exit IP missing");
            }
            return (true, sw.Elapsed.TotalMilliseconds, ip, null);
        }
        catch (TaskCanceledException)
        {
            return (false, sw.Elapsed.TotalMilliseconds, null, "Connection Timeout");
        }
        catch (HttpRequestException ex)
        {
            return (false, sw.Elapsed.TotalMilliseconds, null, $"HTTPS/TLS error: {ex.Message}");
        }
        catch (Exception ex)
        {
            return (false, sw.Elapsed.TotalMilliseconds, null, ex.Message);
        }
    }

    private bool IsExactExpectedExit(string? ip) =>
        !string.IsNullOrWhiteSpace(ip) &&
        string.Equals(ip.Trim(), _cred.server_ip.Trim(), StringComparison.Ordinal);

    private static void ClassifyFailure(ProtocolMethod m, string detail)
    {
        var d = (detail ?? "").ToLowerInvariant();
        if (d.Contains("libcronet") || d.Contains("library not found") || d.Contains("dependency"))
        {
            m.FailureKind = FailureKind.DependencyMissing;
            m.LastError = "Dependency Missing";
        }
        else if (d.Contains("unknown outbound") || d.Contains("unknown endpoint") || d.Contains("decode config") ||
                 d.Contains("missing `") || d.Contains("no outbound builder"))
        {
            m.FailureKind = FailureKind.ConfigError;
            m.LastError = "Config Error: " + Trim(detail ?? "");
        }
        else if (d.Contains("auth") || d.Contains("401") || d.Contains("rejected") || d.Contains("authentication"))
        {
            m.FailureKind = FailureKind.AuthenticationError;
            m.LastError = "Authentication Failed";
        }
        else if (d.Contains("timeout") || d.Contains("i/o timeout") || d.Contains("deadline"))
        {
            m.FailureKind = m.Network.Equals("udp", StringComparison.OrdinalIgnoreCase)
                ? FailureKind.NetworkBlocked
                : FailureKind.Timeout;
            m.LastError = m.Network.Equals("udp", StringComparison.OrdinalIgnoreCase)
                ? "UDP Timeout / possible network block (not necessarily a software bug)"
                : "Connection Timeout";
        }
        else if (d.Contains("tls") || d.Contains("certificate") || d.Contains("handshake"))
        {
            m.FailureKind = FailureKind.Other;
            m.LastError = "TLS Error";
        }
        else if (d.Contains("dns"))
        {
            m.FailureKind = FailureKind.Other;
            m.LastError = "DNS Error";
        }
        else if (string.IsNullOrWhiteSpace(m.LastError))
        {
            m.FailureKind = FailureKind.Other;
            m.LastError = "Server Unreachable or protocol failure";
        }
        else
        {
            m.FailureKind = FailureKind.Other;
        }
    }

    public static void Rank(IReadOnlyList<ProtocolMethod> methods)
    {
        var passed = methods.Where(x => x.Status == TestStatus.Pass).ToList();
        foreach (var m in passed)
        {
            var latencyScore = Math.Max(0, 100 - m.LatencyMs / 10.0);
            var jitterScore = Math.Max(0, 100 - m.JitterMs / 5.0);
            var connectScore = Math.Max(0, 100 - m.ConnectTimeMs / 20.0);
            var successScore = m.SuccessRate * 100;
            // Freshness bonus for recently tested methods
            var freshness = 10.0;
            if (m.LastTestedAtUtc is { } t)
            {
                var ageHours = (DateTime.UtcNow - t).TotalHours;
                freshness = ageHours < 1 ? 12 : ageHours < 24 ? 10 : ageHours < 72 ? 6 : 2;
            }

            m.QualityScore =
                successScore * 0.40 +
                latencyScore * 0.22 +
                jitterScore * 0.13 +
                connectScore * 0.10 +
                freshness;
        }

        var ordered = passed
            .OrderByDescending(x => x.QualityScore)
            .ThenBy(x => x.LatencyMs)
            .ThenBy(x => x.JitterMs)
            .ToList();
        for (var i = 0; i < ordered.Count; i++)
        {
            ordered[i].Rank = i + 1;
        }

        foreach (var m in methods.Where(x => x.Status != TestStatus.Pass))
        {
            m.Rank = 0;
            m.QualityScore = 0;
        }
    }

    private static double StdDev(List<double> values)
    {
        var avg = values.Average();
        return Math.Sqrt(values.Sum(v => (v - avg) * (v - avg)) / values.Count);
    }

    private static int FreeTcpPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    private static string Trim(string s) =>
        string.IsNullOrWhiteSpace(s) ? "" : (s.Length <= 180 ? s.Trim() : s.Trim()[..180]);
}
