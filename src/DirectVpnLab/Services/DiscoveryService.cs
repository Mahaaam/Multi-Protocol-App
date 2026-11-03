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
        _log.Info("Starting protocol discovery");
        _log.Info("Windows default route will NOT be modified during discovery");

        foreach (var m in methods)
        {
            ct.ThrowIfCancellationRequested();
            if (m.IsSkipped)
            {
                m.Status = TestStatus.Skipped;
                _log.Warn($"SKIPPED - {m.Id} {m.DisplayName}: {m.SkipReason}");
                progress?.Report(m);
                continue;
            }

            // Endpoint methods: never PASS without real data-path proof
            if (m.Id is "E04" or "F03" or "F04")
            {
                await TestEndpointAsync(m, ct);
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

            // PASS only with >=2/3 successes AND exact exit IP
            if (ok >= 2 && IsExactExpectedExit(m.ExitIp))
            {
                m.Status = TestStatus.Pass;
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
            ClassifyFailure(m, ex.Message);
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

    private async Task TestEndpointAsync(ProtocolMethod m, CancellationToken ct)
    {
        _log.Info($"Testing endpoint method {m.Id} {m.DisplayName}");
        try
        {
            var cfg = ConfigFactory.BuildTunConfig(_cred, m, AppPaths.WorkDir);
            var psi = new ProcessStartInfo
            {
                FileName = AppPaths.SingBoxExe,
                Arguments = $"check -c \"{cfg}\"",
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("check failed to start");
            var err = await p.StandardError.ReadToEndAsync(ct);
            await p.WaitForExitAsync(ct);
            if (p.ExitCode != 0)
            {
                m.Status = TestStatus.Skipped;
                m.SkipReason = $"Config invalid for client endpoint: {Trim(err)}";
                _log.Warn($"SKIPPED - {m.Id}: {m.SkipReason}");
            }
            else
            {
                // Config parses, but no real data-path proof => never PASS
                m.Status = TestStatus.Unverified;
                m.LastError = "Endpoint has no isolated data-path proof; not eligible for auto-connect";
                _log.Warn($"UNVERIFIED - {m.Id}: no PASS without real traffic proof");
            }
            try { File.Delete(cfg); } catch { /* ignore */ }
        }
        catch (Exception ex)
        {
            m.Status = TestStatus.Fail;
            m.LastError = ex.Message;
            _log.Fail($"FAIL - {m.Id}: {ex.Message}");
        }
    }

    private async Task<(bool ok, double latencyMs, string? ip, string? err)> ProbeViaProxyAsync(int mixedPort, CancellationToken ct)
    {
        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy($"http://127.0.0.1:{mixedPort}"),
            UseProxy = true
            // Standard HTTPS certificate validation remains enabled (no bypass).
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(18) };
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
        if (d.Contains("timeout")) m.LastError = "Connection Timeout";
        else if (d.Contains("auth") || d.Contains("401") || d.Contains("rejected")) m.LastError = "Authentication Failed";
        else if (d.Contains("tls") || d.Contains("certificate") || d.Contains("handshake")) m.LastError = "TLS Error";
        else if (d.Contains("dns")) m.LastError = "DNS Error";
        else if (d.Contains("udp")) m.LastError = "UDP Timeout";
        else if (string.IsNullOrWhiteSpace(m.LastError)) m.LastError = "Server Unreachable or protocol failure";
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
            m.QualityScore =
                successScore * 0.40 +
                latencyScore * 0.25 +
                jitterScore * 0.15 +
                connectScore * 0.10 +
                10.0;
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
