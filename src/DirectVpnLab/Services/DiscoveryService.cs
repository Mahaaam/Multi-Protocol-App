using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using DirectVpnLab.Models;

namespace DirectVpnLab.Services;

public sealed class DiscoveryService
{
    public const int MaxParallel = 3;

    private readonly LiveLogService _log;
    private readonly LabCredentials _cred;
    private readonly ConcurrentDictionary<string, double> _recentLatencyMs = new(StringComparer.OrdinalIgnoreCase);

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
        var swAll = Stopwatch.StartNew();
        _log.Info("Starting protocol discovery (TEST ALL) — parallel up to 3");
        _log.Info("Windows default route will NOT be modified during discovery");

        EnsureNaiveDependency(methods);

        // Fresh TEST ALL: re-evaluate skips; do not keep prior Pass mixed into new ranking
        var priorLatency = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        var runnable = new List<ProtocolMethod>();
        foreach (var m in methods)
        {
            ct.ThrowIfCancellationRequested();
            if (m.LatencyMs > 0)
            {
                priorLatency[m.Id] = m.LatencyMs;
            }

            PrepareMethodForFreshTest(m);

            if (TryMarkNonRunnable(m))
            {
                progress?.Report(m);
                continue;
            }

            runnable.Add(m);
        }

        // Schedule order may use prior latency hints only — ranking uses this run's Pass only
        runnable = runnable
            .OrderBy(m => priorLatency.TryGetValue(m.Id, out var lat) ? lat : 9_999)
            .ThenBy(m => m.Id)
            .ToList();

        using var gate = new SemaphoreSlim(MaxParallel, MaxParallel);
        var tasks = runnable.Select(async m =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                ct.ThrowIfCancellationRequested();
                await TestProxyMethodAsync(m, ct).ConfigureAwait(false);
                progress?.Report(m);
            }
            finally
            {
                gate.Release();
            }
        });

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _log.Warn("TEST ALL cancelled — cleaning temporary discovery processes");
            throw;
        }

        Rank(methods);
        var passed = methods.Where(x => x.Status == TestStatus.Pass).OrderBy(x => x.Rank).ToList();
        swAll.Stop();
        _log.Info($"Ranking complete. Successful methods: {passed.Count} in {swAll.Elapsed.TotalSeconds:F1}s");
        if (passed.Count > 0)
        {
            _log.Info($"Best candidate: {passed[0].Id} {passed[0].DisplayName}");
        }
        return methods;
    }

    /// <summary>Single live probe for Quick Connect — no full re-test of all methods.</summary>
    public async Task<(bool ok, string detail)> QuickRecheckAsync(ProtocolMethod m, CancellationToken ct)
    {
        if (TryMarkNonRunnable(m, reportLog: false))
        {
            return (false, m.LastError ?? m.SkipReason ?? "not runnable");
        }

        _log.Info($"Quick recheck {m.Id} {m.DisplayName} (1 probe)");
        var port = FreeTcpPort();
        string? cfg = null;
        await using var sb = new SingBoxProcess(_log);
        try
        {
            cfg = ConfigFactory.BuildDiscoveryConfig(_cred, m, port, AppPaths.WorkDir);
            var pre = await PreflightConfigAsync(cfg, ct).ConfigureAwait(false);
            if (!pre.ok)
            {
                ClassifyFailure(m, pre.detail);
                return (false, m.LastError ?? pre.detail);
            }

            await sb.StartAsync(cfg, ct, readyDelayMs: 220).ConfigureAwait(false);
            var timeout = AdaptiveProbeTimeout(m, quick: true);
            var (success, latency, exitIp, err) = await ProbeViaProxyAsync(port, timeout, ct).ConfigureAwait(false);
            m.ProbeAttempts = 1;
            m.ProbeSuccesses = success && IsExactExpectedExit(exitIp) ? 1 : 0;

            if (success && IsExactExpectedExit(exitIp))
            {
                m.ExitIp = exitIp;
                m.LatencyMs = latency;
                _recentLatencyMs[m.Id] = latency;
                return (true, $"recheck OK {latency:F0}ms exit={exitIp}");
            }

            return (false, err ?? (success ? $"Exit IP mismatch: {exitIp}" : "quick recheck failed"));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            ClassifyFailure(m, ex.Message + "\n" + sb.StderrSnapshot);
            return (false, m.LastError ?? ex.Message);
        }
        finally
        {
            await sb.StopAsync().ConfigureAwait(false);
            if (cfg != null)
            {
                try { File.Delete(cfg); } catch { /* ignore */ }
            }
        }
    }

    /// <summary>Reset transient skip/pass state so a new TEST ALL re-evaluates current conditions.</summary>
    public static void PrepareMethodForFreshTest(ProtocolMethod m)
    {
        m.IsHistorical = false;
        m.ProbeAttempts = 0;
        m.ProbeSuccesses = 0;
        m.Rank = 0;
        m.QualityScore = 0;

        if (IsTransientSkip(m))
        {
            m.SkipReason = null;
            m.LastError = null;
            m.FailureKind = FailureKind.None;
        }

        // Permanent unsupported keeps SkipReason; everything else starts Pending until classified
        if (m.Id is "F01" or "F02")
        {
            return;
        }

        if (m.Port <= 0 &&
            !string.IsNullOrEmpty(m.SkipReason) &&
            m.SkipReason.StartsWith("Port key missing", StringComparison.OrdinalIgnoreCase))
        {
            m.FailureKind = FailureKind.Unsupported;
            return;
        }

        m.Status = TestStatus.Pending;
        if (!IsPermanentSkipReason(m.SkipReason))
        {
            m.SkipReason = null;
        }
    }

    public static bool IsTransientSkip(ProtocolMethod m)
    {
        if (m.FailureKind == FailureKind.DependencyMissing)
        {
            return true;
        }

        var reason = m.SkipReason ?? m.LastError ?? "";
        return reason.Contains("libcronet", StringComparison.OrdinalIgnoreCase) ||
               reason.Contains("Dependency missing", StringComparison.OrdinalIgnoreCase) ||
               reason.Contains("library not found", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPermanentSkipReason(string? reason)
    {
        if (string.IsNullOrWhiteSpace(reason)) return false;
        return reason.StartsWith("Port key missing", StringComparison.OrdinalIgnoreCase) ||
               reason.Contains("Unsupported", StringComparison.OrdinalIgnoreCase) ||
               reason.Contains("MASQUE", StringComparison.OrdinalIgnoreCase);
    }

    private bool TryMarkNonRunnable(ProtocolMethod m, bool reportLog = true)
    {
        // 1) Permanent engine unsupported (MASQUE on 1.14.4)
        if (m.Id is "F01" or "F02")
        {
            m.Status = TestStatus.Skipped;
            m.FailureKind = FailureKind.Unsupported;
            m.SkipReason = "Unsupported: MASQUE requires sing-box >= 1.15.0 (engine is 1.14.4)";
            m.LastError = m.SkipReason;
            m.LastTestedAtUtc = DateTime.UtcNow;
            if (reportLog) _log.Warn($"SKIPPED - {m.Id}: {m.SkipReason}");
            return true;
        }

        // 2) Permanent structural catalog gap (missing port key)
        if (m.Port <= 0 ||
            (!string.IsNullOrEmpty(m.SkipReason) &&
             m.SkipReason.StartsWith("Port key missing", StringComparison.OrdinalIgnoreCase)))
        {
            m.Status = TestStatus.Skipped;
            m.FailureKind = FailureKind.Unsupported;
            m.SkipReason ??= "Port key missing";
            m.LastError = m.SkipReason;
            m.LastTestedAtUtc = DateTime.UtcNow;
            if (reportLog) _log.Warn($"SKIPPED - {m.Id}: {m.SkipReason}");
            return true;
        }

        // 3) Transient dependency — re-check live filesystem (prior SkipReason must not stick)
        if (m.Id is "D01" or "D02")
        {
            if (!File.Exists(AppPaths.LibCronetDll))
            {
                m.Status = TestStatus.Skipped;
                m.FailureKind = FailureKind.DependencyMissing;
                m.SkipReason = "Dependency missing: libcronet.dll (NaiveProxy)";
                m.LastError = m.SkipReason;
                m.LastTestedAtUtc = DateTime.UtcNow;
                if (reportLog) _log.Warn($"SKIPPED - {m.Id}: {m.SkipReason}");
                return true;
            }

            // Dependency restored — clear any prior dependency skip and allow test
            if (IsTransientSkip(m) ||
                (m.Status == TestStatus.Skipped &&
                 (m.SkipReason?.Contains("libcronet", StringComparison.OrdinalIgnoreCase) == true)))
            {
                m.SkipReason = null;
                m.LastError = null;
                m.FailureKind = FailureKind.None;
                m.Status = TestStatus.Pending;
                if (reportLog) _log.Info($"{m.Id}: libcronet.dll present — re-enabled for testing");
            }
        }

        // Do NOT treat leftover SkipReason from older runs as permanent Unsupported
        return false;
    }

    private void EnsureNaiveDependency(IReadOnlyList<ProtocolMethod> methods)
    {
        var need = methods.Any(m => m.Id is "D01" or "D02");
        if (!need) return;
        if (File.Exists(AppPaths.LibCronetDll))
            _log.Info("NaiveProxy dependency libcronet.dll present");
        else
            _log.Warn("NaiveProxy dependency libcronet.dll missing — D01/D02 will be skipped");
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

            var pre = await PreflightConfigAsync(cfg, ct).ConfigureAwait(false);
            if (!pre.ok)
            {
                m.Status = TestStatus.Fail;
                m.LastTestedAtUtc = DateTime.UtcNow;
                ClassifyFailure(m, pre.detail);
                // Hard config/dependency errors stay Fail; no network wait
                if (m.FailureKind is FailureKind.ConfigError or FailureKind.DependencyMissing or FailureKind.Unsupported)
                {
                    _log.Fail($"FAIL - {m.Id} (fail-fast): {m.LastError}");
                }
                else
                {
                    m.Status = TestStatus.Unverified;
                    _log.Fail($"UNVERIFIED - {m.Id}: {m.LastError}");
                }
                return;
            }

            await sb.StartAsync(cfg, ct, readyDelayMs: 250).ConfigureAwait(false);
            swConnect.Stop();
            m.ConnectTimeMs = swConnect.Elapsed.TotalMilliseconds;

            var latencies = new List<double>();
            var verifiedIps = new List<string>();
            var ok = 0;
            var attempts = 0;
            string? lastErr = null;

            for (var i = 0; i < 3; i++)
            {
                ct.ThrowIfCancellationRequested();

                // Early PASS: already 2 successes
                if (ok >= 2) break;
                // Remaining probes cannot reach 2 successes → stop (will be Unverified or Fail)
                var remaining = 3 - i;
                if (ok + remaining < 2) break;

                attempts++;
                var timeout = AdaptiveProbeTimeout(m, quick: false, sampleIndex: i, priorLatencies: latencies);
                var (success, latency, ip, err) = await ProbeViaProxyAsync(port, timeout, ct).ConfigureAwait(false);

                if (success && IsExactExpectedExit(ip))
                {
                    ok++;
                    latencies.Add(latency);
                    verifiedIps.Add(ip!);
                    _recentLatencyMs[m.Id] = latency;
                    _log.Info($"Probe {attempts}/3 OK latency={latency:F0}ms exit={ip}");
                }
                else if (success)
                {
                    lastErr = $"Exit IP Mismatch: {ip}";
                    m.LastError = lastErr;
                    _log.Warn($"Probe {attempts}/3 Exit IP Mismatch: got={ip} expected={_cred.server_ip}");
                }
                else
                {
                    lastErr = err;
                    m.LastError = err;
                    _log.Warn($"Probe {attempts}/3 failed: {err}");
                }
            }

            m.ProbeAttempts = attempts;
            m.ProbeSuccesses = ok;
            m.SuccessRate = attempts > 0 ? ok / (double)attempts : 0;
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
                _log.Pass($"PASS - {m.Id} {m.DisplayName} ({ok}/{attempts})");
            }
            else if (ok > 0)
            {
                m.Status = TestStatus.Unverified;
                m.LastError ??= $"Incomplete verification ({ok}/{attempts})";
                _log.Fail($"UNVERIFIED - {m.Id}: {m.LastError}");
            }
            else
            {
                ClassifyFailure(m, (lastErr ?? "") + "\n" + sb.StderrSnapshot);
                // Transient network/timeout → Unverified; hard errors → Fail
                if (m.FailureKind is FailureKind.Timeout or FailureKind.NetworkBlocked or FailureKind.Other)
                {
                    m.Status = TestStatus.Unverified;
                    m.LastError ??= lastErr ?? "No successful probes (temporary/network)";
                    _log.Fail($"UNVERIFIED - {m.Id}: {m.LastError}");
                }
                else
                {
                    m.Status = TestStatus.Fail;
                    _log.Fail($"FAIL - {m.Id} {m.DisplayName}: {m.LastError}");
                }
            }
        }
        catch (OperationCanceledException)
        {
            m.LastError = "Cancelled";
            throw;
        }
        catch (Exception ex)
        {
            m.LastTestedAtUtc = DateTime.UtcNow;
            ClassifyFailure(m, ex.Message + "\n" + sb.StderrSnapshot);
            if (m.FailureKind is FailureKind.ConfigError or FailureKind.DependencyMissing or FailureKind.AuthenticationError)
            {
                m.Status = TestStatus.Fail;
            }
            else
            {
                m.Status = TestStatus.Unverified;
            }
            m.LastError ??= ex.Message;
            _log.Fail($"{m.Status.ToString().ToUpperInvariant()} - {m.Id}: {m.LastError}");
        }
        finally
        {
            await sb.StopAsync().ConfigureAwait(false);
            if (cfg != null)
            {
                try { File.Delete(cfg); } catch { /* ignore */ }
            }
        }
    }

    private TimeSpan AdaptiveProbeTimeout(
        ProtocolMethod m,
        bool quick,
        int sampleIndex = 0,
        List<double>? priorLatencies = null)
    {
        var udp = m.Network.Equals("udp", StringComparison.OrdinalIgnoreCase);
        double baseSec = quick
            ? (udp ? 7.0 : 5.0)
            : (udp ? 10.0 : 7.0);

        if (_recentLatencyMs.TryGetValue(m.Id, out var known) && known > 0)
        {
            // 3× observed latency + margin, clamped
            baseSec = Math.Clamp(known / 1000.0 * 3.5 + 1.5, quick ? 3.0 : 4.0, udp ? 14.0 : 11.0);
        }
        else if (priorLatencies is { Count: > 0 })
        {
            var avg = priorLatencies.Average();
            baseSec = Math.Clamp(avg / 1000.0 * 3.0 + 1.2, 3.5, udp ? 12.0 : 10.0);
        }

        // First probe slightly more patient; later probes can be tighter if path looked fast
        if (!quick && sampleIndex == 0)
        {
            baseSec = Math.Min(baseSec + 1.5, udp ? 14.0 : 11.0);
        }
        else if (!quick && sampleIndex > 0 && priorLatencies is { Count: > 0 } && priorLatencies.Average() < 400)
        {
            baseSec = Math.Max(3.5, baseSec * 0.75);
        }

        return TimeSpan.FromSeconds(baseSec);
    }

    private async Task<(bool ok, string detail)> PreflightConfigAsync(string cfgPath, CancellationToken ct)
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
            await p.WaitForExitAsync(ct).ConfigureAwait(false);
            var err = await errTask.ConfigureAwait(false);
            _ = await outTask.ConfigureAwait(false);
            if (p.ExitCode != 0)
            {
                return (false, string.IsNullOrWhiteSpace(err) ? $"sing-box check exit={p.ExitCode}" : err.Trim());
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

    private async Task<(bool ok, double latencyMs, string? ip, string? err)> ProbeViaProxyAsync(
        int mixedPort,
        TimeSpan timeout,
        CancellationToken ct)
    {
        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy($"http://127.0.0.1:{mixedPort}"),
            UseProxy = true
        };
        using var client = new HttpClient(handler) { Timeout = timeout };
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(timeout);
        var sw = Stopwatch.StartNew();
        try
        {
            using var r1 = await client.GetAsync("https://1.1.1.1/cdn-cgi/trace", linked.Token).ConfigureAwait(false);
            if (!r1.IsSuccessStatusCode)
            {
                return (false, sw.Elapsed.TotalMilliseconds, null, $"HTTPS verification failed status={(int)r1.StatusCode}");
            }
            var body = await r1.Content.ReadAsStringAsync(linked.Token).ConfigureAwait(false);
            sw.Stop();

            string? ip = null;
            foreach (var line in body.Split('\n'))
            {
                if (line.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
                {
                    ip = line[3..].Trim();
                    break;
                }
            }

            // Prefer ipify only if trace lacked ip (saves a round-trip when present)
            if (string.IsNullOrWhiteSpace(ip))
            {
                try
                {
                    ip = (await client.GetStringAsync("https://api.ipify.org", linked.Token).ConfigureAwait(false)).Trim();
                }
                catch (Exception ex)
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
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return (false, sw.Elapsed.TotalMilliseconds, null, "Connection Timeout");
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
                 d.Contains("missing `") || d.Contains("no outbound builder") || d.Contains("sing-box check"))
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
