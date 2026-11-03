using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using DirectVpnLab.Models;

namespace DirectVpnLab.Services;

/// <summary>
/// Temporary A/B diagnostic: same fixed 256 KiB transfer via C01 proxy-only vs full TUN.
/// Does not change ranking, TEST ALL, or other protocols.
/// </summary>
public sealed class ProxyTunCompareDiagnostic
{
    public const string MethodId = "C01";
    public const int TargetBytes = 262_144; // 256 KiB exact request size
    public const string DownloadUrl = "https://speed.cloudflare.com/__down?bytes=262144";
    public const string ExitIpUrl = "https://1.1.1.1/cdn-cgi/trace";
    private static readonly TimeSpan OverallBudget = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan StallIdle = TimeSpan.FromSeconds(3);

    private readonly LiveLogService _log;
    private readonly LabCredentials _cred;
    private readonly ConnectionService _connection;

    public ProxyTunCompareDiagnostic(LiveLogService log, LabCredentials cred, ConnectionService connection)
    {
        _log = log;
        _cred = cred;
        _connection = connection;
    }

    public sealed class LegResult
    {
        public string Mode { get; init; } = "";
        public bool ServerPathOk { get; init; }
        public string? ExitIp { get; init; }
        public int? HttpStatus { get; init; }
        public bool HttpsOk { get; init; }
        public double? FirstByteMs { get; init; }
        public double? LastProgressMs { get; init; }
        public double TotalMs { get; init; }
        public long BytesReceived { get; init; }
        public double Mbps { get; init; }
        public string? Error { get; init; }
        public string Outcome { get; init; } = "FAIL";
        public string Detail { get; init; } = "";
    }

    public sealed class CompareReport
    {
        public LegResult? DirectBaseline { get; init; }
        public LegResult Proxy { get; init; } = new();
        public LegResult Tun { get; init; } = new();
        public bool CleanupOk { get; init; }
        public string CleanupDetail { get; init; } = "";
        public string Summary { get; init; } = "";
        public string Hypothesis { get; init; } = "";
    }

    public async Task<CompareReport> RunAsync(ProtocolMethod c01, CancellationToken ct)
    {
        if (!string.Equals(c01.Id, MethodId, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Diagnostic is locked to C01 only", nameof(c01));
        }

        var otherVpn = DetectOtherVpnAdapters();
        if (otherVpn.Count > 0)
        {
            var msg = "Aborted: other VPN adapter(s) active: " + string.Join(", ", otherVpn);
            _log.Fail(msg);
            return new CompareReport
            {
                Proxy = new LegResult { Mode = "PROXY", Outcome = "ABORT", Error = msg },
                Tun = new LegResult { Mode = "TUN", Outcome = "ABORT", Error = msg },
                CleanupOk = true,
                Summary = msg,
                Hypothesis = "Cannot compare while another VPN is active."
            };
        }

        var fatal = _connection.CheckFatalPrerequisites();
        if (fatal != null)
        {
            _log.Fail(fatal);
            return new CompareReport
            {
                Proxy = new LegResult { Mode = "PROXY", Outcome = "ABORT", Error = fatal },
                Tun = new LegResult { Mode = "TUN", Outcome = "ABORT", Error = fatal },
                CleanupOk = true,
                Summary = fatal,
                Hypothesis = "Administrator / wintun / sing-box prerequisite missing."
            };
        }

        // Ensure no leftover DirectVpnLab TUN before A
        await _connection.DisconnectAsync().ConfigureAwait(false);

        _log.Info("=== DIAG C01 A/B START — same URL/size for PROXY and TUN ===");
        _log.Info($"Download URL: {DownloadUrl} target={TargetBytes}B budget={OverallBudget.TotalSeconds:F0}s stallIdle={StallIdle.TotalSeconds:F0}s");

        LegResult? baseline = null;
        try
        {
            _log.Info("Baseline DIRECT (no proxy, no TUN) — informational only");
            baseline = await MeasureTransferAsync("DIRECT", proxyPort: null, ct).ConfigureAwait(false);
            LogLeg(baseline);
            if (baseline.Outcome != "PASS")
            {
                _log.Warn(
                    "Direct path cannot fetch the test object — that alone is NOT a VPN defect. Continuing A/B via NL.");
            }
        }
        catch (Exception ex)
        {
            _log.Warn($"Direct baseline error (ignored for VPN verdict): {ex.Message}");
        }

        LegResult proxy;
        try
        {
            proxy = await RunProxyOnlyAsync(c01, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            proxy = new LegResult { Mode = "PROXY", Outcome = "FAIL", Error = ex.Message, Detail = ex.Message };
            _log.Fail($"PROXY leg exception: {ex.Message}");
        }
        LogLeg(proxy);

        // Hard stop proxy resources before TUN
        await Task.Delay(400, CancellationToken.None).ConfigureAwait(false);

        LegResult tun;
        var cleanupOk = true;
        var cleanupDetail = "ok";
        try
        {
            tun = await RunTunAsync(c01, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            tun = new LegResult { Mode = "TUN", Outcome = "FAIL", Error = ex.Message, Detail = ex.Message };
            _log.Fail($"TUN leg exception: {ex.Message}");
        }
        finally
        {
            var (ok, msg) = await _connection.DisconnectAsync().ConfigureAwait(false);
            cleanupOk = ok;
            cleanupDetail = msg;
            if (!ok) _log.Fail($"Post-diag cleanup: {msg}");
            else _log.Info($"Post-diag cleanup OK: {msg}");
        }

        LogLeg(tun);

        var hypothesis = BuildHypothesis(baseline, proxy, tun);
        var summary = $"PROXY={proxy.Outcome} ({proxy.BytesReceived}B) | TUN={tun.Outcome} ({tun.BytesReceived}B) | cleanup={(cleanupOk ? "OK" : "FAIL")}";
        _log.Info("=== DIAG C01 A/B RESULT ===");
        _log.Info(summary);
        _log.Info(hypothesis);

        try
        {
            var outPath = Path.Combine(AppPaths.LogDir, "diag-c01-proxy-vs-tun.json");
            var json = JsonSerializer.Serialize(new
            {
                at = DateTime.UtcNow,
                method = MethodId,
                url = DownloadUrl,
                targetBytes = TargetBytes,
                expectedExitIp = _cred.server_ip,
                baseline,
                proxy = Sanitize(proxy),
                tun = Sanitize(tun),
                cleanupOk,
                cleanupDetail,
                summary,
                hypothesis
            }, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(outPath, json);
            _log.Info($"Wrote diagnostic report: {outPath}");
        }
        catch (Exception ex)
        {
            _log.Warn($"Could not write diag JSON: {ex.Message}");
        }

        return new CompareReport
        {
            DirectBaseline = baseline,
            Proxy = proxy,
            Tun = tun,
            CleanupOk = cleanupOk,
            CleanupDetail = cleanupDetail,
            Summary = summary,
            Hypothesis = hypothesis
        };
    }

    private static object Sanitize(LegResult r) => new
    {
        r.Mode,
        r.ServerPathOk,
        r.ExitIp,
        r.HttpStatus,
        r.HttpsOk,
        r.FirstByteMs,
        r.LastProgressMs,
        r.TotalMs,
        r.BytesReceived,
        r.Mbps,
        r.Outcome,
        r.Error,
        r.Detail
    };

    private async Task<LegResult> RunProxyOnlyAsync(ProtocolMethod c01, CancellationToken ct)
    {
        _log.Info("DIAG A — PROXY ONLY (mixed inbound, no Windows route/DNS change)");
        var port = FreeTcpPort();
        var cfg = ConfigFactory.BuildDiscoveryConfig(_cred, c01, port, AppPaths.WorkDir);
        await using var sb = new SingBoxProcess(_log);
        await sb.StartAsync(cfg, ct, readyDelayMs: 280).ConfigureAwait(false);
        try
        {
            return await MeasureTransferAsync("PROXY", proxyPort: port, ct).ConfigureAwait(false);
        }
        finally
        {
            await sb.StopAsync().ConfigureAwait(false);
            TryDelete(cfg);
        }
    }

    private async Task<LegResult> RunTunAsync(ProtocolMethod c01, CancellationToken ct)
    {
        _log.Info("DIAG B — FULL TUN (Windows route via DirectVpnLab, no app HTTP proxy)");
        // Reuse production connect path for a single method, but measure OUR fixed transfer
        // instead of the built-in health gate (so A/B share the same URL/size).
        var cfg = ConfigFactory.BuildTunConfig(_cred, c01, AppPaths.WorkDir);
        var (checkOk, checkDetail) = await ValidateConfigAsync(cfg, ct).ConfigureAwait(false);
        if (!checkOk)
        {
            return new LegResult
            {
                Mode = "TUN",
                Outcome = "FAIL",
                Error = "sing-box check failed",
                Detail = checkDetail
            };
        }

        await using var sb = new SingBoxProcess(_log);
        await sb.StartAsync(cfg, ct, readyDelayMs: 700).ConfigureAwait(false);
        try
        {
            for (var i = 0; i < 12 && !TunUp(); i++)
                await Task.Delay(250, ct).ConfigureAwait(false);

            if (!TunUp())
            {
                return new LegResult
                {
                    Mode = "TUN",
                    Outcome = "FAIL",
                    Error = "DirectVpnLab TUN interface not active",
                    Detail = "TUN_IFACE"
                };
            }

            var pathOk = EffectiveRouteUsesTun("1.1.1.1");
            if (!pathOk)
            {
                return new LegResult
                {
                    Mode = "TUN",
                    Outcome = "FAIL",
                    Error = "Windows effective route does not use DirectVpnLab",
                    Detail = "ROUTE",
                    ServerPathOk = false
                };
            }

            _log.Info("TUN up + route via DirectVpnLab — measuring same 256KiB URL (UseProxy=false)");
            return await MeasureTransferAsync("TUN", proxyPort: null, ct).ConfigureAwait(false);
        }
        finally
        {
            await sb.StopAsync().ConfigureAwait(false);
            for (var i = 0; i < 10 && TunUp(); i++)
                await Task.Delay(200).ConfigureAwait(false);
            TryDelete(cfg);
        }
    }

    private async Task<LegResult> MeasureTransferAsync(string mode, int? proxyPort, CancellationToken ct)
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None
        };
        if (proxyPort is int port)
        {
            handler.Proxy = new WebProxy($"http://127.0.0.1:{port}");
            handler.UseProxy = true;
        }
        else
        {
            handler.Proxy = null;
            handler.UseProxy = false;
        }

        using var client = new HttpClient(handler)
        {
            Timeout = OverallBudget + TimeSpan.FromSeconds(2)
        };
        client.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Encoding", "identity");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Cache-Control", "no-cache");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Pragma", "no-cache");

        string? exitIp = null;
        var serverPathOk = false;
        try
        {
            using var ipCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            ipCts.CancelAfter(TimeSpan.FromSeconds(8));
            var trace = await client.GetStringAsync(ExitIpUrl, ipCts.Token).ConfigureAwait(false);
            foreach (var line in trace.Split('\n'))
            {
                if (line.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
                {
                    exitIp = line[3..].Trim();
                    break;
                }
            }
            serverPathOk = !string.IsNullOrWhiteSpace(exitIp);
        }
        catch (Exception ex)
        {
            return new LegResult
            {
                Mode = mode,
                ServerPathOk = false,
                Outcome = "FAIL",
                Error = $"Exit/path probe failed: {ex.Message}",
                Detail = ex.Message
            };
        }

        var expected = _cred.server_ip.Trim();
        var viaNl = string.Equals(exitIp, expected, StringComparison.Ordinal);
        // DIRECT baseline is not expected to be NL; PROXY/TUN must be NL
        if ((mode is "PROXY" or "TUN") && !viaNl)
        {
            return new LegResult
            {
                Mode = mode,
                ServerPathOk = serverPathOk,
                ExitIp = exitIp,
                HttpsOk = true,
                Outcome = "FAIL",
                Error = $"Exit IP not NL server (got={exitIp} expected={expected})",
                Detail = "EXIT_IP"
            };
        }

        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(OverallBudget);
        var sw = Stopwatch.StartNew();
        double? firstByteMs = null;
        double? lastProgressMs = null;
        long got = 0;
        int? status = null;
        string? err = null;
        string outcome;

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, DownloadUrl);
            req.Headers.TryAddWithoutValidation("Accept-Encoding", "identity");
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, budget.Token)
                .ConfigureAwait(false);
            status = (int)resp.StatusCode;
            if (!resp.IsSuccessStatusCode)
            {
                return new LegResult
                {
                    Mode = mode,
                    ServerPathOk = serverPathOk,
                    ExitIp = exitIp,
                    HttpStatus = status,
                    HttpsOk = false,
                    TotalMs = sw.Elapsed.TotalMilliseconds,
                    Outcome = "FAIL",
                    Error = $"HTTP {status}",
                    Detail = $"HTTP {status}"
                };
            }

            await using var stream = await resp.Content.ReadAsStreamAsync(budget.Token).ConfigureAwait(false);
            var buffer = new byte[16_384];
            while (got < TargetBytes)
            {
                budget.Token.ThrowIfCancellationRequested();

                // Early stall stop: no progress for StallIdle after first byte
                if (firstByteMs != null && lastProgressMs != null &&
                    sw.Elapsed.TotalMilliseconds - lastProgressMs.Value > StallIdle.TotalMilliseconds)
                {
                    err = $"STALL idle>{StallIdle.TotalSeconds:F0}s after {got} bytes";
                    break;
                }

                var readTask = stream.ReadAsync(buffer.AsMemory(0, buffer.Length), budget.Token).AsTask();
                var delayTask = Task.Delay(500, budget.Token);
                var finished = await Task.WhenAny(readTask, delayTask).ConfigureAwait(false);
                if (finished != readTask)
                {
                    // idle slice — loop checks stall condition
                    continue;
                }

                var n = await readTask.ConfigureAwait(false);
                if (n <= 0) break;
                if (firstByteMs == null) firstByteMs = sw.Elapsed.TotalMilliseconds;
                got += n;
                lastProgressMs = sw.Elapsed.TotalMilliseconds;
            }

            sw.Stop();
            var mbps = got <= 0 || sw.Elapsed.TotalSeconds <= 0
                ? 0
                : got * 8.0 / sw.Elapsed.TotalSeconds / 1_000_000.0;

            if (got >= TargetBytes * 0.95 && err == null)
            {
                outcome = "PASS";
            }
            else if (err != null || (firstByteMs != null && got < TargetBytes * 0.95))
            {
                outcome = "STALL";
                err ??= $"Incomplete {got}/{TargetBytes}";
            }
            else
            {
                outcome = "FAIL";
                err ??= $"No usable payload ({got} bytes)";
            }

            return new LegResult
            {
                Mode = mode,
                ServerPathOk = serverPathOk,
                ExitIp = exitIp,
                HttpStatus = status,
                HttpsOk = true,
                FirstByteMs = firstByteMs,
                LastProgressMs = lastProgressMs,
                TotalMs = sw.Elapsed.TotalMilliseconds,
                BytesReceived = got,
                Mbps = mbps,
                Error = err,
                Outcome = outcome,
                Detail = err ?? "ok"
            };
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            sw.Stop();
            var mbps = got <= 0 || sw.Elapsed.TotalSeconds <= 0
                ? 0
                : got * 8.0 / sw.Elapsed.TotalSeconds / 1_000_000.0;
            return new LegResult
            {
                Mode = mode,
                ServerPathOk = serverPathOk,
                ExitIp = exitIp,
                HttpStatus = status,
                HttpsOk = status is >= 200 and < 300,
                FirstByteMs = firstByteMs,
                LastProgressMs = lastProgressMs,
                TotalMs = sw.Elapsed.TotalMilliseconds,
                BytesReceived = got,
                Mbps = mbps,
                Error = $"Budget/stall stop after {got} bytes",
                Outcome = got > 0 ? "STALL" : "FAIL",
                Detail = "TIMEOUT_OR_STALL"
            };
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new LegResult
            {
                Mode = mode,
                ServerPathOk = serverPathOk,
                ExitIp = exitIp,
                HttpStatus = status,
                FirstByteMs = firstByteMs,
                LastProgressMs = lastProgressMs,
                TotalMs = sw.Elapsed.TotalMilliseconds,
                BytesReceived = got,
                Error = ex.Message,
                Outcome = got > 0 ? "STALL" : "FAIL",
                Detail = ex.Message
            };
        }
    }

    private void LogLeg(LegResult r)
    {
        _log.Info(
            $"[{r.Mode}] outcome={r.Outcome} https={(r.HttpsOk ? "OK" : "NO")} status={r.HttpStatus?.ToString() ?? "-"} " +
            $"exit={r.ExitIp ?? "-"} ttfb={Fmt(r.FirstByteMs)} lastProg={Fmt(r.LastProgressMs)} " +
            $"bytes={r.BytesReceived}/{TargetBytes} mbps={r.Mbps:F3} totalMs={r.TotalMs:F0} err={r.Error ?? "-"}");
    }

    private static string Fmt(double? ms) => ms is null ? "-" : $"{ms:F0}ms";

    private static string BuildHypothesis(LegResult? baseline, LegResult proxy, LegResult tun)
    {
        var sb = new StringBuilder();
        if (baseline is { Outcome: not "PASS" })
        {
            sb.Append("Direct baseline failed (not counted as VPN defect). ");
        }

        if (proxy.Outcome == "PASS" && tun.Outcome is "STALL" or "FAIL")
        {
            sb.Append(
                "LIKELY client TUN path issue (MTU/MSS/stack/route): C01 proxy transfers OK but same object stalls/fails via TUN. ");
            sb.Append("Next fix focus: TUN MTU/MSS, stack mode, server-IP route exclude, IPv6. ");
            return sb.ToString().Trim();
        }

        if (proxy.Outcome is "STALL" or "FAIL" && tun.Outcome is "STALL" or "FAIL")
        {
            sb.Append(
                "BOTH paths fail transfer — do NOT blame TUN alone. Consider path filtering, TCP disruption, or NL/proxy behavior for bulk download. ");
            sb.Append("Need owner live logs on Irancell for byte/ttfb comparison. ");
            return sb.ToString().Trim();
        }

        if (proxy.Outcome == "PASS" && tun.Outcome == "PASS")
        {
            sb.Append(
                "Both diagnostic transfers PASS — real browsing failure may differ (SNI/HTTP2/parallel/MTU for larger pages). Not Full VPN PASS. ");
            return sb.ToString().Trim();
        }

        sb.Append($"Inconclusive (PROXY={proxy.Outcome}, TUN={tun.Outcome}). Need live Irancell run.");
        return sb.ToString().Trim();
    }

    private static async Task<(bool ok, string detail)> ValidateConfigAsync(string cfgPath, CancellationToken ct)
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
            var err = await p.StandardError.ReadToEndAsync(ct).ConfigureAwait(false);
            _ = await p.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            await p.WaitForExitAsync(ct).ConfigureAwait(false);
            return p.ExitCode == 0 ? (true, "ok") : (false, string.IsNullOrWhiteSpace(err) ? $"exit={p.ExitCode}" : err.Trim());
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    private static bool TunUp()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces().Any(n =>
                n.OperationalStatus == OperationalStatus.Up &&
                (n.Name.Contains(ConnectionService.TunInterfaceName, StringComparison.OrdinalIgnoreCase) ||
                 n.Description.Contains(ConnectionService.TunInterfaceName, StringComparison.OrdinalIgnoreCase)));
        }
        catch
        {
            return false;
        }
    }

    private static bool EffectiveRouteUsesTun(string destIp)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell",
                Arguments =
                    $"-NoProfile -Command \"(Find-NetRoute -RemoteIPAddress {destIp} | Select-Object -First 1).InterfaceAlias\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return false;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(4000);
            return output.Contains(ConnectionService.TunInterfaceName, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static List<string> DetectOtherVpnAdapters()
    {
        var hits = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                var name = ni.Name + " " + ni.Description;
                if (name.Contains(ConnectionService.TunInterfaceName, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (name.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("TAP-Windows", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Outline", StringComparison.OrdinalIgnoreCase) ||
                    (name.Contains("Wintun", StringComparison.OrdinalIgnoreCase) &&
                     !name.Contains(ConnectionService.TunInterfaceName, StringComparison.OrdinalIgnoreCase)))
                {
                    hits.Add(ni.Name);
                }
            }
        }
        catch
        {
            // ignore
        }
        return hits;
    }

    private static int FreeTcpPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    private static void TryDelete(string? path)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path)) File.Delete(path);
        }
        catch
        {
            // ignore
        }
    }
}
