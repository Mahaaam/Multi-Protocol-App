using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text.Json;
using DirectVpnLab.Models;

namespace DirectVpnLab.Services;

/// <summary>
/// Temporary A/B diagnostic: same fixed 256 KiB transfer via C01 proxy-only vs full TUN.
/// Exit-IP probe and download are independent; errors are classified from real exceptions.
/// </summary>
public sealed class ProxyTunCompareDiagnostic
{
    public const string MethodId = "C01";
    public const int TargetBytes = 262_144;
    public const string DownloadUrl = "https://speed.cloudflare.com/__down?bytes=262144";
    public const string ExitIpUrl = "https://1.1.1.1/cdn-cgi/trace";
    public const int C01ServerPort = 40121;

    private static readonly TimeSpan OverallBudget = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan StallIdle = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan ExitIpBudget = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan TcpProbeBudget = TimeSpan.FromSeconds(5);

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
        public string? ExitIp { get; init; }
        public string ExitIpStatus { get; init; } = "NOT_RUN"; // OK | MISMATCH | FAILED | NOT_RUN
        public string? ExitIpCategory { get; init; }
        public string? ExitIpError { get; init; }

        public string DownloadStatus { get; init; } = "NOT_RUN"; // PASS | STALL | FAIL | TIMEOUT | NOT_RUN | CANCELLED
        public string? DownloadCategory { get; init; }
        public string? DownloadError { get; init; }
        public int? HttpStatus { get; init; }
        public double? FirstByteMs { get; init; }
        public double? LastProgressMs { get; init; }
        public double TotalMs { get; init; }
        public long BytesReceived { get; init; }
        public double Mbps { get; init; }

        public string TcpConnectStatus { get; init; } = "NOT_MEASURED"; // OK | TIMEOUT | REFUSED | RESET | FAIL | NOT_MEASURED
        public string? TcpConnectDetail { get; init; }
        public string TlsStatus { get; init; } = "UNKNOWN"; // OK | FAILED | UNKNOWN | NOT_REACHED
        public string? EngineHint { get; init; }

        /// <summary>Overall VPN-path verdict for PROXY/TUN: PASS only if download PASS and exit IP OK.</summary>
        public string Outcome { get; init; } = "FAIL";
        public string ErrorCategory { get; init; } = "UNKNOWN";
        public string? ErrorDetail { get; init; }
    }

    public sealed class CompareReport
    {
        public string RunId { get; init; } = "";
        public DateTime StartedAtUtc { get; init; }
        public DateTime FinishedAtUtc { get; init; }
        public string NetworkFingerprint { get; init; } = "";
        public string ServerIp { get; init; } = "";
        public int ServerPort { get; init; }
        public LegResult? DirectBaseline { get; init; }
        public LegResult Proxy { get; init; } = new();
        public LegResult Tun { get; init; } = new();
        public bool CleanupOk { get; init; }
        public string CleanupDetail { get; init; } = "";
        public string Summary { get; init; } = "";
        public string Hypothesis { get; init; } = "";
        public string Confidence { get; init; } = "low";
        public string? NextStep { get; init; }
    }

    public async Task<CompareReport> RunAsync(ProtocolMethod c01, CancellationToken ct)
    {
        if (!string.Equals(c01.Id, MethodId, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Diagnostic is locked to C01 only", nameof(c01));

        var runId = $"diag-{DateTime.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid().ToString("N")[..8]}";
        var started = DateTime.UtcNow;
        var serverPort = c01.Port > 0 ? c01.Port : C01ServerPort;
        var netFp = PersistenceService.CaptureNetworkFingerprint();
        var logMarkStart = $"=== DIAG C01 RUN {runId} START ===";

        var otherVpn = DetectOtherVpnAdapters();
        if (otherVpn.Count > 0)
        {
            var msg = "Aborted: other VPN adapter(s) active: " + string.Join(", ", otherVpn);
            _log.Fail(msg);
            return AbortReport(runId, started, netFp, serverPort, msg, "Cannot compare while another VPN is active.", "high");
        }

        var fatal = _connection.CheckFatalPrerequisites();
        if (fatal != null)
        {
            _log.Fail(fatal);
            return AbortReport(runId, started, netFp, serverPort, fatal,
                "Administrator / wintun / sing-box prerequisite missing.", "high");
        }

        await _connection.DisconnectAsync().ConfigureAwait(false);

        _log.Info(logMarkStart);
        _log.Info(
            $"URL={DownloadUrl} target={TargetBytes}B budget={OverallBudget.TotalSeconds:F0}s stallIdle={StallIdle.TotalSeconds:F0}s server={_cred.server_ip}:{serverPort}");
        _log.Info("Note: TUN path may carry unrelated system background traffic; download bytes below are only the diagnostic HTTP body.");

        // Direct TCP to NL:40121 (no proxy) — shared path evidence
        var (tcpDirectStatus, tcpDirectDetail) = await ProbeTcpAsync(_cred.server_ip, serverPort, TcpProbeBudget, ct)
            .ConfigureAwait(false);
        _log.Info($"[TCP direct→{_cred.server_ip}:{serverPort}] status={tcpDirectStatus} detail={tcpDirectDetail}");

        LegResult? baseline = null;
        try
        {
            _log.Info("Baseline DIRECT (informational — failure is NOT a VPN defect)");
            baseline = await MeasureTransferAsync("DIRECT", proxyPort: null, engineStderr: null, ct)
                .ConfigureAwait(false);
            // Overlay raw TCP probe for DIRECT context
            baseline = CloneWithTcp(baseline, tcpDirectStatus, tcpDirectDetail);
            LogLeg(baseline);
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
            var cat = ClassifyException(ex);
            proxy = new LegResult
            {
                Mode = "PROXY",
                Outcome = "FAIL",
                DownloadStatus = "NOT_RUN",
                ExitIpStatus = "NOT_RUN",
                ErrorCategory = cat,
                ErrorDetail = ex.Message,
                DownloadCategory = cat,
                DownloadError = ex.Message
            };
            _log.Fail($"PROXY leg exception [{cat}]: {ex.Message}");
        }
        LogLeg(proxy);

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
            var cat = ClassifyException(ex);
            tun = new LegResult
            {
                Mode = "TUN",
                Outcome = "FAIL",
                DownloadStatus = "NOT_RUN",
                ExitIpStatus = "NOT_RUN",
                ErrorCategory = cat,
                ErrorDetail = ex.Message,
                DownloadCategory = cat,
                DownloadError = ex.Message
            };
            _log.Fail($"TUN leg exception [{cat}]: {ex.Message}");
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

        var finished = DateTime.UtcNow;
        var (hypothesis, confidence, nextStep) = BuildHypothesis(baseline, proxy, tun, tcpDirectStatus);
        var summary =
            $"PROXY={proxy.Outcome} dl={proxy.DownloadStatus}/{proxy.BytesReceived}B exit={proxy.ExitIpStatus} | " +
            $"TUN={tun.Outcome} dl={tun.DownloadStatus}/{tun.BytesReceived}B exit={tun.ExitIpStatus} | " +
            $"tcpDirect={tcpDirectStatus} cleanup={(cleanupOk ? "OK" : "FAIL")}";

        _log.Info($"=== DIAG C01 RUN {runId} RESULT ===");
        _log.Info(summary);
        _log.Info($"hypothesis[{confidence}]: {hypothesis}");
        if (!string.IsNullOrWhiteSpace(nextStep))
            _log.Info($"nextStep: {nextStep}");

        try
        {
            var outPath = Path.Combine(AppPaths.LogDir, $"diag-c01-{runId}.json");
            var latestPath = Path.Combine(AppPaths.LogDir, "diag-c01-proxy-vs-tun.json");
            var payload = new
            {
                runId,
                startedAtUtc = started,
                finishedAtUtc = finished,
                networkFingerprint = netFp,
                serverIp = _cred.server_ip,
                serverPort,
                method = MethodId,
                url = DownloadUrl,
                targetBytes = TargetBytes,
                tcpConnectDirect = new { status = tcpDirectStatus, detail = tcpDirectDetail },
                directBaseline = Sanitize(baseline),
                proxyResult = Sanitize(proxy),
                tunResult = Sanitize(tun),
                cleanupOk,
                cleanupDetail,
                summary,
                hypothesis,
                confidence,
                nextStep,
                note =
                    "TUN may carry unrelated OS background traffic; bytesReceived is diagnostic HTTP body only."
            };
            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(outPath, json);
            File.WriteAllText(latestPath, json);
            _log.Info($"Wrote diagnostic report: {outPath}");
        }
        catch (Exception ex)
        {
            _log.Warn($"Could not write diag JSON: {ex.Message}");
        }

        return new CompareReport
        {
            RunId = runId,
            StartedAtUtc = started,
            FinishedAtUtc = finished,
            NetworkFingerprint = netFp,
            ServerIp = _cred.server_ip,
            ServerPort = serverPort,
            DirectBaseline = baseline,
            Proxy = proxy,
            Tun = tun,
            CleanupOk = cleanupOk,
            CleanupDetail = cleanupDetail,
            Summary = summary,
            Hypothesis = hypothesis,
            Confidence = confidence,
            NextStep = nextStep
        };
    }

    private CompareReport AbortReport(
        string runId, DateTime started, string netFp, int serverPort, string msg, string hypothesis, string confidence) =>
        new()
        {
            RunId = runId,
            StartedAtUtc = started,
            FinishedAtUtc = DateTime.UtcNow,
            NetworkFingerprint = netFp,
            ServerIp = _cred.server_ip,
            ServerPort = serverPort,
            Proxy = new LegResult { Mode = "PROXY", Outcome = "ABORT", ErrorCategory = "UNKNOWN", ErrorDetail = msg, DownloadStatus = "NOT_RUN", ExitIpStatus = "NOT_RUN" },
            Tun = new LegResult { Mode = "TUN", Outcome = "ABORT", ErrorCategory = "UNKNOWN", ErrorDetail = msg, DownloadStatus = "NOT_RUN", ExitIpStatus = "NOT_RUN" },
            CleanupOk = true,
            Summary = msg,
            Hypothesis = hypothesis,
            Confidence = confidence
        };

    private static object? Sanitize(LegResult? r)
    {
        if (r == null) return null;
        return new
        {
            r.Mode,
            r.ExitIp,
            r.ExitIpStatus,
            r.ExitIpCategory,
            r.ExitIpError,
            r.DownloadStatus,
            r.DownloadCategory,
            r.DownloadError,
            tlsStatus = r.TlsStatus,
            tcpConnectStatus = r.TcpConnectStatus,
            tcpConnectDetail = r.TcpConnectDetail,
            httpStatus = r.HttpStatus,
            r.FirstByteMs,
            r.LastProgressMs,
            r.TotalMs,
            r.BytesReceived,
            r.Mbps,
            r.Outcome,
            errorCategory = r.ErrorCategory,
            errorDetail = r.ErrorDetail,
            r.EngineHint
        };
    }

    private async Task<LegResult> RunProxyOnlyAsync(ProtocolMethod c01, CancellationToken ct)
    {
        _log.Info("DIAG A — PROXY ONLY (mixed inbound, no Windows route/DNS change)");
        var port = FreeTcpPort();
        var cfg = ConfigFactory.BuildDiscoveryConfig(_cred, c01, port, AppPaths.WorkDir);
        await using var sb = new SingBoxProcess(_log);
        await sb.StartAsync(cfg, ct, readyDelayMs: 280).ConfigureAwait(false);
        try
        {
            return await MeasureTransferAsync("PROXY", proxyPort: port, engineStderr: () => sb.StderrSnapshot, ct)
                .ConfigureAwait(false);
        }
        finally
        {
            await sb.StopAsync().ConfigureAwait(false);
            TryDelete(cfg);
        }
    }

    private async Task<LegResult> RunTunAsync(ProtocolMethod c01, CancellationToken ct)
    {
        _log.Info("DIAG B — FULL TUN (Windows route via DirectVpnLab, UseProxy=false)");
        var cfg = ConfigFactory.BuildTunConfig(_cred, c01, AppPaths.WorkDir);
        var (checkOk, checkDetail) = await ValidateConfigAsync(cfg, ct).ConfigureAwait(false);
        if (!checkOk)
        {
            return new LegResult
            {
                Mode = "TUN",
                Outcome = "FAIL",
                DownloadStatus = "NOT_RUN",
                ExitIpStatus = "NOT_RUN",
                ErrorCategory = "UNKNOWN",
                ErrorDetail = "sing-box check failed: " + Trim(checkDetail),
                DownloadError = "NOT_RUN — config invalid"
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
                    DownloadStatus = "NOT_RUN",
                    ExitIpStatus = "NOT_RUN",
                    ErrorCategory = "TUN_ROUTE_FAILED",
                    ErrorDetail = "DirectVpnLab TUN interface not active",
                    TcpConnectStatus = "NOT_MEASURED",
                    TlsStatus = "NOT_REACHED"
                };
            }

            if (!EffectiveRouteUsesTun("1.1.1.1"))
            {
                return new LegResult
                {
                    Mode = "TUN",
                    Outcome = "FAIL",
                    DownloadStatus = "NOT_RUN",
                    ExitIpStatus = "NOT_RUN",
                    ErrorCategory = "TUN_ROUTE_FAILED",
                    ErrorDetail = "Windows effective route does not use DirectVpnLab",
                    TcpConnectStatus = "NOT_MEASURED",
                    TlsStatus = "NOT_REACHED"
                };
            }

            _log.Info("TUN up + route via DirectVpnLab — exit-IP probe then same 256KiB download");
            return await MeasureTransferAsync("TUN", proxyPort: null, engineStderr: () => sb.StderrSnapshot, ct)
                .ConfigureAwait(false);
        }
        finally
        {
            await sb.StopAsync().ConfigureAwait(false);
            for (var i = 0; i < 10 && TunUp(); i++)
                await Task.Delay(200).ConfigureAwait(false);
            TryDelete(cfg);
        }
    }

    private async Task<LegResult> MeasureTransferAsync(
        string mode,
        int? proxyPort,
        Func<string>? engineStderr,
        CancellationToken ct)
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None
        };
        if (proxyPort is int p)
        {
            handler.Proxy = new WebProxy($"http://127.0.0.1:{p}");
            handler.UseProxy = true;
        }
        else
        {
            handler.Proxy = null;
            handler.UseProxy = false;
        }

        using var client = new HttpClient(handler)
        {
            Timeout = OverallBudget + TimeSpan.FromSeconds(5)
        };
        client.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Encoding", "identity");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Cache-Control", "no-cache");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Pragma", "no-cache");

        // --- Exit IP probe (independent; failure does NOT skip download) ---
        string? exitIp = null;
        var exitStatus = "FAILED";
        string? exitCat = null;
        string? exitErr = null;
        string tlsFromExit = "UNKNOWN";
        try
        {
            using var ipCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            ipCts.CancelAfter(ExitIpBudget);
            var trace = await client.GetStringAsync(ExitIpUrl, ipCts.Token).ConfigureAwait(false);
            foreach (var line in trace.Split('\n'))
            {
                if (line.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
                {
                    exitIp = line[3..].Trim();
                    break;
                }
            }

            tlsFromExit = "OK";
            if (string.IsNullOrWhiteSpace(exitIp))
            {
                exitStatus = "FAILED";
                exitCat = "HTTP_FAILED";
                exitErr = "trace returned no ip=";
            }
            else if (mode is "PROXY" or "TUN")
            {
                if (string.Equals(exitIp, _cred.server_ip.Trim(), StringComparison.Ordinal))
                {
                    exitStatus = "OK";
                }
                else
                {
                    exitStatus = "MISMATCH";
                    exitCat = "EXIT_IP_MISMATCH";
                    exitErr = $"got={exitIp} expected={_cred.server_ip}";
                }
            }
            else
            {
                exitStatus = "OK"; // DIRECT: any exit is fine for baseline
            }
        }
        catch (Exception ex)
        {
            exitCat = ClassifyException(ex);
            exitErr = Flatten(ex);
            exitStatus = "FAILED";
            tlsFromExit = exitCat is "TLS_HANDSHAKE_FAILED" ? "FAILED"
                : exitCat is "TCP_CONNECT_TIMEOUT" or "TCP_CONNECTION_REFUSED" or "TCP_RESET" or "DNS_FAILED"
                    ? "NOT_REACHED"
                    : "UNKNOWN";
            _log.Warn($"[{mode}] Exit-IP probe failed [{exitCat}] — continuing to download test. {exitErr}");
        }

        _log.Info($"[{mode}] exitIpStatus={exitStatus} exit={exitIp ?? "-"} cat={exitCat ?? "-"}");

        // --- Download (always attempted unless cancelled) ---
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(OverallBudget);
        var sw = Stopwatch.StartNew();
        double? firstByteMs = null;
        double? lastProgressMs = null;
        long got = 0;
        int? httpStatus = null;
        string downloadStatus = "NOT_RUN";
        string? downloadCat = null;
        string? downloadErr = null;
        string tlsStatus = tlsFromExit;
        string? engineHint = null;

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, DownloadUrl);
            req.Headers.TryAddWithoutValidation("Accept-Encoding", "identity");
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, budget.Token)
                .ConfigureAwait(false);
            httpStatus = (int)resp.StatusCode;
            tlsStatus = "OK";

            if (!resp.IsSuccessStatusCode)
            {
                downloadStatus = "FAIL";
                downloadCat = "HTTP_FAILED";
                downloadErr = $"HTTP {httpStatus}";
            }
            else
            {
                await using var stream = await resp.Content.ReadAsStreamAsync(budget.Token).ConfigureAwait(false);
                var buffer = new byte[16_384];

                while (got < TargetBytes)
                {
                    if (ct.IsCancellationRequested)
                    {
                        downloadStatus = "CANCELLED";
                        downloadCat = "CANCELLED";
                        downloadErr = "cancelled by user";
                        break;
                    }

                    // One active read only — cancel that read on stall/budget
                    using var readCts = CancellationTokenSource.CreateLinkedTokenSource(budget.Token);
                    // Cap each read wait so we can detect stall promptly after first byte
                    var slice = firstByteMs == null
                        ? TimeSpan.FromSeconds(8)
                        : StallIdle;
                    readCts.CancelAfter(slice);

                    int n;
                    try
                    {
                        n = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), readCts.Token)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                    {
                        if (firstByteMs != null &&
                            lastProgressMs != null &&
                            sw.Elapsed.TotalMilliseconds - lastProgressMs.Value >= StallIdle.TotalMilliseconds)
                        {
                            downloadStatus = "STALL";
                            downloadCat = "DOWNLOAD_STALL";
                            downloadErr =
                                $"No new bytes for >{StallIdle.TotalSeconds:F0}s after {got}B (lastProgress={lastProgressMs:F0}ms)";
                        }
                        else if (budget.IsCancellationRequested)
                        {
                            downloadStatus = got > 0 ? "TIMEOUT" : "FAIL";
                            downloadCat = got > 0 ? "DOWNLOAD_TIMEOUT" : "DOWNLOAD_TIMEOUT";
                            downloadErr = $"Overall budget after {got}B";
                        }
                        else
                        {
                            // Pre-first-byte slice expired — treat as timeout connecting/reading headers body
                            downloadStatus = "TIMEOUT";
                            downloadCat = "DOWNLOAD_TIMEOUT";
                            downloadErr = $"No first byte within {slice.TotalSeconds:F0}s";
                        }
                        break;
                    }

                    if (n <= 0)
                    {
                        if (got < TargetBytes * 0.95)
                        {
                            downloadStatus = "FAIL";
                            downloadCat = "HTTP_FAILED";
                            downloadErr = $"EOF early at {got}/{TargetBytes}";
                        }
                        break;
                    }

                    if (firstByteMs == null) firstByteMs = sw.Elapsed.TotalMilliseconds;
                    got += n;
                    lastProgressMs = sw.Elapsed.TotalMilliseconds;
                }

                if (downloadStatus == "NOT_RUN")
                {
                    if (got >= (long)(TargetBytes * 0.95))
                    {
                        downloadStatus = "PASS";
                        downloadCat = null;
                        downloadErr = null;
                    }
                    else
                    {
                        downloadStatus = "STALL";
                        downloadCat = "DOWNLOAD_STALL";
                        downloadErr = $"Incomplete {got}/{TargetBytes}";
                    }
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            downloadStatus = "CANCELLED";
            downloadCat = "CANCELLED";
            downloadErr = "cancelled by user";
        }
        catch (OperationCanceledException)
        {
            downloadStatus = got > 0 ? "TIMEOUT" : "FAIL";
            downloadCat = "DOWNLOAD_TIMEOUT";
            downloadErr = $"Budget cancelled after {got}B";
        }
        catch (Exception ex)
        {
            downloadCat = ClassifyException(ex);
            downloadErr = Flatten(ex);
            downloadStatus = got > 0 ? "STALL" : "FAIL";
            if (downloadCat == "TLS_HANDSHAKE_FAILED") tlsStatus = "FAILED";
            else if (downloadCat is "TCP_CONNECT_TIMEOUT" or "TCP_CONNECTION_REFUSED" or "TCP_RESET" or "DNS_FAILED")
                tlsStatus = "NOT_REACHED";
        }

        sw.Stop();

        if (engineStderr != null)
        {
            engineHint = ExtractEngineHint(engineStderr(), _cred.server_ip, c01Port: C01ServerPort);
            if (engineHint != null)
                _log.Info($"[{mode}] sing-box hint (this run window): {engineHint}");
        }

        var mbps = got <= 0 || sw.Elapsed.TotalSeconds <= 0
            ? 0
            : got * 8.0 / sw.Elapsed.TotalSeconds / 1_000_000.0;

        // Overall outcome: PROXY/TUN require download PASS + exit OK. DIRECT only needs download PASS.
        string outcome;
        string errorCategory;
        string? errorDetail;
        if (mode == "DIRECT")
        {
            outcome = downloadStatus == "PASS" ? "PASS" : "FAIL";
            errorCategory = downloadCat ?? (downloadStatus == "PASS" ? "OK" : "UNKNOWN");
            errorDetail = downloadErr;
        }
        else if (downloadStatus == "NOT_RUN")
        {
            outcome = "FAIL";
            errorCategory = downloadCat ?? exitCat ?? "UNKNOWN";
            errorDetail = downloadErr ?? "download NOT_RUN";
        }
        else if (downloadStatus == "PASS" && exitStatus == "OK")
        {
            outcome = "PASS";
            errorCategory = "OK";
            errorDetail = null;
        }
        else if (downloadStatus == "PASS" && exitStatus != "OK")
        {
            outcome = "FAIL";
            errorCategory = exitCat ?? "EXIT_IP_MISMATCH";
            errorDetail = $"Download OK but exit IP not verified ({exitStatus}): {exitErr}";
        }
        else
        {
            outcome = "FAIL";
            errorCategory = downloadCat ?? exitCat ?? "UNKNOWN";
            errorDetail = downloadErr ?? exitErr;
        }

        _log.Info(
            $"[{mode}] stages: tcp={"(see probe/engine)"} tls={tlsStatus} http={httpStatus?.ToString() ?? "NONE"} " +
            $"downloadStarted={(firstByteMs != null)} lastByteMs={Fmt(lastProgressMs)} bytes={got}");

        return new LegResult
        {
            Mode = mode,
            ExitIp = exitIp,
            ExitIpStatus = exitStatus,
            ExitIpCategory = exitCat,
            ExitIpError = exitErr,
            DownloadStatus = downloadStatus,
            DownloadCategory = downloadCat,
            DownloadError = downloadErr,
            HttpStatus = httpStatus,
            FirstByteMs = firstByteMs,
            LastProgressMs = lastProgressMs,
            TotalMs = sw.Elapsed.TotalMilliseconds,
            BytesReceived = got,
            Mbps = mbps,
            TcpConnectStatus = "NOT_MEASURED",
            TlsStatus = tlsStatus,
            EngineHint = engineHint,
            Outcome = outcome,
            ErrorCategory = errorCategory,
            ErrorDetail = errorDetail
        };
    }

    private static LegResult CloneWithTcp(LegResult r, string tcpStatus, string tcpDetail) => new()
    {
        Mode = r.Mode,
        ExitIp = r.ExitIp,
        ExitIpStatus = r.ExitIpStatus,
        ExitIpCategory = r.ExitIpCategory,
        ExitIpError = r.ExitIpError,
        DownloadStatus = r.DownloadStatus,
        DownloadCategory = r.DownloadCategory,
        DownloadError = r.DownloadError,
        HttpStatus = r.HttpStatus,
        FirstByteMs = r.FirstByteMs,
        LastProgressMs = r.LastProgressMs,
        TotalMs = r.TotalMs,
        BytesReceived = r.BytesReceived,
        Mbps = r.Mbps,
        TcpConnectStatus = tcpStatus,
        TcpConnectDetail = tcpDetail,
        TlsStatus = r.TlsStatus,
        EngineHint = r.EngineHint,
        Outcome = r.Outcome,
        ErrorCategory = r.ErrorCategory,
        ErrorDetail = r.ErrorDetail
    };

    public static string ClassifyException(Exception ex)
    {
        for (Exception? e = ex; e != null; e = e.InnerException)
        {
            switch (e)
            {
                case SocketException se:
                    return se.SocketErrorCode switch
                    {
                        SocketError.TimedOut => "TCP_CONNECT_TIMEOUT",
                        SocketError.ConnectionRefused => "TCP_CONNECTION_REFUSED",
                        SocketError.ConnectionReset => "TCP_RESET",
                        SocketError.HostNotFound => "DNS_FAILED",
                        SocketError.NoData => "DNS_FAILED",
                        SocketError.TryAgain => "DNS_FAILED",
                        _ => "UNKNOWN"
                    };
                case AuthenticationException:
                    return "TLS_HANDSHAKE_FAILED";
                case HttpRequestException hre:
                {
                    // Prefer socket/DNS evidence in InnerException over surface "SSL could not be established"
                    if (hre.InnerException is SocketException se2)
                    {
                        return se2.SocketErrorCode switch
                        {
                            SocketError.TimedOut => "TCP_CONNECT_TIMEOUT",
                            SocketError.ConnectionRefused => "TCP_CONNECTION_REFUSED",
                            SocketError.ConnectionReset => "TCP_RESET",
                            SocketError.HostNotFound => "DNS_FAILED",
                            SocketError.NoData => "DNS_FAILED",
                            _ => "UNKNOWN"
                        };
                    }

                    var msg = (hre.Message + " " + (hre.InnerException?.Message ?? "")).ToLowerInvariant();
                    if (msg.Contains("timed out") || msg.Contains("timeout"))
                        return "TCP_CONNECT_TIMEOUT";
                    if (msg.Contains("refused"))
                        return "TCP_CONNECTION_REFUSED";
                    if (msg.Contains("reset"))
                        return "TCP_RESET";
                    if (msg.Contains("name or service") || msg.Contains("nodename") || msg.Contains("dns"))
                        return "DNS_FAILED";
                    if (msg.Contains("ssl") || msg.Contains("tls") || msg.Contains("certificate") ||
                        msg.Contains("authentication"))
                        return "TLS_HANDSHAKE_FAILED";
                    return "UNKNOWN";
                }
                case IOException io when io.InnerException is SocketException se3:
                    return se3.SocketErrorCode switch
                    {
                        SocketError.TimedOut => "TCP_CONNECT_TIMEOUT",
                        SocketError.ConnectionRefused => "TCP_CONNECTION_REFUSED",
                        SocketError.ConnectionReset => "TCP_RESET",
                        _ => "UNKNOWN"
                    };
            }
        }

        var flat = Flatten(ex).ToLowerInvariant();
        if (flat.Contains("operation was canceled") || flat.Contains("cancelled"))
            return "CANCELLED";
        return "UNKNOWN";
    }

    public static string? ExtractEngineHint(string stderr, string serverIp, int c01Port)
    {
        if (string.IsNullOrWhiteSpace(stderr)) return null;
        var needle = $"{serverIp}:{c01Port}";
        string? last = null;
        foreach (var line in stderr.Split('\n'))
        {
            if (!line.Contains(needle, StringComparison.OrdinalIgnoreCase) &&
                !line.Contains(serverIp, StringComparison.OrdinalIgnoreCase))
                continue;
            var l = line.Trim();
            if (l.Contains("i/o timeout", StringComparison.OrdinalIgnoreCase) ||
                l.Contains("connection refused", StringComparison.OrdinalIgnoreCase) ||
                l.Contains("reset by peer", StringComparison.OrdinalIgnoreCase) ||
                l.Contains("EOF", StringComparison.Ordinal) ||
                l.Contains("timeout", StringComparison.OrdinalIgnoreCase))
            {
                last = l.Length <= 220 ? l : l[..220];
            }
        }
        return last;
    }

    private static async Task<(string status, string detail)> ProbeTcpAsync(
        string host, int port, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            using var client = new TcpClient();
            var sw = Stopwatch.StartNew();
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            sw.Stop();
            return ("OK", $"connected in {sw.Elapsed.TotalMilliseconds:F0}ms");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return ("TIMEOUT", $"connect exceeded {timeout.TotalSeconds:F0}s");
        }
        catch (SocketException se)
        {
            var status = se.SocketErrorCode switch
            {
                SocketError.TimedOut => "TIMEOUT",
                SocketError.ConnectionRefused => "REFUSED",
                SocketError.ConnectionReset => "RESET",
                _ => "FAIL"
            };
            return (status, $"{se.SocketErrorCode}: {se.Message}");
        }
        catch (Exception ex)
        {
            return ("FAIL", Flatten(ex));
        }
    }

    private void LogLeg(LegResult r)
    {
        _log.Info(
            $"[{r.Mode}] outcome={r.Outcome} exit={r.ExitIpStatus}/{r.ExitIp ?? "-"} dl={r.DownloadStatus} " +
            $"http={r.HttpStatus?.ToString() ?? "-"} tls={r.TlsStatus} tcp={r.TcpConnectStatus} " +
            $"ttfb={Fmt(r.FirstByteMs)} lastProg={Fmt(r.LastProgressMs)} bytes={r.BytesReceived}/{TargetBytes} " +
            $"mbps={r.Mbps:F3} totalMs={r.TotalMs:F0} cat={r.ErrorCategory} err={r.ErrorDetail ?? "-"}");
    }

    private static string Fmt(double? ms) => ms is null ? "-" : $"{ms:F0}ms";

    private static (string hypothesis, string confidence, string? nextStep) BuildHypothesis(
        LegResult? baseline, LegResult proxy, LegResult tun, string tcpDirectStatus)
    {
        var proxyDl = proxy.DownloadStatus;
        var tunDl = tun.DownloadStatus;

        if ((tcpDirectStatus is "TIMEOUT" or "REFUSED" or "FAIL") &&
            proxyDl is not "PASS" && tunDl is not "PASS")
        {
            return (
                $"Direct TCP to NL:{C01ServerPort}={tcpDirectStatus}; PROXY and TUN downloads did not PASS. " +
                "Shared reachability to the server port is impaired — do NOT blame TUN alone. " +
                "This does not by itself prove DPI; could be path, ISP, or server listener.",
                "medium",
                "Owner: confirm on Irancell with DIAG C01. If TCP still TIMEOUT, read-only check that 40121 is listening on NL (no Production changes).");
        }

        if (proxyDl == "PASS" && tunDl is "STALL" or "FAIL" or "TIMEOUT")
        {
            return (
                "PROXY download PASS but TUN download not PASS — likely TUN-path (MTU/MSS/stack/route) rather than SS credentials.",
                "medium",
                "Next: compare MTU/stack only after confirming PROXY still PASSes on same network.");
        }

        if ((proxyDl is "STALL" or "FAIL" or "TIMEOUT") &&
            (tunDl is "STALL" or "FAIL" or "TIMEOUT"))
        {
            var bothTls = proxy.TlsStatus == "FAILED" && tun.TlsStatus == "FAILED";
            if (bothTls)
            {
                return (
                    "Both PROXY and TUN failed before/at TLS toward the test destination via C01. " +
                    "Shared failure through the SS tunnel — investigate TCP to NL and tunnel establishment first.",
                    "medium",
                    "Inspect tcpConnectDirect + sing-box i/o timeout lines for this runId only.");
            }

            return (
                "Both PROXY and TUN downloads failed — do NOT conclude TUN is the root cause. " +
                "Shared path to NL or tunnel data plane is the primary suspect.",
                "medium",
                "Re-run DIAG C01 once on Irancell; if identical, gather read-only NL listener evidence for :40121.");
        }

        if (proxyDl == "PASS" && tunDl == "PASS")
        {
            if (proxy.ExitIpStatus == "OK" && tun.ExitIpStatus == "OK")
            {
                return (
                    "Both diagnostic downloads PASS with NL exit IP. Real browser failure may still differ — NOT Full VPN PASS.",
                    "medium",
                    "If browsing still fails, compare browser vs diagnostic (SNI/HTTP2/parallel flows).");
            }

            return (
                "Downloads completed but exit IP not fully verified — do not declare VPN path PASS.",
                "low",
                "Inspect exitIpStatus fields in the run JSON.");
        }

        return (
            $"Inconclusive (PROXY dl={proxyDl} outcome={proxy.Outcome}; TUN dl={tunDl} outcome={tun.Outcome}; tcpDirect={tcpDirectStatus}).",
            "low",
            "Owner runs DIAG C01 on Irancell and shares diag-c01-*.json for this runId.");
    }

    private static string Flatten(Exception ex)
    {
        var parts = new List<string>();
        for (Exception? e = ex; e != null; e = e.InnerException)
            parts.Add(e.GetType().Name + ": " + e.Message);
        var s = string.Join(" | ", parts);
        return s.Length <= 400 ? s : s[..400];
    }

    private static string Trim(string s) =>
        string.IsNullOrWhiteSpace(s) ? "" : (s.Length <= 220 ? s.Trim() : s.Trim()[..220]);

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
