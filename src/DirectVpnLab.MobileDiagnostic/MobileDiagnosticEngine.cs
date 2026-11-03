using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DirectVpnLab.Models;
using DirectVpnLab.Services;

namespace DirectVpnLab.MobileDiagnostic;

public sealed class PathCheckResult
{
    public bool PathOk { get; init; }
    public string NetworkAdapter { get; init; } = "UNKNOWN";
    public string DefaultRoute { get; init; } = "UNKNOWN";
    public string EffectiveToServer { get; init; } = "UNKNOWN";
    public string Gateway { get; init; } = "UNKNOWN";
    public string PublicIpv4A { get; init; } = "UNKNOWN";
    public string PublicIpv4B { get; init; } = "UNKNOWN";
    public string PublicIpv4 { get; init; } = "UNKNOWN";
    public string MobileNetworkStatus { get; init; } = "UNKNOWN";
    public string BlockReason { get; init; } = "";
    public bool WireGuardEffective { get; init; }
    public IReadOnlyList<string> ActiveVpnAdapters { get; init; } = Array.Empty<string>();
}

public sealed class TcpSnapshot
{
    public DateTime Utc { get; init; }
    public string Local { get; init; } = "";
    public string Remote { get; init; } = "";
    public string State { get; init; } = "";
}

public sealed class MobileRunReport
{
    public string ApplicationVersion { get; set; } = "";
    public string RunId { get; set; } = "";
    public DateTime StartUtc { get; set; }
    public DateTime EndUtc { get; set; }
    public string NetworkAdapter { get; set; } = "";
    public string EffectiveRoute { get; set; } = "";
    public string PublicIpv4 { get; set; } = "";
    public string TcpConnectionResult { get; set; } = "NOT_RUN";
    public string DirectDownloadResult { get; set; } = "NOT_RUN";
    public string ProxyDownloadResult { get; set; } = "NOT_RUN";
    public string ConfirmedExitIp { get; set; } = "";
    public long BytesReceived { get; set; }
    public double? StallDurationSeconds { get; set; }
    public string ErrorClassification { get; set; } = "";
    public string CleanupResult { get; set; } = "";
    public string SingBoxLogExcerpt { get; set; } = "";
    public string Summary { get; set; } = "";
    public string Hypothesis { get; set; } = "";
    public string Retransmission { get; set; } = "NOT_AVAILABLE";
    public string AckInfo { get; set; } = "NOT_AVAILABLE";
    public List<TcpSnapshot> TcpSnapshots { get; set; } = new();
    public object? RawCompare { get; set; }
}

/// <summary>
/// Offline-from-Cursor C01 PROXY-ONLY orchestrator for Irancell / MCI hotspot path.
/// Does not mutate WireGuard, Windows routes, DNS, or firewall.
/// </summary>
public sealed class MobileDiagnosticEngine
{
    public const string AppVersion = "1.1.10-mobile-diag";
    public const string ServerIpDefault = "82.23.248.121";
    public const int ServerPortDefault = 40121;

    public static string ReportsDir
    {
        get
        {
            const string preferred = @"E:\Repsitory\Multi-Protocol-App\MobileDiagnosticReports";
            try
            {
                Directory.CreateDirectory(preferred);
                return preferred;
            }
            catch
            {
                var fallback = Path.Combine(
                    Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory,
                    "MobileDiagnosticReports");
                Directory.CreateDirectory(fallback);
                return fallback;
            }
        }
    }

    private readonly LiveLogService _log;
    private LabCredentials? _cred;
    private ConnectionService? _connection;
    private MobileRunReport? _lastReport;

    public MobileRunReport? LastReport => _lastReport;

    public MobileDiagnosticEngine(LiveLogService log)
    {
        _log = log;
    }

    public void EnsureReady()
    {
        AppPaths.EnsureDirs();
        if (!File.Exists(AppPaths.CredentialsPath))
            throw new FileNotFoundException("credentials.json missing next to EXE (Assets\\certs\\credentials.json)");
        if (!File.Exists(AppPaths.SingBoxExe))
            throw new FileNotFoundException("sing-box.exe missing (Assets\\sing-box\\sing-box.exe)");
        _cred = ProtocolCatalog.LoadCredentials();
        _connection = new ConnectionService(_log, _cred);
    }

    public PathCheckResult CheckNetwork()
    {
        var wifi = FindWifiIpv4();
        var defaults = ListDefaultRoutes();
        var effective = FindEffectiveRoute(ServerIpDefault);
        var vpnAdapters = ListVpnLikeAdapters();
        var wgEffective = effective.Contains("WG", StringComparison.OrdinalIgnoreCase) ||
                          effective.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                          defaults.Any(d => d.Contains("WG", StringComparison.OrdinalIgnoreCase) &&
                                            !d.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase));

        var (ipA, errA) = FetchPublicIp("https://api.ipify.org");
        var (ipB, errB) = FetchPublicIpFromTrace("https://1.1.1.1/cdn-cgi/trace");

        string publicIp;
        if (!string.IsNullOrWhiteSpace(ipA) && !string.IsNullOrWhiteSpace(ipB))
            publicIp = string.Equals(ipA, ipB, StringComparison.Ordinal) ? ipA! : $"A={ipA};B={ipB}";
        else if (!string.IsNullOrWhiteSpace(ipA))
            publicIp = ipA!;
        else if (!string.IsNullOrWhiteSpace(ipB))
            publicIp = ipB!;
        else
            publicIp = "UNKNOWN";

        var gateway = wifi.Gateway ?? "UNKNOWN";
        var adapter = wifi.Alias ?? "UNKNOWN";
        var looksHotspot = gateway is "172.20.10.1" ||
                           (wifi.Ip?.StartsWith("172.20.10.", StringComparison.Ordinal) == true);

        string mobileStatus;
        var block = "";
        var pathOk = false;

        if (wgEffective || vpnAdapters.Any(a => a.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                                                a.Equals("WG", StringComparison.OrdinalIgnoreCase)))
        {
            mobileStatus = "BLOCKED — WireGuard still effective; deactivate tunnel WG first";
            block = "Effective path uses WireGuard (not interface name alone / not geo-IP)";
        }
        else if (effective.Contains("UNKNOWN", StringComparison.OrdinalIgnoreCase) &&
                 string.IsNullOrWhiteSpace(wifi.Alias))
        {
            mobileStatus = "UNKNOWN — no Wi-Fi / route evidence";
            block = "Could not resolve Wi-Fi adapter or route to server";
        }
        else if (publicIp == "UNKNOWN")
        {
            // Path may still be OK; do not invent previous mobile IP
            mobileStatus = looksHotspot
                ? "PARTIAL — hotspot path likely; public IP lookup UNKNOWN (do not assume prior IP)"
                : "PARTIAL — public IP UNKNOWN; confirm route carefully";
            pathOk = !wgEffective &&
                     effective.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase);
            if (!pathOk)
                block = "Public IP unknown and effective route not clearly Wi-Fi";
        }
        else if (!wgEffective &&
                 (effective.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase) ||
                  effective.Contains(gateway, StringComparison.OrdinalIgnoreCase) ||
                  looksHotspot))
        {
            mobileStatus = "OK — direct path (WireGuard not effective)";
            pathOk = true;
        }
        else
        {
            mobileStatus = "BLOCKED — path not confirmed as direct Wi-Fi/mobile";
            block = $"EffectiveToServer={effective}; DefaultRoutes={string.Join(" | ", defaults)}";
        }

        return new PathCheckResult
        {
            PathOk = pathOk,
            NetworkAdapter = string.IsNullOrWhiteSpace(wifi.Ip)
                ? adapter
                : $"{adapter} ({wifi.Ip})",
            DefaultRoute = defaults.Count == 0 ? "NONE" : string.Join(" | ", defaults),
            EffectiveToServer = effective,
            Gateway = gateway,
            PublicIpv4A = ipA ?? $"FAIL:{errA}",
            PublicIpv4B = ipB ?? $"FAIL:{errB}",
            PublicIpv4 = publicIp,
            MobileNetworkStatus = mobileStatus,
            BlockReason = block,
            WireGuardEffective = wgEffective,
            ActiveVpnAdapters = vpnAdapters
        };
    }

    public async Task<MobileRunReport> RunC01TestAsync(
        PathCheckResult path,
        Action<string> setStatus,
        Action<long, long, double> setProgress,
        CancellationToken ct)
    {
        EnsureReady();
        if (!path.PathOk)
        {
            var denied = new MobileRunReport
            {
                ApplicationVersion = AppVersion,
                RunId = $"denied-{DateTime.UtcNow:yyyyMMddHHmmss}",
                StartUtc = DateTime.UtcNow,
                EndUtc = DateTime.UtcNow,
                NetworkAdapter = path.NetworkAdapter,
                EffectiveRoute = path.EffectiveToServer,
                PublicIpv4 = path.PublicIpv4,
                ErrorClassification = "PATH_NOT_DIRECT",
                Summary = path.MobileNetworkStatus,
                CleanupResult = "n/a"
            };
            _lastReport = denied;
            AutoSave(denied);
            return denied;
        }

        var cred = _cred!;
        var connection = _connection!;
        var c01 = ProtocolCatalog.BuildMethods(cred)
            .FirstOrDefault(m => m.Id == "C01")
            ?? throw new InvalidOperationException("C01 missing from catalog");

        var started = DateTime.UtcNow;
        var runId = $"mobile-c01-{started:yyyyMMddHHmmss}-{Guid.NewGuid().ToString("N")[..8]}";
        var serverIp = string.IsNullOrWhiteSpace(cred.server_ip) ? ServerIpDefault : cred.server_ip.Trim();
        var serverPort = c01.Port > 0 ? c01.Port : ServerPortDefault;

        setStatus("TCP probe…");
        var snapshots = new List<TcpSnapshot>();
        using var snapCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var snapTask = SnapshotLoopAsync(serverIp, serverPort, snapshots, snapCts.Token);

        var diag = new ProxyTunCompareDiagnostic(_log, cred, connection)
        {
            OnTransferProgress = (mode, got, target, elapsedMs) =>
            {
                var secs = Math.Max(elapsedMs / 1000.0, 0.001);
                var mbps = got * 8.0 / secs / 1_000_000.0;
                setProgress(got, target, mbps);
                setStatus($"{mode}: {got}/{target} B");
            }
        };

        ProxyTunCompareDiagnostic.CompareReport compare;
        try
        {
            setStatus("C01 PROXY-ONLY session…");
            compare = await diag.RunProxyOnlySessionAsync(c01, ct).ConfigureAwait(false);
        }
        finally
        {
            snapCts.Cancel();
            try { await snapTask.ConfigureAwait(false); } catch { /* ignore */ }
            setStatus("Cleanup…");
            try { await connection.DisconnectAsync().ConfigureAwait(false); } catch { /* ignore */ }
        }

        var proxy = compare.Proxy;
        var stallSec = proxy.DownloadStatus is "STALL" or "TIMEOUT"
            ? ProxyTunCompareDiagnostic.ProxyOnlyStallIdle.TotalSeconds
            : (double?)null;

        var report = new MobileRunReport
        {
            ApplicationVersion = AppVersion,
            RunId = compare.RunId.Length > 0 ? compare.RunId : runId,
            StartUtc = compare.StartedAtUtc == default ? started : compare.StartedAtUtc,
            EndUtc = compare.FinishedAtUtc == default ? DateTime.UtcNow : compare.FinishedAtUtc,
            NetworkAdapter = path.NetworkAdapter,
            EffectiveRoute = path.EffectiveToServer,
            PublicIpv4 = path.PublicIpv4,
            TcpConnectionResult = proxy.TcpConnectStatus != "NOT_MEASURED"
                ? $"{proxy.TcpConnectStatus}: {proxy.TcpConnectDetail}"
                : compare.DirectBaseline?.TcpConnectStatus + ": " + compare.DirectBaseline?.TcpConnectDetail,
            DirectDownloadResult = FormatLeg(compare.DirectBaseline),
            ProxyDownloadResult = FormatLeg(proxy),
            ConfirmedExitIp = proxy.ExitIp ?? "",
            BytesReceived = proxy.BytesReceived,
            StallDurationSeconds = stallSec,
            ErrorClassification = proxy.ErrorCategory ?? proxy.DownloadCategory ?? "",
            CleanupResult = compare.CleanupOk ? $"OK: {compare.CleanupDetail}" : $"FAIL: {compare.CleanupDetail}",
            SingBoxLogExcerpt = ExtractRunLog(_log.ExportSanitized(), compare.RunId),
            Summary = compare.Summary,
            Hypothesis = compare.Hypothesis,
            Retransmission = "NOT_AVAILABLE",
            AckInfo = "NOT_AVAILABLE",
            TcpSnapshots = snapshots,
            RawCompare = new
            {
                compare.RunId,
                compare.Summary,
                compare.Hypothesis,
                compare.Confidence,
                proxyOutcome = proxy.Outcome,
                proxyDownload = proxy.DownloadStatus,
                proxyBytes = proxy.BytesReceived,
                proxyExit = proxy.ExitIp,
                proxyExitStatus = proxy.ExitIpStatus,
                firstByteMs = proxy.FirstByteMs,
                lastProgressMs = proxy.LastProgressMs,
                totalMs = proxy.TotalMs,
                mbps = proxy.Mbps
            }
        };

        _lastReport = report;
        AutoSave(report);
        setStatus(proxy.Outcome == "PASS" ? "DONE — PROXY PASS (not Full VPN PASS)" : $"DONE — {proxy.Outcome}/{proxy.DownloadStatus}");
        return report;
    }

    public async Task<string> CancelAndCleanupAsync()
    {
        try
        {
            if (_connection != null)
            {
                var (ok, msg) = await _connection.DisconnectAsync().ConfigureAwait(false);
                return ok ? $"OK: {msg}" : $"FAIL: {msg}";
            }

            // Best-effort: stop any discover-* sing-box left from this tool
            foreach (var p in Process.GetProcessesByName("sing-box"))
            {
                try
                {
                    var path = p.MainModule?.FileName ?? "";
                    if (path.Contains("DirectVpnLab", StringComparison.OrdinalIgnoreCase) ||
                        path.Contains("Mobile-Diagnostic", StringComparison.OrdinalIgnoreCase) ||
                        path.Contains("MobileDiagnostic", StringComparison.OrdinalIgnoreCase))
                    {
                        p.Kill(entireProcessTree: true);
                    }
                }
                catch
                {
                    // ignore access denied
                }
            }

            return "OK: no ConnectionService; best-effort process scan done";
        }
        catch (Exception ex)
        {
            return "FAIL: " + ex.Message;
        }
    }

    public (string jsonPath, string txtPath) SaveReport(MobileRunReport? report = null)
    {
        report ??= _lastReport ?? throw new InvalidOperationException("No report to save — run CHECK/TEST first");
        return AutoSave(report);
    }

    public static (string jsonPath, string txtPath) WriteSampleReportForValidation()
    {
        var sample = new MobileRunReport
        {
            ApplicationVersion = AppVersion,
            RunId = "sample-validation-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss"),
            StartUtc = DateTime.UtcNow.AddMinutes(-1),
            EndUtc = DateTime.UtcNow,
            NetworkAdapter = "Wi-Fi (172.20.10.2)",
            EffectiveRoute = "Wi-Fi via 172.20.10.1",
            PublicIpv4 = "UNKNOWN",
            TcpConnectionResult = "NOT_RUN (sample)",
            DirectDownloadResult = "NOT_RUN (sample)",
            ProxyDownloadResult = "NOT_RUN (sample)",
            ConfirmedExitIp = "",
            BytesReceived = 0,
            StallDurationSeconds = null,
            ErrorClassification = "SAMPLE_ONLY",
            CleanupResult = "OK: sample",
            SingBoxLogExcerpt = "(none — sample)",
            Summary = "Sample JSON validation — not a live Irancell run",
            Hypothesis = "n/a",
            Retransmission = "NOT_AVAILABLE",
            AckInfo = "NOT_AVAILABLE"
        };
        return WriteFiles(sample);
    }

    private (string jsonPath, string txtPath) AutoSave(MobileRunReport report) => WriteFiles(report);

    private static (string jsonPath, string txtPath) WriteFiles(MobileRunReport report)
    {
        var dir = ReportsDir;
        var safeId = Regex.Replace(report.RunId, @"[^\w\-.]+", "_");
        var jsonPath = Path.Combine(dir, $"{safeId}.json");
        var txtPath = Path.Combine(dir, $"{safeId}.txt");

        var payload = new
        {
            report.ApplicationVersion,
            report.RunId,
            startUtc = report.StartUtc,
            endUtc = report.EndUtc,
            report.NetworkAdapter,
            report.EffectiveRoute,
            report.PublicIpv4,
            report.TcpConnectionResult,
            report.DirectDownloadResult,
            report.ProxyDownloadResult,
            report.ConfirmedExitIp,
            report.BytesReceived,
            report.StallDurationSeconds,
            report.ErrorClassification,
            report.CleanupResult,
            report.Retransmission,
            report.AckInfo,
            report.Summary,
            report.Hypothesis,
            tcpSnapshots = report.TcpSnapshots,
            rawCompare = report.RawCompare,
            singBoxLogExcerpt = report.SingBoxLogExcerpt
        };

        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
        // Strip accidental secrets if any leaked into excerpt
        json = LiveLogService.Sanitize(json);
        File.WriteAllText(jsonPath, json, Encoding.UTF8);

        var sb = new StringBuilder();
        sb.AppendLine("Direct VPN Lab — Mobile C01 Diagnostic Report");
        sb.AppendLine($"ApplicationVersion: {report.ApplicationVersion}");
        sb.AppendLine($"RunId: {report.RunId}");
        sb.AppendLine($"StartUtc: {report.StartUtc:o}");
        sb.AppendLine($"EndUtc: {report.EndUtc:o}");
        sb.AppendLine($"NetworkAdapter: {report.NetworkAdapter}");
        sb.AppendLine($"EffectiveRoute: {report.EffectiveRoute}");
        sb.AppendLine($"PublicIpv4: {report.PublicIpv4}");
        sb.AppendLine($"TcpConnectionResult: {report.TcpConnectionResult}");
        sb.AppendLine($"DirectDownloadResult: {report.DirectDownloadResult}");
        sb.AppendLine($"ProxyDownloadResult: {report.ProxyDownloadResult}");
        sb.AppendLine($"ConfirmedExitIp: {report.ConfirmedExitIp}");
        sb.AppendLine($"BytesReceived: {report.BytesReceived}");
        sb.AppendLine($"StallDurationSeconds: {report.StallDurationSeconds?.ToString() ?? "n/a"}");
        sb.AppendLine($"ErrorClassification: {report.ErrorClassification}");
        sb.AppendLine($"CleanupResult: {report.CleanupResult}");
        sb.AppendLine($"Retransmission: {report.Retransmission}");
        sb.AppendLine($"AckInfo: {report.AckInfo}");
        sb.AppendLine($"Summary: {report.Summary}");
        sb.AppendLine($"Hypothesis: {report.Hypothesis}");
        sb.AppendLine();
        sb.AppendLine("--- sing-box log (this run, sanitized) ---");
        sb.AppendLine(report.SingBoxLogExcerpt);
        File.WriteAllText(txtPath, LiveLogService.Sanitize(sb.ToString()), Encoding.UTF8);

        return (jsonPath, txtPath);
    }

    private static string FormatLeg(ProxyTunCompareDiagnostic.LegResult? leg)
    {
        if (leg == null) return "NOT_RUN";
        return $"{leg.DownloadStatus} bytes={leg.BytesReceived} exit={leg.ExitIpStatus}/{leg.ExitIp ?? "-"} " +
               $"fb={leg.FirstByteMs:F0}ms last={leg.LastProgressMs:F0}ms {leg.Mbps:F2}Mbps cat={leg.DownloadCategory ?? "-"}";
    }

    private static string ExtractRunLog(string all, string runId)
    {
        if (string.IsNullOrWhiteSpace(all)) return "(empty)";
        if (string.IsNullOrWhiteSpace(runId)) return TrimLog(all, 80);
        var idx = all.IndexOf(runId, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return TrimLog(all, 80);
        return TrimLog(all[Math.Max(0, idx - 200)..], 120);
    }

    private static string TrimLog(string s, int maxLines)
    {
        var lines = s.Replace("\r\n", "\n").Split('\n');
        if (lines.Length <= maxLines) return s;
        return string.Join("\n", lines.TakeLast(maxLines));
    }

    private static async Task SnapshotLoopAsync(string serverIp, int port, List<TcpSnapshot> sink, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                foreach (var c in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections())
                {
                    if (c.RemoteEndPoint.Address.ToString() == serverIp && c.RemoteEndPoint.Port == port)
                    {
                        sink.Add(new TcpSnapshot
                        {
                            Utc = DateTime.UtcNow,
                            Local = c.LocalEndPoint.ToString(),
                            Remote = c.RemoteEndPoint.ToString(),
                            State = c.State.ToString()
                        });
                    }
                }
            }
            catch
            {
                // ignore
            }

            try { await Task.Delay(500, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private static (string? Alias, string? Ip, string? Gateway) FindWifiIpv4()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (!ni.Name.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase) &&
                    ni.NetworkInterfaceType != NetworkInterfaceType.Wireless80211)
                    continue;

                var props = ni.GetIPProperties();
                var ip = props.UnicastAddresses
                    .FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork)
                    ?.Address.ToString();
                var gw = props.GatewayAddresses
                    .Select(g => g.Address)
                    .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                    ?.ToString();
                return (ni.Name, ip, gw);
            }
        }
        catch
        {
            // ignore
        }

        return (null, null, null);
    }

    private static List<string> ListDefaultRoutes()
    {
        var list = new List<string>();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell",
                Arguments =
                    "-NoProfile -Command \"Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | " +
                    "Sort-Object RouteMetric,InterfaceMetric | " +
                    "ForEach-Object { '{0} via {1} metric={2}' -f $_.InterfaceAlias,$_.NextHop,$_.RouteMetric }\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return list;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                list.Add(line);
        }
        catch (Exception ex)
        {
            list.Add("ERROR:" + ex.Message);
        }

        return list;
    }

    private static string FindEffectiveRoute(string destIp)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell",
                Arguments =
                    $"-NoProfile -Command \"$r=Find-NetRoute -RemoteIPAddress {destIp} | Select-Object -First 1; " +
                    "if($null -eq $r){'UNKNOWN'} else { '{0} ip={1} nexthop={2}' -f $r.InterfaceAlias,$r.IPAddress,$r.NextHop }\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return "UNKNOWN";
            var output = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit(5000);
            return string.IsNullOrWhiteSpace(output) ? "UNKNOWN" : output;
        }
        catch (Exception ex)
        {
            return "ERROR:" + ex.Message;
        }
    }

    private static List<string> ListVpnLikeAdapters()
    {
        var hits = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                var name = ni.Name + " " + ni.Description;
                if (name.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("WG", StringComparison.OrdinalIgnoreCase) ||
                    ni.Name.Equals("WG", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("TAP-Windows", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase))
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

    private static (string? ip, string? err) FetchPublicIp(string url)
    {
        try
        {
            using var handler = new HttpClientHandler { UseProxy = false, Proxy = null };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
            var s = client.GetStringAsync(url).GetAwaiter().GetResult().Trim();
            if (IPAddress.TryParse(s, out _)) return (s, null);
            return (null, "unparseable");
        }
        catch (Exception ex)
        {
            return (null, ex.Message);
        }
    }

    private static (string? ip, string? err) FetchPublicIpFromTrace(string url)
    {
        try
        {
            using var handler = new HttpClientHandler { UseProxy = false, Proxy = null };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
            var trace = client.GetStringAsync(url).GetAwaiter().GetResult();
            foreach (var line in trace.Split('\n'))
            {
                if (line.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
                    return (line[3..].Trim(), null);
            }

            return (null, "no ip=");
        }
        catch (Exception ex)
        {
            return (null, ex.Message);
        }
    }
}
