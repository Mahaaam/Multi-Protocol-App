using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using DirectVpnLab.Models;

namespace DirectVpnLab.Services;

public sealed class SpeedTestService
{
    private readonly LiveLogService _log;

    private const string DownloadUrl = "https://speed.cloudflare.com/__down?bytes=5000000"; // 5MB
    private const string UploadUrl = "https://speed.cloudflare.com/__up";

    public SpeedTestService(LiveLogService log)
    {
        _log = log;
    }

    public async Task<SpeedTestResult> RunAsync(string route, string? protocol, int? proxyPort, CancellationToken ct)
    {
        if (route is not ("DIRECT" or "VPN"))
        {
            throw new ArgumentException("Route must be DIRECT or VPN", nameof(route));
        }

        _log.Info($"Speed Test starting route={route}");
        if (route == "DIRECT")
        {
            WarnOtherVpn();
        }

        HttpMessageHandler handler;
        if (proxyPort is > 0)
        {
            handler = new HttpClientHandler
            {
                Proxy = new WebProxy($"http://127.0.0.1:{proxyPort.Value}"),
                UseProxy = true
            };
            _log.Info($"Speed Test path confirmed: {route} via explicit local proxy :{proxyPort}");
        }
        else
        {
            handler = new HttpClientHandler { UseProxy = false, Proxy = null };
            _log.Info($"Speed Test path confirmed: {route} without HTTP proxy (system proxy disabled)");
        }

        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(60) };

        try
        {
            var (latency, jitter) = await MeasureLatencyAsync(client, ct);
            var download = await MeasureDownloadAsync(client, ct);
            var upload = await MeasureUploadAsync(client, ct);

            var result = new SpeedTestResult
            {
                Route = route,
                Protocol = protocol,
                DownloadMbps = download,
                UploadMbps = upload,
                LatencyMs = latency,
                JitterMs = jitter,
                Success = true
            };

            _log.Info(
                $"Speed Test done route={route} down={download:F2}Mbps up={upload:F2}Mbps " +
                $"latency={latency:F0}ms jitter={jitter:F0}ms");
            return result;
        }
        catch (Exception ex)
        {
            _log.Warn($"Speed Test FAILED route={route}: {ex.Message}");
            return new SpeedTestResult
            {
                Route = route,
                Protocol = protocol,
                Success = false,
                Error = ex.Message
            };
        }
    }

    private async Task<(double latency, double jitter)> MeasureLatencyAsync(HttpClient client, CancellationToken ct)
    {
        var samples = new List<double>();
        Exception? last = null;
        for (var i = 0; i < 5; i++)
        {
            ct.ThrowIfCancellationRequested();
            var sw = Stopwatch.StartNew();
            try
            {
                using var resp = await client.GetAsync("https://1.1.1.1/cdn-cgi/trace", HttpCompletionOption.ResponseHeadersRead, ct);
                resp.EnsureSuccessStatusCode();
                sw.Stop();
                samples.Add(sw.Elapsed.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                sw.Stop();
                last = ex;
            }
            await Task.Delay(120, ct);
        }

        if (samples.Count == 0)
        {
            throw new InvalidOperationException($"Latency probes failed: {last?.Message ?? "no samples"}");
        }
        var avg = samples.Average();
        var jitter = Math.Sqrt(samples.Sum(v => (v - avg) * (v - avg)) / samples.Count);
        return (avg, jitter);
    }

    private async Task<double> MeasureDownloadAsync(HttpClient client, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var resp = await client.GetAsync(DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!resp.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"Download HTTP {(int)resp.StatusCode} — not counted as speed");
        }
        var data = await resp.Content.ReadAsByteArrayAsync(ct);
        sw.Stop();
        if (data.Length < 100_000)
        {
            throw new InvalidOperationException($"Download payload too small ({data.Length} bytes)");
        }
        var seconds = Math.Max(sw.Elapsed.TotalSeconds, 0.001);
        var mbps = data.Length * 8.0 / seconds / 1_000_000.0;
        _log.Info($"Download measured bytes={data.Length} time={seconds:F2}s http={(int)resp.StatusCode}");
        return mbps;
    }

    private async Task<double> MeasureUploadAsync(HttpClient client, CancellationToken ct)
    {
        var payload = new byte[2_000_000];
        Random.Shared.NextBytes(payload);
        using var content = new ByteArrayContent(payload);
        var sw = Stopwatch.StartNew();
        using var resp = await client.PostAsync(UploadUrl, content, ct);
        sw.Stop();
        if (!resp.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"Upload HTTP {(int)resp.StatusCode} — not counted as speed");
        }
        var seconds = Math.Max(sw.Elapsed.TotalSeconds, 0.001);
        var mbps = payload.Length * 8.0 / seconds / 1_000_000.0;
        _log.Info($"Upload measured bytes={payload.Length} time={seconds:F2}s http={(int)resp.StatusCode}");
        return mbps;
    }

    private void WarnOtherVpn()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                var n = ni.Name + ni.Description;
                if ((n.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                     n.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase) ||
                     n.Contains("Outline", StringComparison.OrdinalIgnoreCase)) &&
                    !n.Contains("DirectVpnLab", StringComparison.OrdinalIgnoreCase))
                {
                    _log.Warn("Other VPN may be active; DIRECT result may not represent raw ISP path");
                    break;
                }
            }
        }
        catch { /* ignore */ }
    }
}
