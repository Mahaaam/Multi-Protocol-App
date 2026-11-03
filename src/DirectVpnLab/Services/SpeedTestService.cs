using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using DirectVpnLab.Models;

namespace DirectVpnLab.Services;

public sealed class SpeedTestService
{
    private readonly LiveLogService _log;

    // Small bounded endpoints (few MB). Cloudflare / thinkbroadband small files.
    private const string DownloadUrl = "https://speed.cloudflare.com/__down?bytes=5000000"; // 5MB
    private const string UploadUrl = "https://speed.cloudflare.com/__up";

    public SpeedTestService(LiveLogService log)
    {
        _log = log;
    }

    public async Task<SpeedTestResult> RunAsync(string route, string? protocol, int? proxyPort, CancellationToken ct)
    {
        _log.Info($"Speed Test starting route={route}");
        WarnOtherVpn();

        HttpMessageHandler handler;
        if (proxyPort is > 0)
        {
            handler = new HttpClientHandler
            {
                Proxy = new WebProxy($"http://127.0.0.1:{proxyPort.Value}"),
                UseProxy = true
            };
        }
        else
        {
            handler = new HttpClientHandler { UseProxy = false };
        }

        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(60) };

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
            JitterMs = jitter
        };

        _log.Info($"Speed Test done route={route} down={download:F2}Mbps up={upload:F2}Mbps latency={latency:F0}ms jitter={jitter:F0}ms");
        return result;
    }

    private async Task<(double latency, double jitter)> MeasureLatencyAsync(HttpClient client, CancellationToken ct)
    {
        var samples = new List<double>();
        for (var i = 0; i < 5; i++)
        {
            ct.ThrowIfCancellationRequested();
            var sw = Stopwatch.StartNew();
            try
            {
                using var resp = await client.GetAsync("https://1.1.1.1/cdn-cgi/trace", HttpCompletionOption.ResponseHeadersRead, ct);
                _ = resp.EnsureSuccessStatusCode();
                sw.Stop();
                samples.Add(sw.Elapsed.TotalMilliseconds);
            }
            catch
            {
                sw.Stop();
            }
            await Task.Delay(120, ct);
        }

        if (samples.Count == 0) return (0, 0);
        var avg = samples.Average();
        var jitter = Math.Sqrt(samples.Sum(v => (v - avg) * (v - avg)) / samples.Count);
        return (avg, jitter);
    }

    private async Task<double> MeasureDownloadAsync(HttpClient client, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var data = await client.GetByteArrayAsync(DownloadUrl, ct);
            sw.Stop();
            var seconds = Math.Max(sw.Elapsed.TotalSeconds, 0.001);
            var mbps = data.Length * 8.0 / seconds / 1_000_000.0;
            _log.Info($"Download measured bytes={data.Length} time={seconds:F2}s");
            return mbps;
        }
        catch (Exception ex)
        {
            _log.Warn($"Download test failed: {ex.Message}");
            return 0;
        }
    }

    private async Task<double> MeasureUploadAsync(HttpClient client, CancellationToken ct)
    {
        // 2MB upload
        var payload = new byte[2_000_000];
        Random.Shared.NextBytes(payload);
        var content = new ByteArrayContent(payload);
        var sw = Stopwatch.StartNew();
        try
        {
            using var resp = await client.PostAsync(UploadUrl, content, ct);
            sw.Stop();
            var seconds = Math.Max(sw.Elapsed.TotalSeconds, 0.001);
            var mbps = payload.Length * 8.0 / seconds / 1_000_000.0;
            _log.Info($"Upload measured bytes={payload.Length} time={seconds:F2}s status={(int)resp.StatusCode}");
            return mbps;
        }
        catch (Exception ex)
        {
            _log.Warn($"Upload test failed: {ex.Message}");
            return 0;
        }
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
