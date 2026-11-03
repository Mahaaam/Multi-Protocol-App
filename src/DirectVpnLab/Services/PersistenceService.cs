using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DirectVpnLab.Models;

namespace DirectVpnLab.Services;

public sealed class PersistedLabState
{
    public string SchemaVersion { get; set; } = "1";
    public string ServerIp { get; set; } = "";
    public string EngineVersion { get; set; } = "";
    public string NetworkFingerprint { get; set; } = "";
    public DateTime? LastTestAtUtc { get; set; }
    public string? BestMethodId { get; set; }
    public string? LastExitIp { get; set; }
    public bool ResultsStale { get; set; }
    public string? StaleReason { get; set; }
    public List<PersistedMethodResult> Methods { get; set; } = new();
    public UiPrefs Ui { get; set; } = new();
}

public sealed class PersistedMethodResult
{
    public string Id { get; set; } = "";
    public string Status { get; set; } = "Pending";
    public double LatencyMs { get; set; }
    public double JitterMs { get; set; }
    public double ConnectTimeMs { get; set; }
    public double SuccessRate { get; set; }
    public double QualityScore { get; set; }
    public int Rank { get; set; }
    public string? ExitIp { get; set; }
    public string? LastError { get; set; }
    public string? SkipReason { get; set; }
    public DateTime? TestedAtUtc { get; set; }
}

public sealed class UiPrefs
{
    public bool AutoScrollLog { get; set; } = true;
    public string? LastSelectedMethodId { get; set; }
}

public sealed class PersistenceService
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("DirectVpnLab.v1.results");
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    private readonly LiveLogService _log;

    public PersistenceService(LiveLogService log)
    {
        _log = log;
    }

    public static string ResultsPath => Path.Combine(AppPaths.StateDir, "results.dpapi");
    public static string ResultsMetaPath => Path.Combine(AppPaths.StateDir, "results.meta.json");

    public PersistedLabState LoadOrCreate(LabCredentials cred)
    {
        var currentFp = CaptureNetworkFingerprint();
        var engine = DetectEngineVersion();
        try
        {
            if (!File.Exists(ResultsPath))
            {
                return Fresh(cred, currentFp, engine);
            }

            var protectedBytes = File.ReadAllBytes(ResultsPath);
            var plain = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.CurrentUser);
            var state = JsonSerializer.Deserialize<PersistedLabState>(plain, JsonOpts)
                        ?? Fresh(cred, currentFp, engine);

            EvaluateFreshness(state, cred, currentFp, engine);
            return state;
        }
        catch (Exception ex)
        {
            _log.Warn($"Could not load persisted results: {ex.Message}");
            return Fresh(cred, currentFp, engine);
        }
    }

    public void Save(PersistedLabState state, LabCredentials cred)
    {
        try
        {
            state.ServerIp = cred.server_ip;
            state.EngineVersion = DetectEngineVersion();
            state.NetworkFingerprint = CaptureNetworkFingerprint();
            var json = JsonSerializer.Serialize(state, JsonOpts);
            var bytes = Encoding.UTF8.GetBytes(json);
            var protectedBytes = ProtectedData.Protect(bytes, Entropy, DataProtectionScope.CurrentUser);
            Directory.CreateDirectory(AppPaths.StateDir);
            File.WriteAllBytes(ResultsPath, protectedBytes);

            // Non-secret meta for quick UI (no passwords/keys)
            var meta = new
            {
                state.LastTestAtUtc,
                state.BestMethodId,
                state.ResultsStale,
                state.StaleReason,
                PassCount = state.Methods.Count(m => m.Status == "Pass"),
                SavedAtUtc = DateTime.UtcNow
            };
            File.WriteAllText(ResultsMetaPath, JsonSerializer.Serialize(meta, JsonOpts));
        }
        catch (Exception ex)
        {
            _log.Warn($"Could not save results: {ex.Message}");
        }
    }

    public void ApplyToMethods(PersistedLabState state, IList<ProtocolMethod> methods)
    {
        var map = state.Methods.ToDictionary(m => m.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var m in methods)
        {
            if (!map.TryGetValue(m.Id, out var p)) continue;
            if (Enum.TryParse<TestStatus>(p.Status, true, out var st))
            {
                m.Status = st;
            }
            m.LatencyMs = p.LatencyMs;
            m.JitterMs = p.JitterMs;
            m.ConnectTimeMs = p.ConnectTimeMs;
            m.SuccessRate = p.SuccessRate;
            m.QualityScore = p.QualityScore;
            m.Rank = p.Rank;
            m.ExitIp = p.ExitIp;
            m.LastError = p.LastError;
            if (!string.IsNullOrWhiteSpace(p.SkipReason))
            {
                m.SkipReason = p.SkipReason;
            }
            m.LastTestedAtUtc = p.TestedAtUtc;
        }

        if (state.ResultsStale)
        {
            foreach (var m in methods.Where(x => x.Status == TestStatus.Pass))
            {
                // Keep data visible but mark as historical — not live Connected
                m.IsHistorical = true;
            }
        }
    }

    public PersistedLabState CaptureFromMethods(
        IEnumerable<ProtocolMethod> methods,
        LabCredentials cred,
        DateTime? lastTestAtUtc,
        string? bestMethodId)
    {
        var state = new PersistedLabState
        {
            ServerIp = cred.server_ip,
            EngineVersion = DetectEngineVersion(),
            NetworkFingerprint = CaptureNetworkFingerprint(),
            LastTestAtUtc = lastTestAtUtc,
            BestMethodId = bestMethodId,
            LastExitIp = methods.FirstOrDefault(m => m.Status == TestStatus.Pass)?.ExitIp,
            ResultsStale = false,
            StaleReason = null,
            Methods = methods.Select(m => new PersistedMethodResult
            {
                Id = m.Id,
                Status = m.Status.ToString(),
                LatencyMs = m.LatencyMs,
                JitterMs = m.JitterMs,
                ConnectTimeMs = m.ConnectTimeMs,
                SuccessRate = m.SuccessRate,
                QualityScore = m.QualityScore,
                Rank = m.Rank,
                ExitIp = m.ExitIp,
                LastError = m.LastError,
                SkipReason = m.SkipReason,
                TestedAtUtc = m.LastTestedAtUtc ?? lastTestAtUtc
            }).ToList()
        };
        return state;
    }

    private static PersistedLabState Fresh(LabCredentials cred, string fp, string engine) => new()
    {
        ServerIp = cred.server_ip,
        EngineVersion = engine,
        NetworkFingerprint = fp
    };

    private static void EvaluateFreshness(
        PersistedLabState state,
        LabCredentials cred,
        string currentFp,
        string engine)
    {
        if (!string.Equals(state.ServerIp, cred.server_ip, StringComparison.OrdinalIgnoreCase))
        {
            state.ResultsStale = true;
            state.StaleReason = "Server IP changed since last test";
            return;
        }

        if (!string.IsNullOrWhiteSpace(state.EngineVersion) &&
            !string.Equals(state.EngineVersion, engine, StringComparison.OrdinalIgnoreCase))
        {
            state.ResultsStale = true;
            state.StaleReason = $"Engine version changed ({state.EngineVersion} → {engine})";
            return;
        }

        if (!string.IsNullOrWhiteSpace(state.NetworkFingerprint) &&
            !string.Equals(state.NetworkFingerprint, currentFp, StringComparison.Ordinal))
        {
            state.ResultsStale = true;
            state.StaleReason = "Network environment changed (Wi-Fi/Hotspot/gateway)";
            return;
        }

        if (state.LastTestAtUtc is { } t && DateTime.UtcNow - t > TimeSpan.FromDays(7))
        {
            state.ResultsStale = true;
            state.StaleReason = "Last test older than 7 days";
        }
    }

    public static string CaptureNetworkFingerprint()
    {
        try
        {
            var parts = new List<string>();
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()
                         .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                                     n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                                     n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                         .OrderBy(n => n.Name))
            {
                var props = ni.GetIPProperties();
                var gw = string.Join(",", props.GatewayAddresses.Select(g => g.Address.ToString()).OrderBy(x => x));
                var dns = string.Join(",", props.DnsAddresses.Select(d => d.ToString()).OrderBy(x => x));
                var ip = string.Join(",", props.UnicastAddresses
                    .Where(u => u.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(u => u.Address.ToString())
                    .OrderBy(x => x));
                parts.Add($"{ni.Name}|{ni.NetworkInterfaceType}|{gw}|{dns}|{ip}");
            }
            var raw = string.Join(";", parts);
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
            return Convert.ToHexString(hash)[..16];
        }
        catch
        {
            return "unknown";
        }
    }

    public static string DetectEngineVersion()
    {
        try
        {
            if (!File.Exists(AppPaths.SingBoxExe)) return "missing";
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = AppPaths.SingBoxExe,
                Arguments = "version",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = System.Diagnostics.Process.Start(psi);
            if (p == null) return "unknown";
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            var line = output.Split('\n').FirstOrDefault(l => l.Contains("sing-box version", StringComparison.OrdinalIgnoreCase));
            return line?.Replace("sing-box version", "", StringComparison.OrdinalIgnoreCase).Trim() ?? "unknown";
        }
        catch
        {
            return "unknown";
        }
    }
}
