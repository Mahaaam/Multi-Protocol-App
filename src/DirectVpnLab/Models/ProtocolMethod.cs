namespace DirectVpnLab.Models;

public enum TestStatus
{
    Pending,
    Pass,
    Fail,
    Unverified,
    Skipped
}

public enum ConnectionUiState
{
    Disconnected,
    Testing,
    Connecting,
    Connected,
    Degraded,
    Failed
}

public sealed class ProtocolMethod
{
    public required string Id { get; init; }
    public required string Protocol { get; init; }
    public required string Transport { get; init; }
    public required int Port { get; init; }
    public required string Network { get; init; } // tcp / udp / both
    public string? SkipReason { get; set; }
    public bool IsSkipped => !string.IsNullOrEmpty(SkipReason);

    public TestStatus Status { get; set; } = TestStatus.Pending;
    public double LatencyMs { get; set; }
    public double JitterMs { get; set; }
    public double ConnectTimeMs { get; set; }
    public double SuccessRate { get; set; }
    public double QualityScore { get; set; }
    public string? ExitIp { get; set; }
    public string? LastError { get; set; }
    public int Rank { get; set; }
    public DateTime? LastTestedAtUtc { get; set; }
    public bool IsHistorical { get; set; }
    public FailureKind FailureKind { get; set; } = FailureKind.None;
    public int ProbeAttempts { get; set; }
    public int ProbeSuccesses { get; set; }

    public string DisplayName => $"{Protocol} + {Transport}";
    public string StatusLabel => Status switch
    {
        TestStatus.Pass when IsHistorical => "Pass (cached)",
        TestStatus.Pass => "Pass",
        TestStatus.Fail => "Fail",
        TestStatus.Unverified => "Unverified",
        TestStatus.Skipped => "Skipped",
        TestStatus.Pending => "Pending",
        _ => Status.ToString()
    };
}

public enum FailureKind
{
    None,
    Unsupported,
    NetworkBlocked,
    ConfigError,
    DependencyMissing,
    AuthenticationError,
    Timeout,
    Other
}

public sealed class SpeedTestResult
{
    public required string Route { get; init; }
    public double? DownloadMbps { get; init; }
    public double? UploadMbps { get; init; }
    public double? LatencyMs { get; init; }
    public double? JitterMs { get; init; }
    public string? Protocol { get; init; }
    public bool Success { get; init; }
    public string? Error { get; init; }
    public DateTime Timestamp { get; init; } = DateTime.Now;
}

public sealed class LabCredentials
{
    public string server_ip { get; set; } = "";
    public string sing_box_version { get; set; } = "";
    public RealityCred reality { get; set; } = new();
    public string vless_uuid { get; set; } = "";
    public string vmess_uuid { get; set; } = "";
    public string tuic_uuid { get; set; } = "";
    public string trojan_password { get; set; } = "";
    public string hysteria2_password { get; set; } = "";
    public string hysteria2_obfs_password { get; set; } = "";
    public string anytls_password { get; set; } = "";
    public string naive_username { get; set; } = "";
    public string naive_password { get; set; } = "";
    public string openvpn_username { get; set; } = "";
    public string openvpn_password { get; set; } = "";
    public string ss2022_method { get; set; } = "";
    public string ss2022_password { get; set; } = "";
    public string ss_inner_method { get; set; } = "";
    public string ss_inner_password { get; set; } = "";
    public string shadowtls_password { get; set; } = "";
    public WireGuardCred wireguard { get; set; } = new();
    public Dictionary<string, int> ports { get; set; } = new();
    public Dictionary<string, string> skipped { get; set; } = new();
}

public sealed class RealityCred
{
    public string public_key { get; set; } = "";
    public string short_id { get; set; } = "";
    public string server_name { get; set; } = "www.cloudflare.com";
}

public sealed class WireGuardCred
{
    public string server_public { get; set; } = "";
    public string client_private { get; set; } = "";
    public string client_public { get; set; } = "";
    public int listen_port { get; set; }
    public string address_server { get; set; } = "";
    public string address_client { get; set; } = "";
}
