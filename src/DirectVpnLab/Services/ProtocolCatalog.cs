using DirectVpnLab.Models;
using System.Text.Json;

namespace DirectVpnLab.Services;

public static class ProtocolCatalog
{
    public static LabCredentials LoadCredentials()
    {
        var json = File.ReadAllText(AppPaths.CredentialsPath);
        var cred = JsonSerializer.Deserialize<LabCredentials>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        }) ?? throw new InvalidOperationException("Invalid credentials.json");
        if (string.IsNullOrWhiteSpace(cred.server_ip))
        {
            throw new InvalidOperationException("credentials missing server_ip");
        }
        return cred;
    }

    public static IReadOnlyList<ProtocolMethod> BuildMethods(LabCredentials cred)
    {
        var p = cred.ports;
        var list = new List<ProtocolMethod>
        {
            M("A01", "VLESS", "REALITY", p, "A01_vless_reality", "tcp"),
            M("A02", "VLESS", "TLS", p, "A02_vless_tls", "tcp"),
            M("A03", "VLESS", "WebSocket+TLS", p, "A03_vless_ws_tls", "tcp"),
            M("A04", "VLESS", "gRPC+TLS", p, "A04_vless_grpc_tls", "tcp"),
            M("A05", "VLESS", "HTTPUpgrade+TLS", p, "A05_vless_httpupgrade_tls", "tcp"),
            M("B01", "Trojan", "TLS", p, "B01_trojan_tls", "tcp"),
            M("B02", "Trojan", "WebSocket+TLS", p, "B02_trojan_ws_tls", "tcp"),
            M("B03", "Trojan", "gRPC+TLS", p, "B03_trojan_grpc_tls", "tcp"),
            M("B04", "VMess", "TCP+TLS", p, "B04_vmess_tcp_tls", "tcp"),
            M("B05", "VMess", "WebSocket+TLS", p, "B05_vmess_ws_tls", "tcp"),
            M("B06", "VMess", "gRPC+TLS", p, "B06_vmess_grpc_tls", "tcp"),
            M("C01", "Shadowsocks", "AEAD-2022", p, "C01_ss2022", "tcp"),
            M("C02", "Shadowsocks", "ShadowTLS-v3", p, "C02_shadowtls", "tcp"),
            M("C03", "AnyTLS", "TLS", p, "C03_anytls", "tcp"),
            M("D01", "NaiveProxy", "HTTP/2", p, "D01_naive_h2", "tcp"),
            M("D02", "NaiveProxy", "QUIC/HTTP3", p, "D02_naive_quic", "udp"),
            M("E01", "Hysteria2", "UDP/QUIC", p, "E01_hysteria2", "udp"),
            M("E02", "Hysteria2", "Obfs-Salamander", p, "E02_hysteria2_obfs", "udp"),
            M("E03", "TUIC", "QUIC", p, "E03_tuic", "udp"),
            M("E04", "WireGuard", "Endpoint", p, "E04_wireguard", "udp"),
            new ProtocolMethod
            {
                Id = "F01", Protocol = "MASQUE", Transport = "HTTP/2", Port = 0, Network = "tcp",
                SkipReason = cred.skipped.GetValueOrDefault("F01_masque_h2", "Requires sing-box >= 1.15.0"),
                Status = TestStatus.Skipped
            },
            new ProtocolMethod
            {
                Id = "F02", Protocol = "MASQUE", Transport = "HTTP/3", Port = 0, Network = "udp",
                SkipReason = cred.skipped.GetValueOrDefault("F02_masque_h3", "Requires sing-box >= 1.15.0"),
                Status = TestStatus.Skipped
            },
            M("F03", "OpenVPN", "TCP", p, "F03_openvpn_tcp", "tcp"),
            M("F04", "OpenVPN", "UDP", p, "F04_openvpn_udp", "udp"),
        };
        return list;
    }

    private static ProtocolMethod M(string id, string protocol, string transport, Dictionary<string, int> ports, string key, string network)
    {
        if (!ports.TryGetValue(key, out var port))
        {
            return new ProtocolMethod
            {
                Id = id,
                Protocol = protocol,
                Transport = transport,
                Port = 0,
                Network = network,
                SkipReason = $"Port key missing: {key}",
                Status = TestStatus.Skipped
            };
        }
        return new ProtocolMethod
        {
            Id = id,
            Protocol = protocol,
            Transport = transport,
            Port = port,
            Network = network
        };
    }
}
