using System.Text.Json;
using System.Text.Json.Nodes;
using DirectVpnLab.Models;

namespace DirectVpnLab.Services;

public static class ConfigFactory
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true
    };

    public static string BuildDiscoveryConfig(LabCredentials cred, ProtocolMethod method, int localMixedPort, string workDir)
    {
        var outbound = BuildOutbound(cred, method)
            ?? throw new InvalidOperationException($"No outbound builder for {method.Id}");

        var root = new JsonObject
        {
            ["log"] = new JsonObject { ["level"] = "info", ["timestamp"] = true },
            ["inbounds"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "mixed",
                    ["tag"] = "mixed-in",
                    ["listen"] = "127.0.0.1",
                    ["listen_port"] = localMixedPort
                }
            },
            ["outbounds"] = new JsonArray
            {
                outbound,
                new JsonObject { ["type"] = "direct", ["tag"] = "direct" }
            },
            ["route"] = new JsonObject { ["final"] = "proxy" }
        };

        // Client chain: Shadowsocks (payload) -> ShadowTLS (detour/transport)
        if (method.Id == "C02")
        {
            root["outbounds"] = new JsonArray
            {
                BuildSsOverShadowTls(cred),
                BuildShadowTlsOutbound(cred),
                new JsonObject { ["type"] = "direct", ["tag"] = "direct" }
            };
        }

        var path = Path.Combine(workDir, $"discover-{method.Id}.json");
        File.WriteAllText(path, root.ToJsonString(JsonOpts));
        return path;
    }

    public static string BuildTunConfig(LabCredentials cred, ProtocolMethod method, string workDir)
    {
        JsonNode proxyOutbound = method.Id == "C02"
            ? BuildSsOverShadowTls(cred)
            : BuildOutbound(cred, method)!;

        var outbounds = new JsonArray
        {
            proxyOutbound,
            new JsonObject { ["type"] = "direct", ["tag"] = "direct" }
        };
        if (method.Id == "C02")
        {
            outbounds.Insert(1, BuildShadowTlsOutbound(cred));
        }

        // WireGuard / OpenVPN use endpoints on client too
        JsonArray? endpoints = null;
        if (method.Id is "E04" or "F03" or "F04")
        {
            endpoints = new JsonArray { BuildClientEndpoint(cred, method) };
            // route via endpoint tag
            outbounds = new JsonArray
            {
                new JsonObject { ["type"] = "direct", ["tag"] = "direct" }
            };
        }

        var root = new JsonObject
        {
            ["log"] = new JsonObject
            {
                ["level"] = "info",
                ["timestamp"] = true,
                ["output"] = Path.Combine(AppPaths.LogDir, "tun-sing-box.log")
            },
            ["inbounds"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "tun",
                    ["tag"] = "tun-in",
                    ["interface_name"] = "DirectVpnLab",
                    ["address"] = new JsonArray { "172.19.0.1/30" },
                    ["mtu"] = 1400,
                    ["auto_route"] = true,
                    ["strict_route"] = true,
                    ["stack"] = "mixed",
                    ["sniff"] = true
                }
            },
            ["outbounds"] = outbounds,
            ["route"] = new JsonObject
            {
                ["auto_detect_interface"] = true,
                ["final"] = method.Id is "E04" or "F03" or "F04" ? method.Id : "proxy",
                ["default_domain_resolver"] = "local"
            },
            ["dns"] = new JsonObject
            {
                ["servers"] = new JsonArray
                {
                    new JsonObject { ["type"] = "udp", ["tag"] = "dns-remote", ["server"] = "1.1.1.1" },
                    new JsonObject { ["type"] = "local", ["tag"] = "local" }
                },
                ["final"] = "dns-remote",
                ["strategy"] = "prefer_ipv4"
            }
        };

        if (endpoints != null)
        {
            root["endpoints"] = endpoints;
        }

        var path = Path.Combine(workDir, $"tun-{method.Id}.json");
        File.WriteAllText(path, root.ToJsonString(JsonOpts));
        return path;
    }

    private static JsonObject TlsClient()
    {
        return new JsonObject
        {
            ["enabled"] = true,
            ["server_name"] = "direct-vpn-lab.internal",
            ["certificate_path"] = AppPaths.CaCertPath.Replace('\\', '/')
        };
    }

    private static JsonObject? BuildOutbound(LabCredentials c, ProtocolMethod m)
    {
        var host = c.server_ip;
        return m.Id switch
        {
            "A01" => new JsonObject
            {
                ["type"] = "vless",
                ["tag"] = "proxy",
                ["server"] = host,
                ["server_port"] = m.Port,
                ["uuid"] = c.vless_uuid,
                ["flow"] = "xtls-rprx-vision",
                ["tls"] = new JsonObject
                {
                    ["enabled"] = true,
                    ["server_name"] = c.reality.server_name,
                    ["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = "chrome" },
                    ["reality"] = new JsonObject
                    {
                        ["enabled"] = true,
                        ["public_key"] = c.reality.public_key,
                        ["short_id"] = c.reality.short_id
                    }
                }
            },
            "A02" => Vless(c, m, null),
            "A03" => Vless(c, m, new JsonObject { ["type"] = "ws", ["path"] = "/dvpn-ws" }),
            "A04" => Vless(c, m, new JsonObject { ["type"] = "grpc", ["service_name"] = "dvpn-grpc" }),
            "A05" => Vless(c, m, new JsonObject { ["type"] = "httpupgrade", ["path"] = "/dvpn-hu" }),
            "B01" => Trojan(c, m, null),
            "B02" => Trojan(c, m, new JsonObject { ["type"] = "ws", ["path"] = "/dvpn-tr-ws" }),
            "B03" => Trojan(c, m, new JsonObject { ["type"] = "grpc", ["service_name"] = "dvpn-tr-grpc" }),
            "B04" => Vmess(c, m, null),
            "B05" => Vmess(c, m, new JsonObject { ["type"] = "ws", ["path"] = "/dvpn-vm-ws" }),
            "B06" => Vmess(c, m, new JsonObject { ["type"] = "grpc", ["service_name"] = "dvpn-vm-grpc" }),
            "C01" => new JsonObject
            {
                ["type"] = "shadowsocks",
                ["tag"] = "proxy",
                ["server"] = host,
                ["server_port"] = m.Port,
                ["method"] = c.ss2022_method,
                ["password"] = c.ss2022_password
            },
            "C03" => new JsonObject
            {
                ["type"] = "anytls",
                ["tag"] = "proxy",
                ["server"] = host,
                ["server_port"] = m.Port,
                ["password"] = c.anytls_password,
                ["tls"] = TlsClient()
            },
            "D01" => new JsonObject
            {
                ["type"] = "naive",
                ["tag"] = "proxy",
                ["server"] = host,
                ["server_port"] = m.Port,
                ["username"] = c.naive_username,
                ["password"] = c.naive_password,
                ["tls"] = TlsClient()
            },
            "D02" => new JsonObject
            {
                ["type"] = "naive",
                ["tag"] = "proxy",
                ["server"] = host,
                ["server_port"] = m.Port,
                ["username"] = c.naive_username,
                ["password"] = c.naive_password,
                ["quic"] = true,
                ["tls"] = TlsClient()
            },
            "E01" => new JsonObject
            {
                ["type"] = "hysteria2",
                ["tag"] = "proxy",
                ["server"] = host,
                ["server_port"] = m.Port,
                ["password"] = c.hysteria2_password,
                ["tls"] = TlsClient()
            },
            "E02" => new JsonObject
            {
                ["type"] = "hysteria2",
                ["tag"] = "proxy",
                ["server"] = host,
                ["server_port"] = m.Port,
                ["password"] = c.hysteria2_password,
                ["obfs"] = new JsonObject
                {
                    ["type"] = "salamander",
                    ["password"] = c.hysteria2_obfs_password
                },
                ["tls"] = TlsClient()
            },
            "E03" => new JsonObject
            {
                ["type"] = "tuic",
                ["tag"] = "proxy",
                ["server"] = host,
                ["server_port"] = m.Port,
                ["uuid"] = c.tuic_uuid,
                ["password"] = c.trojan_password,
                ["congestion_control"] = "bbr",
                ["tls"] = new JsonObject
                {
                    ["enabled"] = true,
                    ["server_name"] = "direct-vpn-lab.internal",
                    ["alpn"] = new JsonArray { "h3" },
                    ["certificate_path"] = AppPaths.CaCertPath.Replace('\\', '/')
                }
            },
            "E04" or "F03" or "F04" => null, // endpoints
            "C02" => null, // special chain
            _ => null
        };

        JsonObject Vless(LabCredentials cred, ProtocolMethod method, JsonObject? transport)
        {
            var o = new JsonObject
            {
                ["type"] = "vless",
                ["tag"] = "proxy",
                ["server"] = cred.server_ip,
                ["server_port"] = method.Port,
                ["uuid"] = cred.vless_uuid,
                ["tls"] = TlsClient()
            };
            if (transport != null) o["transport"] = transport;
            return o;
        }

        JsonObject Trojan(LabCredentials cred, ProtocolMethod method, JsonObject? transport)
        {
            var o = new JsonObject
            {
                ["type"] = "trojan",
                ["tag"] = "proxy",
                ["server"] = cred.server_ip,
                ["server_port"] = method.Port,
                ["password"] = cred.trojan_password,
                ["tls"] = TlsClient()
            };
            if (transport != null) o["transport"] = transport;
            return o;
        }

        JsonObject Vmess(LabCredentials cred, ProtocolMethod method, JsonObject? transport)
        {
            var o = new JsonObject
            {
                ["type"] = "vmess",
                ["tag"] = "proxy",
                ["server"] = cred.server_ip,
                ["server_port"] = method.Port,
                ["uuid"] = cred.vmess_uuid,
                ["security"] = "auto",
                ["tls"] = TlsClient()
            };
            if (transport != null) o["transport"] = transport;
            return o;
        }
    }

    private static JsonObject BuildSsOverShadowTls(LabCredentials c)
    {
        return new JsonObject
        {
            ["type"] = "shadowsocks",
            ["tag"] = "proxy",
            ["server"] = c.server_ip,
            ["server_port"] = c.ports["C02_shadowtls"],
            ["method"] = c.ss_inner_method,
            ["password"] = c.ss_inner_password,
            ["detour"] = "shadowtls-out"
        };
    }

    private static JsonObject BuildShadowTlsOutbound(LabCredentials c)
    {
        return new JsonObject
        {
            ["type"] = "shadowtls",
            ["tag"] = "shadowtls-out",
            ["server"] = c.server_ip,
            ["server_port"] = c.ports["C02_shadowtls"],
            ["version"] = 3,
            ["password"] = c.shadowtls_password,
            ["tls"] = new JsonObject
            {
                ["enabled"] = true,
                ["server_name"] = "www.microsoft.com"
            }
        };
    }

    private static JsonObject BuildClientEndpoint(LabCredentials c, ProtocolMethod m)
    {
        if (m.Id == "E04")
        {
            return new JsonObject
            {
                ["type"] = "wireguard",
                ["tag"] = "E04",
                ["system"] = false,
                ["mtu"] = 1280,
                ["address"] = new JsonArray { c.wireguard.address_client },
                ["private_key"] = c.wireguard.client_private,
                ["peers"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["address"] = c.server_ip,
                        ["port"] = m.Port,
                        ["public_key"] = c.wireguard.server_public,
                        ["allowed_ips"] = new JsonArray { "0.0.0.0/0" },
                        ["persistent_keepalive_interval"] = 25
                    }
                }
            };
        }

        var network = m.Id == "F03" ? "tcp" : "udp";
        return new JsonObject
        {
            ["type"] = "openvpn-client",
            ["tag"] = m.Id,
            ["system"] = false,
            ["network"] = network,
            ["server"] = c.server_ip,
            ["server_port"] = m.Port,
            ["username"] = c.openvpn_username,
            ["password"] = c.openvpn_password,
            ["tls"] = new JsonObject
            {
                ["certificate_path"] = AppPaths.CaCertPath.Replace('\\', '/'),
                // lab uses user/pass; server verify_client_certificate=none
            }
        };
    }
}
