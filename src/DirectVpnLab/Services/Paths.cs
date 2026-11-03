using System.IO;
using System.Reflection;

namespace DirectVpnLab.Services;

public static class AppPaths
{
    /// <summary>
    /// Optional LocalAppData subfolder override (e.g. Mobile Diagnostic).
    /// Null = default "DirectVpnLab". Main app must leave this unset.
    /// </summary>
    public static string? RuntimeFolderNameOverride { get; set; }

    public static string BaseDir =>
        Path.GetDirectoryName(Environment.ProcessPath)
        ?? AppContext.BaseDirectory;

    public static string RuntimeDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        string.IsNullOrWhiteSpace(RuntimeFolderNameOverride) ? "DirectVpnLab" : RuntimeFolderNameOverride);

    public static string WorkDir => Path.Combine(RuntimeDir, "work");
    public static string LogDir => Path.Combine(RuntimeDir, "logs");
    public static string StateDir => Path.Combine(RuntimeDir, "state");

    public static string SingBoxExe => FirstExisting(
        Path.Combine(BaseDir, "Assets", "sing-box", "sing-box.exe"),
        Path.Combine(BaseDir, "sing-box.exe"),
        Path.Combine(BaseDir, "Assets", "sing-box.exe"));

    public static string WintunDll => FirstExisting(
        Path.Combine(BaseDir, "Assets", "sing-box", "wintun.dll"),
        Path.Combine(BaseDir, "wintun.dll"));

    public static string LibCronetDll => FirstExisting(
        Path.Combine(BaseDir, "Assets", "sing-box", "libcronet.dll"),
        Path.Combine(BaseDir, "libcronet.dll"));

    public static string CredentialsPath => FirstExisting(
        Path.Combine(BaseDir, "Assets", "certs", "credentials.json"),
        Path.Combine(BaseDir, "credentials.json"));

    public static string CaCertPath => FirstExisting(
        Path.Combine(BaseDir, "Assets", "certs", "ca.crt"),
        Path.Combine(BaseDir, "ca.crt"));

    public static string ClientCertPath => FirstExisting(
        Path.Combine(BaseDir, "Assets", "certs", "client.crt"));

    public static string ClientKeyPath => FirstExisting(
        Path.Combine(BaseDir, "Assets", "certs", "client.key"));

    public static void EnsureDirs()
    {
        Directory.CreateDirectory(RuntimeDir);
        Directory.CreateDirectory(WorkDir);
        Directory.CreateDirectory(LogDir);
        Directory.CreateDirectory(StateDir);
    }

    private static string FirstExisting(params string[] paths)
    {
        foreach (var p in paths)
        {
            if (!string.IsNullOrWhiteSpace(p) && File.Exists(p))
            {
                return p;
            }
        }
        return paths[0];
    }
}
