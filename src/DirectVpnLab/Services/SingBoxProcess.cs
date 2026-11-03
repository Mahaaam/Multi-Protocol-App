using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace DirectVpnLab.Services;

public sealed partial class SingBoxProcess : IAsyncDisposable
{
    private Process? _process;
    private readonly LiveLogService _log;
    private readonly StringBuilder _stderr = new();

    public SingBoxProcess(LiveLogService log)
    {
        _log = log;
    }

    public bool IsRunning => _process is { HasExited: false };
    public int? ProcessId => _process is { HasExited: false } ? _process.Id : null;
    public string? ExecutablePath { get; private set; }
    public DateTime? StartedAtUtc { get; private set; }
    public string? ConfigPath { get; private set; }

    public string StderrSnapshot
    {
        get
        {
            lock (_stderr) return _stderr.ToString();
        }
    }

    public async Task StartAsync(string configPath, CancellationToken ct = default)
    {
        await StopAsync();
        if (!File.Exists(AppPaths.SingBoxExe))
        {
            throw new FileNotFoundException("sing-box.exe not found", AppPaths.SingBoxExe);
        }

        var exeDir = Path.GetDirectoryName(AppPaths.SingBoxExe)!;
        EnsureSidecar(AppPaths.WintunDll, Path.Combine(exeDir, "wintun.dll"));
        EnsureSidecar(AppPaths.LibCronetDll, Path.Combine(exeDir, "libcronet.dll"));

        ConfigPath = Path.GetFullPath(configPath);
        var psi = new ProcessStartInfo
        {
            FileName = AppPaths.SingBoxExe,
            Arguments = $"run -c \"{ConfigPath}\"",
            WorkingDirectory = exeDir,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        _process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        _process.OutputDataReceived += (_, e) =>
        {
            if (!string.IsNullOrWhiteSpace(e.Data))
            {
                RouteSingBoxLine(e.Data);
            }
        };
        _process.ErrorDataReceived += (_, e) =>
        {
            if (string.IsNullOrWhiteSpace(e.Data)) return;
            var clean = StripAnsi(e.Data);
            lock (_stderr) _stderr.AppendLine(clean);
            RouteSingBoxLine(clean);
        };

        if (!_process.Start())
        {
            throw new InvalidOperationException("Failed to start sing-box");
        }

        StartedAtUtc = DateTime.UtcNow;
        try
        {
            ExecutablePath = Path.GetFullPath(_process.MainModule?.FileName ?? AppPaths.SingBoxExe);
        }
        catch
        {
            ExecutablePath = Path.GetFullPath(AppPaths.SingBoxExe);
        }

        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();

        await Task.Delay(700, ct);
        if (_process.HasExited)
        {
            throw new InvalidOperationException($"sing-box exited early code={_process.ExitCode}. {StderrSnapshot}");
        }
    }

    private void RouteSingBoxLine(string raw)
    {
        var line = StripAnsi(raw).Trim();
        if (string.IsNullOrWhiteSpace(line)) return;

        // sing-box often writes all levels to stderr — classify by content
        if (ContainsLevel(line, "FATAL") || ContainsLevel(line, "ERROR"))
        {
            _log.Error($"sing-box: {line}");
        }
        else if (ContainsLevel(line, "WARN") || ContainsLevel(line, "WARNING"))
        {
            _log.Warn($"sing-box: {line}");
        }
        else
        {
            _log.Info($"sing-box: {line}");
        }
    }

    private static bool ContainsLevel(string line, string level) =>
        line.Contains($"[{level}]", StringComparison.OrdinalIgnoreCase) ||
        line.Contains($"{level}[", StringComparison.OrdinalIgnoreCase) ||
        Regex.IsMatch(line, $@"\b{level}\b", RegexOptions.IgnoreCase);

    private static void EnsureSidecar(string source, string target)
    {
        try
        {
            if (File.Exists(source) &&
                (!File.Exists(target) || new FileInfo(source).Length != new FileInfo(target).Length))
            {
                File.Copy(source, target, true);
            }
        }
        catch
        {
            // non-fatal; caller may still fail later with clearer message
        }
    }

    public async Task StopAsync()
    {
        var p = _process;
        _process = null;
        ExecutablePath = null;
        StartedAtUtc = null;
        ConfigPath = null;
        if (p == null) return;
        try
        {
            if (!p.HasExited)
            {
                p.Kill(entireProcessTree: true);
                await p.WaitForExitAsync();
            }
        }
        catch
        {
            // ignore cleanup races
        }
        finally
        {
            p.Dispose();
        }
    }

    public async ValueTask DisposeAsync() => await StopAsync();

    [GeneratedRegex(@"\x1B\[[0-9;]*[mK]|\x1B\][^\x07]*\x07|\x1B[@-Z\\-_]", RegexOptions.Compiled)]
    private static partial Regex AnsiRegex();

    internal static string StripAnsi(string input) =>
        string.IsNullOrEmpty(input) ? input : AnsiRegex().Replace(input, "");
}
