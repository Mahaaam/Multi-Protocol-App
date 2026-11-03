using System.Diagnostics;
using System.Text;

namespace DirectVpnLab.Services;

public sealed class SingBoxProcess : IAsyncDisposable
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
        var wintunTarget = Path.Combine(exeDir, "wintun.dll");
        if (!File.Exists(wintunTarget) && File.Exists(AppPaths.WintunDll))
        {
            File.Copy(AppPaths.WintunDll, wintunTarget, true);
        }

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
                _log.Info($"sing-box: {e.Data}");
            }
        };
        _process.ErrorDataReceived += (_, e) =>
        {
            if (string.IsNullOrWhiteSpace(e.Data)) return;
            lock (_stderr) _stderr.AppendLine(e.Data);
            _log.Warn($"sing-box: {e.Data}");
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
}
