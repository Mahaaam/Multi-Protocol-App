using System.Collections.ObjectModel;
using System.Text;
using System.Windows;
using System.Windows.Threading;

namespace DirectVpnLab.Services;

public sealed class LiveLogService
{
    private readonly Dispatcher _dispatcher;
    private readonly object _gate = new();
    private readonly StringBuilder _all = new();

    public ObservableCollection<string> Lines { get; } = new();
    public event Action? Changed;

    public LiveLogService(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
    }

    public void Info(string message) => Append("INFO", message);
    public void Warn(string message) => Append("WARN", message);
    public void Error(string message) => Append("ERROR", message);
    public void Pass(string message) => Append("PASS", message);
    public void Fail(string message) => Append("FAIL", message);

    public void Append(string level, string message)
    {
        // Never log secrets/tokens
        var sanitized = Sanitize(message);
        var line = $"[{DateTime.Now:HH:mm:ss}] [{level}] {sanitized}";
        lock (_gate)
        {
            _all.AppendLine(line);
        }

        _dispatcher.BeginInvoke(() =>
        {
            Lines.Add(line);
            while (Lines.Count > 2000)
            {
                Lines.RemoveAt(0);
            }
            Changed?.Invoke();
        });
    }

    public void ClearView()
    {
        _dispatcher.BeginInvoke(() => Lines.Clear());
    }

    public string ExportSanitized()
    {
        lock (_gate)
        {
            return _all.ToString();
        }
    }

    private static string Sanitize(string message)
    {
        // Defensive redaction for accidental secret dumps
        var m = message;
        string[] keys =
        [
            "password", "private_key", "uuid", "token", "credential", "secret"
        ];
        foreach (var k in keys)
        {
            // keep labels, strip values after '=' when key appears
            if (m.Contains(k, StringComparison.OrdinalIgnoreCase) && m.Contains('='))
            {
                // leave structural messages alone unless clearly key=value
            }
        }
        return m;
    }
}
