using System.Collections.ObjectModel;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Threading;

namespace DirectVpnLab.Services;

public sealed partial class LiveLogService
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
            return Sanitize(_all.ToString());
        }
    }

    public static string Sanitize(string message)
    {
        if (string.IsNullOrEmpty(message)) return message;
        var m = StripAnsi(message);

        // key=value / key: value for sensitive keys
        m = SensitiveKvRegex().Replace(m, "$1=[REDACTED]");
        // PEM blocks
        m = PemRegex().Replace(m, "[REDACTED_PEM]");
        // Long base64-looking tokens (keys/passwords)
        m = LongSecretRegex().Replace(m, "[REDACTED]");
        // UUID literals when labeled nearby already handled; also bare bearer tokens
        m = BearerRegex().Replace(m, "Bearer [REDACTED]");
        return m;
    }

    private static string StripAnsi(string input) =>
        AnsiRegex().Replace(input, "");

    [GeneratedRegex(@"\x1B\[[0-9;]*[mK]|\x1B\][^\x07]*\x07|\x1B[@-Z\\-_]", RegexOptions.Compiled)]
    private static partial Regex AnsiRegex();

    [GeneratedRegex(
        @"(?i)\b(password|passwd|pwd|token|secret|credential|api[_-]?key|private[_-]?key|privateKey|uuid|authorization)\b\s*([:=]\s*)([^\s,;""']+)",
        RegexOptions.Compiled)]
    private static partial Regex SensitiveKvRegex();

    [GeneratedRegex(
        @"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        RegexOptions.Compiled)]
    private static partial Regex PemRegex();

    [GeneratedRegex(
        @"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b",
        RegexOptions.Compiled)]
    private static partial Regex LongSecretRegex();

    [GeneratedRegex(
        @"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*",
        RegexOptions.Compiled)]
    private static partial Regex BearerRegex();
}
