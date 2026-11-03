using System.Windows;
using DirectVpnLab.Services;

namespace DirectVpnLab.MobileDiagnostic;

public partial class MainWindow : Window
{
    private readonly LiveLogService _log;
    private readonly MobileDiagnosticEngine _engine;
    private PathCheckResult? _lastPath;
    private CancellationTokenSource? _runCts;
    private bool _busy;

    public MainWindow()
    {
        InitializeComponent();
        _log = new LiveLogService(Dispatcher);
        _engine = new MobileDiagnosticEngine(_log);
        _log.Changed += () => Dispatcher.BeginInvoke(SyncLog);
        Closing += (_, _) =>
        {
            try { _engine.CancelAndCleanupAsync().GetAwaiter().GetResult(); } catch { /* ignore on close */ }
        };
        try
        {
            _engine.EnsureReady();
            _log.Info($"Ready {MobileDiagnosticEngine.AppVersion}");
            _log.Info($"RuntimeDir → {AppPaths.RuntimeDir}");
            _log.Info($"Reports → {MobileDiagnosticEngine.ReportsDir}");
            _log.Info("Admin NOT required (PROXY-ONLY / asInvoker). Do not change WireGuard from this tool.");
            _log.Warn("LOCAL ONLY — publish folder may contain credentials/keys; do not redistribute.");
        }
        catch (Exception ex)
        {
            _log.Error(ex.Message);
            MessageBox.Show(this, ex.Message, "Startup", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SyncLog()
    {
        LogList.Items.Clear();
        foreach (var line in _log.Lines)
            LogList.Items.Add(line);
        if (LogList.Items.Count > 0)
            LogList.ScrollIntoView(LogList.Items[^1]);
    }

    private async void Check_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        SetBusy(true);
        ValPhase.Text = "CHECK NETWORK…";
        try
        {
            await Task.Run(() =>
            {
                _lastPath = _engine.CheckNetwork();
            }).ConfigureAwait(true);

            ApplyPathToUi(_lastPath!);
            ValPhase.Text = _lastPath!.PathOk
                ? "Path OK — you may START C01 TEST"
                : "Path blocked — fix WG / retry CHECK";
            if (!string.IsNullOrWhiteSpace(_lastPath.BlockReason))
                _log.Warn(_lastPath.BlockReason);
            _log.Info(
                $"CHECK: PathOk={_lastPath.PathOk} public={_lastPath.PublicIpv4} " +
                $"if={_lastPath.EffectiveInterface} hop={_lastPath.EffectiveNextHop}");
        }
        catch (Exception ex)
        {
            _log.Error(ex.Message);
            ValPhase.Text = "CHECK failed";
            BtnStart.IsEnabled = false;
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void ApplyPathToUi(PathCheckResult p)
    {
        ValAdapter.Text = p.NetworkAdapter;
        ValRoute.Text =
            p.DefaultRoute + "\n→ " + p.EffectiveToServer +
            $"\n(if={p.EffectiveInterface} hop={p.EffectiveNextHop} gw={p.Gateway})";
        ValPublicIp.Text = p.PublicIpv4 is "UNKNOWN" || p.PublicIpv4.StartsWith("A=", StringComparison.Ordinal)
            ? $"{p.PublicIpv4} (A={p.PublicIpv4A}; B={p.PublicIpv4B})"
            : p.PublicIpv4;
        ValMobile.Text = p.MobileNetworkStatus;
        BtnStart.IsEnabled = p.PathOk;
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;

        SetBusy(true);
        BtnSave.IsEnabled = false;
        ValPhase.Text = "Re-checking path before START…";
        _runCts = null;
        try
        {
            // Fresh CHECK at START — ignore stale PathOk from earlier CHECK.
            await Task.Run(() => { _lastPath = _engine.CheckNetwork(); }).ConfigureAwait(true);
            var pathNow = _lastPath ?? throw new InvalidOperationException("path check returned null");
            ApplyPathToUi(pathNow);
            if (!pathNow.PathOk)
            {
                MessageBox.Show(this,
                    "Path not OK on re-check. Deactivate WG and confirm Wi-Fi/gateway to NL, then CHECK again.\n" +
                    pathNow.MobileNetworkStatus,
                    "Blocked", MessageBoxButton.OK, MessageBoxImage.Warning);
                ValPhase.Text = "START blocked — path re-check failed";
                return;
            }

            ValDlStatus.Text = "RUNNING";
            ValProgress.Text = "0 / 262144";
            ValSpeed.Text = "—";
            ValExitIp.Text = "—";
            ValTcp.Text = "…";
            ValCleanup.Text = "—";
            _runCts = new CancellationTokenSource();

            var report = await _engine.RunC01TestAsync(
                _lastPath,
                status => Dispatcher.BeginInvoke(() => ValPhase.Text = status),
                (got, target, mbps) => Dispatcher.BeginInvoke(() =>
                {
                    ValProgress.Text = $"{got} / {target}";
                    ValSpeed.Text = $"{mbps:F2} Mbps";
                }),
                _runCts.Token).ConfigureAwait(true);

            ValTcp.Text = report.TcpConnectionResult;
            ValExitIp.Text = string.IsNullOrWhiteSpace(report.ConfirmedExitIp) ? "—" : report.ConfirmedExitIp;
            ValProgress.Text = $"{report.BytesReceived} / 262144";
            ValDlStatus.Text = report.ProxyDownloadResult;
            ValCleanup.Text = report.CleanupResult;
            ValPhase.Text = report.Summary;
            BtnSave.IsEnabled = true;
            _log.Info($"Saved auto report for {report.RunId}");
        }
        catch (OperationCanceledException)
        {
            ValDlStatus.Text = "CANCELLED";
            ValPhase.Text = "Cancelled";
            var clean = await _engine.CancelAndCleanupAsync().ConfigureAwait(true);
            ValCleanup.Text = clean;
            BtnSave.IsEnabled = _engine.LastReport != null;
        }
        catch (Exception ex)
        {
            ValDlStatus.Text = "FAIL";
            ValPhase.Text = ex.Message;
            _log.Error(ex.Message);
            var clean = await _engine.CancelAndCleanupAsync().ConfigureAwait(true);
            ValCleanup.Text = clean;
            BtnSave.IsEnabled = _engine.LastReport != null;
        }
        finally
        {
            _runCts?.Dispose();
            _runCts = null;
            SetBusy(false);
            BtnStart.IsEnabled = _lastPath is { PathOk: true };
        }
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var (json, txt) = _engine.SaveReport();
            _log.Info($"SAVE REPORT: {json}");
            _log.Info($"SAVE REPORT: {txt}");
            ValPhase.Text = "Report saved";
            MessageBox.Show(this, $"JSON:\n{json}\n\nTXT:\n{txt}", "Saved", MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Save failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _runCts?.Cancel();
        var clean = await _engine.CancelAndCleanupAsync().ConfigureAwait(true);
        ValCleanup.Text = clean;
        ValPhase.Text = "Cancel/cleanup requested";
        _log.Warn("CANCEL — " + clean);
        if (_engine.LastReport != null)
            BtnSave.IsEnabled = true;
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        BtnCheck.IsEnabled = !busy;
        BtnStart.IsEnabled = !busy && _lastPath is { PathOk: true };
        BtnCancel.IsEnabled = true;
    }
}
