using System.ComponentModel;
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
    private bool _closeAllowed;
    private bool _closeCleanupStarted;

    public MainWindow()
    {
        InitializeComponent();
        _log = new LiveLogService(Dispatcher);
        _engine = new MobileDiagnosticEngine(_log);
        _log.Changed += () => Dispatcher.BeginInvoke(SyncLog);
        Closing += OnClosingLifecycle;
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

    private void OnClosingLifecycle(object? sender, CancelEventArgs e)
    {
        if (_closeAllowed)
            return;

        // Cancel close now; finish cleanup asynchronously, then Close() once.
        e.Cancel = true;
        if (_closeCleanupStarted)
            return;

        _closeCleanupStarted = true;
        _runCts?.Cancel();
        ValPhase.Text = "Closing — cleanup in progress…";
        _ = FinishCloseAsync();
    }

    private async Task FinishCloseAsync()
    {
        string cleanup;
        try
        {
            cleanup = await _engine.CancelAndCleanupAsync().ConfigureAwait(true);
            if (cleanup.StartsWith("FAIL", StringComparison.OrdinalIgnoreCase))
            {
                _log.Error("Close cleanup failed: " + cleanup);
                ValCleanup.Text = cleanup;
            }
            else
            {
                _log.Info("Close cleanup: " + cleanup);
                ValCleanup.Text = cleanup;
            }

            // If a run was in progress without finalize, persist CANCELLED partial for active runId.
            if (_engine.ActiveRunId != null &&
                _engine.LastReport != null &&
                string.Equals(_engine.LastReport.Summary, "IN_PROGRESS — network test not finished",
                    StringComparison.Ordinal))
            {
                _engine.FinalizeCurrentRun(
                    summary: "CANCELLED — window closed before test finished",
                    errorClassification: "CANCELLED",
                    cleanupResult: cleanup,
                    path: _lastPath,
                    tcp: "NOT_RUN",
                    direct: "NOT_RUN",
                    proxy: "NOT_RUN",
                    bytes: _engine.LastReport.BytesReceived);
            }
        }
        catch (Exception ex)
        {
            _log.Error("Close cleanup exception: " + ex.Message);
            ValCleanup.Text = "FAIL: " + ex.Message;
        }
        finally
        {
            _closeAllowed = true;
            // Safe re-entry: Closing will see _closeAllowed and proceed.
            Close();
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

        // New run identity immediately — supersedes any previous report.
        var begun = _engine.BeginRun(_lastPath);
        _log.Info($"START runId={begun.RunId}");

        try
        {
            await Task.Run(() => { _lastPath = _engine.CheckNetwork(); }).ConfigureAwait(true);
            var pathNow = _lastPath ?? throw new InvalidOperationException("path check returned null");
            ApplyPathToUi(pathNow);
            if (!pathNow.PathOk)
            {
                var denied = _engine.FinalizeCurrentRun(
                    summary: pathNow.MobileNetworkStatus,
                    errorClassification: "PATH_NOT_DIRECT",
                    cleanupResult: "n/a — test not started",
                    path: pathNow,
                    tcp: "NOT_RUN",
                    direct: "NOT_RUN",
                    proxy: "NOT_RUN",
                    hypothesis: pathNow.BlockReason);
                ApplyReportToUi(denied);
                MessageBox.Show(this,
                    "Path not OK on re-check. Deactivate WG and confirm Wi-Fi/gateway to NL, then CHECK again.\n" +
                    pathNow.MobileNetworkStatus,
                    "Blocked", MessageBoxButton.OK, MessageBoxImage.Warning);
                ValPhase.Text = "START blocked — path re-check failed (report saved)";
                BtnSave.IsEnabled = true;
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
                pathNow,
                status => Dispatcher.BeginInvoke(() => ValPhase.Text = status),
                (got, target, mbps) => Dispatcher.BeginInvoke(() =>
                {
                    ValProgress.Text = $"{got} / {target}";
                    ValSpeed.Text = $"{mbps:F2} Mbps";
                }),
                _runCts.Token).ConfigureAwait(true);

            ApplyReportToUi(report);
            BtnSave.IsEnabled = true;
            _log.Info($"Saved auto report for {report.RunId}");
        }
        catch (OperationCanceledException)
        {
            var clean = await _engine.CancelAndCleanupAsync().ConfigureAwait(true);
            var report = _engine.FinalizeCurrentRun(
                summary: "CANCELLED — network test incomplete",
                errorClassification: "CANCELLED",
                cleanupResult: clean,
                path: _lastPath,
                tcp: "NOT_RUN",
                direct: "NOT_RUN",
                proxy: "NOT_RUN");
            ApplyReportToUi(report);
            BtnSave.IsEnabled = true;
        }
        catch (Exception ex)
        {
            _log.Error(ex.Message);
            var clean = await _engine.CancelAndCleanupAsync().ConfigureAwait(true);
            var report = _engine.FinalizeCurrentRun(
                summary: "FAILURE — exception",
                errorClassification: "EXCEPTION",
                cleanupResult: clean,
                path: _lastPath,
                tcp: "NOT_RUN",
                direct: "NOT_RUN",
                proxy: "NOT_RUN",
                hypothesis: LiveLogService.Sanitize(ex.Message));
            ApplyReportToUi(report);
            BtnSave.IsEnabled = true;
        }
        finally
        {
            _runCts?.Dispose();
            _runCts = null;
            SetBusy(false);
            BtnStart.IsEnabled = _lastPath is { PathOk: true };
        }
    }

    private void ApplyReportToUi(MobileRunReport report)
    {
        ValTcp.Text = report.TcpConnectionResult;
        ValExitIp.Text = string.IsNullOrWhiteSpace(report.ConfirmedExitIp) ? "—" : report.ConfirmedExitIp;
        ValProgress.Text = $"{report.BytesReceived} / 262144";
        ValDlStatus.Text = report.ProxyDownloadResult;
        ValCleanup.Text = report.CleanupResult;
        ValPhase.Text = report.Summary;
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var (json, txt) = _engine.SaveReport();
            _log.Info($"SAVE REPORT: {json}");
            _log.Info($"SAVE REPORT: {txt}");
            ValPhase.Text = "Report saved (current run only)";
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
        if (clean.StartsWith("FAIL", StringComparison.OrdinalIgnoreCase))
            _log.Error("CANCEL cleanup failed: " + clean);
        else
            _log.Warn("CANCEL — " + clean);

        if (_engine.ActiveRunId != null)
        {
            var report = _engine.FinalizeCurrentRun(
                summary: "CANCELLED by user",
                errorClassification: "CANCELLED",
                cleanupResult: clean,
                path: _lastPath,
                tcp: "NOT_RUN",
                direct: "NOT_RUN",
                proxy: "NOT_RUN");
            ApplyReportToUi(report);
            BtnSave.IsEnabled = true;
        }
        else
        {
            ValPhase.Text = "Cancel/cleanup requested (no active run)";
        }
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        BtnCheck.IsEnabled = !busy;
        BtnStart.IsEnabled = !busy && _lastPath is { PathOk: true };
        BtnCancel.IsEnabled = true;
    }
}
