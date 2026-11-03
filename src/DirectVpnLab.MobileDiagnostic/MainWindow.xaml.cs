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
        try
        {
            _engine.EnsureReady();
            _log.Info($"Ready {MobileDiagnosticEngine.AppVersion}");
            _log.Info($"Reports → {MobileDiagnosticEngine.ReportsDir}");
            _log.Info("Admin NOT required (PROXY-ONLY / asInvoker). Do not change WireGuard from this tool.");
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

            var p = _lastPath!;
            ValAdapter.Text = p.NetworkAdapter;
            ValRoute.Text = p.DefaultRoute + "\n→ " + p.EffectiveToServer;
            ValPublicIp.Text = p.PublicIpv4 == "UNKNOWN"
                ? $"UNKNOWN (A={p.PublicIpv4A}; B={p.PublicIpv4B})"
                : p.PublicIpv4;
            ValMobile.Text = p.MobileNetworkStatus;
            BtnStart.IsEnabled = p.PathOk;
            ValPhase.Text = p.PathOk ? "Path OK — you may START C01 TEST" : "Path blocked — fix WG / retry CHECK";
            if (!string.IsNullOrWhiteSpace(p.BlockReason))
                _log.Warn(p.BlockReason);
            _log.Info($"CHECK: PathOk={p.PathOk} public={p.PublicIpv4} effective={p.EffectiveToServer}");
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

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        if (_lastPath is not { PathOk: true })
        {
            MessageBox.Show(this, "Run CHECK NETWORK first and ensure path is direct (WG off).", "Blocked",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        SetBusy(true);
        BtnSave.IsEnabled = false;
        ValDlStatus.Text = "RUNNING";
        ValProgress.Text = "0 / 262144";
        ValSpeed.Text = "—";
        ValExitIp.Text = "—";
        ValTcp.Text = "…";
        ValCleanup.Text = "—";
        _runCts = new CancellationTokenSource();

        try
        {
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
