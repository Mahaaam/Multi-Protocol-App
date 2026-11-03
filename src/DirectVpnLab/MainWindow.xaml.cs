using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using DirectVpnLab.Models;
using DirectVpnLab.Services;
using Microsoft.Win32;

namespace DirectVpnLab;

public partial class MainWindow : Window
{
    private readonly LiveLogService _log;
    private readonly LabCredentials _cred;
    private readonly ObservableCollection<ProtocolMethod> _methods = new();
    private readonly ConnectionService _connection;
    private readonly SpeedTestService _speed;
    private readonly PersistenceService _persist;
    private readonly DispatcherTimer _healthTimer;
    private readonly DispatcherTimer _durationTimer;
    private CancellationTokenSource? _cts;
    private ConnectionUiState _uiState = ConnectionUiState.Disconnected;
    private SpeedTestResult? _directSpeed;
    private SpeedTestResult? _vpnSpeed;
    private bool _closingCleanupDone;
    private int _healthGate;
    private int _opGate;
    private PersistedLabState _state;
    private DateTime? _connectedSince;

    public MainWindow()
    {
        InitializeComponent();
        AppPaths.EnsureDirs();
        _log = new LiveLogService(Dispatcher);
        _log.Changed += () =>
        {
            if (ChkAutoScroll.IsChecked == true && LogList.Items.Count > 0)
            {
                LogList.ScrollIntoView(LogList.Items[^1]);
            }
        };
        LogList.ItemsSource = _log.Lines;

        _cred = ProtocolCatalog.LoadCredentials();
        foreach (var m in ProtocolCatalog.BuildMethods(_cred))
        {
            _methods.Add(m);
        }

        _connection = new ConnectionService(_log, _cred);
        _speed = new SpeedTestService(_log);
        _persist = new PersistenceService(_log);
        _state = _persist.LoadOrCreate(_cred);
        _persist.ApplyToMethods(_state, _methods);
        if (_state.Ui.AutoScrollLog == false)
        {
            ChkAutoScroll.IsChecked = false;
        }

        DiscoveryService.Rank(_methods.ToList());
        RefreshGrids();
        UpdatePersistMeta();

        _healthTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(25) };
        _healthTimer.Tick += async (_, _) => await HealthTickAsync();
        _durationTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _durationTimer.Tick += (_, _) => UpdateDuration();

        Loaded += async (_, _) =>
        {
            _log.Info("Application started");
            _log.Info($"Network fingerprint: {PersistenceService.CaptureNetworkFingerprint()}");
            await _connection.RecoverOrphansAsync();
            _log.Info($"sing-box: {(File.Exists(AppPaths.SingBoxExe) ? "found" : "MISSING")}");
            _log.Info($"wintun: {(File.Exists(AppPaths.WintunDll) ? "found" : "MISSING")}");
            _log.Info($"libcronet: {(File.Exists(AppPaths.LibCronetDll) ? "found" : "MISSING")}");
            _log.Info($"Credentials loaded for server {_cred.server_ip}");

            var fatal = _connection.CheckFatalPrerequisites();
            if (fatal != null)
            {
                _log.Fail(fatal);
                SetUiState(ConnectionUiState.Failed, fatal);
            }
            else
            {
                _log.Info("Administrator privileges confirmed");
                SetUiState(ConnectionUiState.Disconnected);
            }

            if (_state.LastTestAtUtc != null)
            {
                _log.Info($"Restored previous results from {_state.LastTestAtUtc:u} (no auto TEST ALL)");
                if (_state.ResultsStale)
                {
                    _log.Warn($"Cached results marked stale: {_state.StaleReason}");
                }
            }
        };

        Closing += OnClosing;
    }

    private async void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (_closingCleanupDone) return;

        e.Cancel = true;
        _healthTimer.Stop();
        _durationTimer.Stop();
        SetBusy(true);
        try
        {
            _cts?.Cancel();
            _state.Ui.AutoScrollLog = ChkAutoScroll.IsChecked == true;
            SaveResultsSnapshot();
            var (ok, msg) = await _connection.DisconnectAsync();
            if (!ok) _log.Fail($"Shutdown cleanup incomplete: {msg}");
            else _log.Info("Shutdown cleanup finished");
            _closingCleanupDone = true;
            Close();
        }
        catch (Exception ex)
        {
            _closingCleanupDone = true;
            _log.Error($"Shutdown cleanup error: {ex.Message}");
            Close();
        }
    }

    private async void Connect_Click(object sender, RoutedEventArgs e)
    {
        if (_uiState == ConnectionUiState.Connected)
        {
            await DoDisconnectAsync();
            return;
        }

        if (!TryBeginOp()) return;

        var fatal = _connection.CheckFatalPrerequisites();
        if (fatal != null)
        {
            _log.Fail(fatal);
            SetUiState(ConnectionUiState.Failed, fatal);
            EndOp();
            return;
        }

        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        SetBusy(true);
        try
        {
            // CONNECT uses prior PASS ranking — does NOT run full TEST ALL
            var passed = _methods
                .Where(m => m.Status == TestStatus.Pass)
                .OrderBy(m => m.Rank == 0 ? int.MaxValue : m.Rank)
                .ThenByDescending(m => m.QualityScore)
                .ToList();

            if (passed.Count == 0)
            {
                SetUiState(ConnectionUiState.Failed, "No PASS methods — run TEST ALL first");
                _log.Fail("CONNECTION FAILED — no PASS methods. Run TEST ALL first.");
                return;
            }

            if (_state.ResultsStale)
            {
                _log.Warn($"Using stale cached ranking ({_state.StaleReason}) — quick recheck required before TUN");
            }

            SetUiState(ConnectionUiState.Connecting);
            var discovery = new DiscoveryService(_log, _cred);
            var eligible = new List<ProtocolMethod>();

            foreach (var m in passed)
            {
                ct.ThrowIfCancellationRequested();
                var (ok, detail) = await discovery.QuickRecheckAsync(m, ct);
                if (ok)
                {
                    m.IsHistorical = false;
                    eligible.Add(m);
                    _log.Info($"Eligible for TUN: {m.Id} ({detail})");
                }
                else
                {
                    _log.Warn($"Quick recheck failed for {m.Id}: {detail}");
                    m.LastError = detail;
                }
            }

            if (eligible.Count == 0)
            {
                SetUiState(ConnectionUiState.Failed, "No method passed quick recheck");
                _log.Fail("CONNECTION FAILED — no method available after quick recheck");
                return;
            }

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var (connOk, msg) = await _connection.ConnectBestAsync(eligible, ct);
            sw.Stop();
            if (!connOk || !_connection.IsConnected)
            {
                SetUiState(ConnectionUiState.Failed, msg);
                _log.Fail(msg);
                ClearConnInfo();
                return;
            }

            var active = _connection.ActiveMethod!;
            TxtProtocol.Text = $"Method: {active.Id} {active.DisplayName}";
            TxtTransport.Text = $"Transport: {active.Transport}";
            TxtExitIp.Text = $"Exit IP: {active.ExitIp ?? "—"}";
            TxtLatency.Text = $"Latency: {active.LatencyMs:F0} ms";
            TxtConnStatus.Text = "Status: Connected";
            _connectedSince = DateTime.Now;
            UpdateDuration();
            _durationTimer.Start();
            _state.BestMethodId = active.Id;
            _state.LastExitIp = active.ExitIp;
            _state.ResultsStale = false;
            _state.StaleReason = null;
            SaveResultsSnapshot();
            SetUiState(ConnectionUiState.Connected);
            _healthTimer.Start();
            _log.Info($"Connect duration setup: {sw.Elapsed.TotalSeconds:F1}s");
        }
        catch (OperationCanceledException)
        {
            _log.Warn("Operation cancelled");
            SetUiState(ConnectionUiState.Disconnected);
        }
        catch (Exception ex)
        {
            _log.Error(ex.Message);
            SetUiState(ConnectionUiState.Failed, ex.Message);
        }
        finally
        {
            SetBusy(false);
            EndOp();
        }
    }

    private async void TestAll_Click(object sender, RoutedEventArgs e)
    {
        if (_connection.IsConnected || _uiState == ConnectionUiState.Connected)
        {
            _log.Warn("TEST ALL disabled while VPN Connected");
            return;
        }

        if (!TryBeginOp()) return;

        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        SetBusy(true);
        SetUiState(ConnectionUiState.Testing);
        try
        {
            foreach (var m in _methods)
            {
                if (m.Status != TestStatus.Skipped || m.Id is not ("F01" or "F02"))
                {
                    // reset non-MASQUE for fresh run; MASQUE stays skipped
                }
                m.IsHistorical = false;
            }

            var discovery = new DiscoveryService(_log, _cred);
            await discovery.RunAsync(_methods.ToList(), new Progress<ProtocolMethod>(_ => RefreshGrids()), _cts.Token);
            RefreshGrids();

            _state = _persist.CaptureFromMethods(
                _methods,
                _cred,
                DateTime.UtcNow,
                _methods.Where(m => m.Status == TestStatus.Pass).OrderBy(m => m.Rank).FirstOrDefault()?.Id);
            _persist.Save(_state, _cred);
            UpdatePersistMeta();
            SetUiState(ConnectionUiState.Disconnected);
            _log.Info("TEST ALL finished — results saved locally");
        }
        catch (Exception ex)
        {
            _log.Error(ex.Message);
            SetUiState(ConnectionUiState.Failed, ex.Message);
        }
        finally
        {
            SetBusy(false);
            EndOp();
        }
    }

    private async void SpeedTest_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginOp()) return;
        SetBusy(true);
        try
        {
            if (!_connection.IsConnected)
            {
                _directSpeed = await _speed.RunAsync("DIRECT", null, null, CancellationToken.None);
                TxtSpeedDirect.Text = FormatSpeed("Direct", _directSpeed);
            }
            else
            {
                if (!_connection.TunnelPathVerified)
                {
                    _log.Warn("VPN Speed Test blocked — tunnel path not verified");
                    TxtSpeedVpn.Text = "VPN: BLOCKED — tunnel path not verified";
                    return;
                }

                var p = _connection.ActiveMethod;
                _vpnSpeed = await _speed.RunAsync("VPN", p?.DisplayName, null, CancellationToken.None);
                TxtSpeedVpn.Text = FormatSpeed($"VPN ({p?.Protocol})", _vpnSpeed);
            }
        }
        catch (Exception ex)
        {
            _log.Error($"Speed Test error: {ex.Message}");
        }
        finally
        {
            SetBusy(false);
            EndOp();
        }
    }

    private static string FormatSpeed(string label, SpeedTestResult r)
    {
        if (!r.Success)
        {
            return $"{label}: FAIL — {r.Error}";
        }
        return $"{label}: ↓ {r.DownloadMbps:F2} Mbps  ↑ {r.UploadMbps:F2} Mbps  lat {r.LatencyMs:F0} ms";
    }

    private async void Disconnect_Click(object sender, RoutedEventArgs e) => await DoDisconnectAsync();

    private async Task DoDisconnectAsync()
    {
        if (!TryBeginOp()) return;
        _healthTimer.Stop();
        _durationTimer.Stop();
        _cts?.Cancel();
        SetBusy(true);
        try
        {
            var (ok, msg) = await _connection.DisconnectAsync();
            ClearConnInfo();
            if (!ok)
            {
                SetUiState(ConnectionUiState.Failed, msg);
                _log.Fail(msg);
                return;
            }
            SetUiState(ConnectionUiState.Disconnected);
        }
        finally
        {
            SetBusy(false);
            EndOp();
        }
    }

    private async Task HealthTickAsync()
    {
        if (Interlocked.CompareExchange(ref _healthGate, 1, 0) != 0) return;

        try
        {
            if (!_connection.IsConnected)
            {
                if (_uiState == ConnectionUiState.Connected)
                {
                    SetUiState(ConnectionUiState.Failed, "Connection no longer verified");
                    _log.Fail("Connection no longer verified");
                }
                return;
            }

            var (ok, exitIp, detail) = await _connection.VerifyHealthAsync(CancellationToken.None);
            if (ok) return;

            _log.Warn($"Health check failed: {detail}");
            SetUiState(ConnectionUiState.Degraded);

            var ranked = _methods.Where(m => m.Status == TestStatus.Pass).OrderBy(m => m.Rank).ToList();
            var (discOk, discMsg) = await _connection.DisconnectAsync();
            if (!discOk)
            {
                ClearConnInfo();
                SetUiState(ConnectionUiState.Failed, discMsg);
                _log.Fail($"Recovery aborted — cleanup failed: {discMsg}");
                return;
            }

            var discovery = new DiscoveryService(_log, _cred);
            var eligible = new List<ProtocolMethod>();
            foreach (var m in ranked)
            {
                var (rOk, _) = await discovery.QuickRecheckAsync(m, CancellationToken.None);
                if (rOk) eligible.Add(m);
            }

            var (reOk, msg) = await _connection.ConnectBestAsync(eligible, CancellationToken.None);
            if (reOk && _connection.IsConnected)
            {
                SetUiState(ConnectionUiState.Connected);
                var a = _connection.ActiveMethod!;
                TxtProtocol.Text = $"Method: {a.Id} {a.DisplayName}";
                TxtExitIp.Text = $"Exit IP: {a.ExitIp ?? exitIp ?? "—"}";
                TxtConnStatus.Text = "Status: Connected";
                _connectedSince = DateTime.Now;
                _durationTimer.Start();
            }
            else
            {
                ClearConnInfo();
                SetUiState(ConnectionUiState.Failed, msg);
                _log.Fail(msg);
            }
        }
        finally
        {
            Interlocked.Exchange(ref _healthGate, 0);
        }
    }

    private void CopyLog_Click(object sender, RoutedEventArgs e)
    {
        Clipboard.SetText(_log.ExportSanitized());
        _log.Info("Log copied to clipboard");
    }

    private void ClearLog_Click(object sender, RoutedEventArgs e) => _log.ClearView();

    private void ExportLog_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog
        {
            Filter = "Log file|*.log|Text|*.txt",
            FileName = $"direct-vpn-lab-{DateTime.Now:yyyyMMdd-HHmmss}.log"
        };
        if (dlg.ShowDialog() == true)
        {
            File.WriteAllText(dlg.FileName, _log.ExportSanitized());
            _log.Info("Log exported to file");
        }
    }

    private void RefreshGrids()
    {
        var success = _methods
            .Where(m => m.Status == TestStatus.Pass)
            .OrderBy(m => m.Rank == 0 ? 999 : m.Rank)
            .ToList();
        GridMethods.ItemsSource = null;
        GridMethods.ItemsSource = success;

        var other = _methods
            .Where(m => m.Status is TestStatus.Fail or TestStatus.Unverified or TestStatus.Skipped)
            .OrderBy(m => m.Id)
            .Select(m =>
            {
                if (m.Status == TestStatus.Skipped && string.IsNullOrWhiteSpace(m.LastError))
                {
                    m.LastError = m.SkipReason;
                }
                return m;
            })
            .ToList();
        GridOther.ItemsSource = null;
        GridOther.ItemsSource = other;

        TxtSuccessHint.Text = success.Count == 0
            ? "No PASS methods yet. Run TEST ALL to discover."
            : $"{success.Count} PASS method(s). Green Connected requires verified TUN.";
    }

    private void SaveResultsSnapshot()
    {
        _state = _persist.CaptureFromMethods(
            _methods,
            _cred,
            _state.LastTestAtUtc,
            _state.BestMethodId ?? _methods.Where(m => m.Status == TestStatus.Pass).OrderBy(m => m.Rank).FirstOrDefault()?.Id);
        _state.Ui.AutoScrollLog = ChkAutoScroll.IsChecked == true;
        _persist.Save(_state, _cred);
        UpdatePersistMeta();
    }

    private void UpdatePersistMeta()
    {
        if (_state.LastTestAtUtc == null)
        {
            TxtPersistMeta.Text = "Results: none saved yet";
            return;
        }

        var local = _state.LastTestAtUtc.Value.ToLocalTime();
        var stale = _state.ResultsStale ? $" · STALE: {_state.StaleReason}" : " · saved locally";
        var best = string.IsNullOrWhiteSpace(_state.BestMethodId) ? "" : $" · best {_state.BestMethodId}";
        TxtPersistMeta.Text = $"Last test: {local:yyyy-MM-dd HH:mm}{best}{stale}";
    }

    private void ClearConnInfo()
    {
        TxtProtocol.Text = "Method: —";
        TxtTransport.Text = "Transport: —";
        TxtExitIp.Text = "Exit IP: —";
        TxtLatency.Text = "Latency: —";
        TxtConnTime.Text = "Duration: —";
        TxtConnStatus.Text = "Status: Disconnected";
        _connectedSince = null;
    }

    private void UpdateDuration()
    {
        if (_connectedSince is { } since && _uiState == ConnectionUiState.Connected)
        {
            var d = DateTime.Now - since;
            TxtConnTime.Text = $"Duration: {d:hh\\:mm\\:ss}";
        }
    }

    private bool TryBeginOp()
    {
        if (Interlocked.CompareExchange(ref _opGate, 1, 0) != 0)
        {
            _log.Warn("Another operation is in progress");
            return false;
        }
        return true;
    }

    private void EndOp() => Interlocked.Exchange(ref _opGate, 0);

    private void SetBusy(bool busy)
    {
        var vpnActive = _connection.IsConnected || _uiState == ConnectionUiState.Connected;
        var op = busy || _uiState is ConnectionUiState.Testing or ConnectionUiState.Connecting or ConnectionUiState.Degraded;
        BtnTestAll.IsEnabled = !op && !vpnActive;
        BtnSpeed.IsEnabled = !busy;
        BtnConnectTop.IsEnabled = !busy || _uiState == ConnectionUiState.Connected;
        BtnConnect.IsEnabled = BtnConnectTop.IsEnabled;
        BtnDisconnect.IsEnabled = !busy && _uiState is ConnectionUiState.Connected or ConnectionUiState.Degraded;
    }

    private void SetUiState(ConnectionUiState state, string? detail = null)
    {
        _uiState = state;
        var label = state switch
        {
            ConnectionUiState.Disconnected => "DISCONNECTED",
            ConnectionUiState.Testing => "TESTING",
            ConnectionUiState.Connecting => "CONNECTING",
            ConnectionUiState.Connected => "CONNECTED",
            ConnectionUiState.Degraded => "RECOVERING",
            ConnectionUiState.Failed => "FAILED",
            _ => state.ToString()
        };
        TxtStatus.Text = string.IsNullOrWhiteSpace(detail) || state != ConnectionUiState.Failed
            ? label
            : Truncate(detail, 72);
        TxtConnStatus.Text = $"Status: {label}";

        var vpnActive = state == ConnectionUiState.Connected || _connection.IsConnected;
        BtnTestAll.IsEnabled = !vpnActive && state is not (ConnectionUiState.Testing or ConnectionUiState.Connecting or ConnectionUiState.Degraded);
        BtnDisconnect.IsEnabled = state is ConnectionUiState.Connected or ConnectionUiState.Degraded;
        BtnConnectTop.Content = "CONNECT";

        var (fg, bg) = state switch
        {
            ConnectionUiState.Connected => ("#2ECC71", "#143022"),
            ConnectionUiState.Connecting => ("#E6B450", "#2A2415"),
            ConnectionUiState.Testing => ("#3DB9F5", "#15202A"),
            ConnectionUiState.Degraded => ("#E6B450", "#2A2415"),
            ConnectionUiState.Failed => ("#E85D5D", "#2A1515"),
            _ => ("#8B949E", "#30363D")
        };
        TxtStatus.Foreground = Brush(fg);
        StatusBadge.Background = Brush(bg);

        if (state != ConnectionUiState.Connected)
        {
            _durationTimer.Stop();
        }
    }

    private static string Truncate(string s, int n) =>
        string.IsNullOrEmpty(s) ? s : (s.Length <= n ? s : s[..(n - 1)] + "…");

    private static SolidColorBrush Brush(string hex) =>
        (SolidColorBrush)new BrushConverter().ConvertFrom(hex)!;
}
