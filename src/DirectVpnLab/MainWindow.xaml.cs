using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Shapes;
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
    private readonly DispatcherTimer _pulseTimer;
    private readonly DispatcherTimer _healthTimer;
    private CancellationTokenSource? _cts;
    private ConnectionUiState _uiState = ConnectionUiState.Disconnected;
    private SpeedTestResult? _directSpeed;
    private SpeedTestResult? _vpnSpeed;
    private double _pulse;
    private bool _closingCleanupDone;
    private int _healthGate; // 0=idle, 1=running

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
        GridMethods.ItemsSource = _methods;

        _cred = ProtocolCatalog.LoadCredentials();
        foreach (var m in ProtocolCatalog.BuildMethods(_cred))
        {
            _methods.Add(m);
        }

        _connection = new ConnectionService(_log, _cred);
        _speed = new SpeedTestService(_log);

        _pulseTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(40) };
        _pulseTimer.Tick += (_, _) => AnimatePulse();
        _healthTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(25) };
        _healthTimer.Tick += async (_, _) => await HealthTickAsync();

        Loaded += async (_, _) =>
        {
            _log.Info("Application started");
            _log.Info("Windows network detected");
            await _connection.RecoverOrphansAsync();
            _log.Info($"sing-box asset: {(File.Exists(AppPaths.SingBoxExe) ? "found" : "MISSING")}");
            _log.Info($"Credentials loaded for server {_cred.server_ip}");
            if (!ConnectionService.IsAdministrator())
            {
                _log.Warn("Not running as Administrator — TUN connect will require elevation");
            }
            SetUiState(ConnectionUiState.Disconnected);
        };

        Closing += OnClosing;
    }

    private async void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (_closingCleanupDone)
        {
            return;
        }

        e.Cancel = true;
        _healthTimer.Stop();
        _pulseTimer.Stop();
        SetBusy(true);
        try
        {
            _cts?.Cancel();
            await _connection.DisconnectAsync();
            _closingCleanupDone = true;
            _log.Info("Shutdown cleanup finished");
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

        if (_uiState is ConnectionUiState.Testing or ConnectionUiState.Connecting or ConnectionUiState.Degraded)
        {
            return;
        }

        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        SetBusy(true);
        try
        {
            SetUiState(ConnectionUiState.Testing);
            var discovery = new DiscoveryService(_log, _cred);
            var progress = new Progress<ProtocolMethod>(_ => RefreshGrid());
            await discovery.RunAsync(_methods.ToList(), progress, ct);
            RefreshGrid();

            // Only PASS methods may enter auto-connect.
            var passed = _methods
                .Where(m => m.Status == TestStatus.Pass)
                .OrderBy(m => m.Rank)
                .ToList();

            if (passed.Count == 0)
            {
                SetUiState(ConnectionUiState.Failed);
                _log.Fail("CONNECTION FAILED - no PASS methods");
                return;
            }

            SetUiState(ConnectionUiState.Connecting);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var (ok, msg) = await _connection.ConnectBestAsync(passed, ct);
            sw.Stop();
            if (!ok || !_connection.IsConnected)
            {
                SetUiState(ConnectionUiState.Failed);
                _log.Fail(msg);
                ClearConnInfo();
                return;
            }

            var active = _connection.ActiveMethod!;
            TxtProtocol.Text = $"Protocol: {active.Protocol}";
            TxtTransport.Text = $"Transport: {active.Transport}";
            TxtExitIp.Text = $"Exit IP: {active.ExitIp ?? "—"}";
            TxtLatency.Text = $"Latency: {active.LatencyMs:F0} ms";
            TxtConnTime.Text = $"Connection Time: {sw.Elapsed.TotalSeconds:F1} s";
            TxtConnStatus.Text = "Status: Connected";
            SetUiState(ConnectionUiState.Connected);
            _healthTimer.Start();
        }
        catch (OperationCanceledException)
        {
            _log.Warn("Operation cancelled");
            SetUiState(ConnectionUiState.Disconnected);
        }
        catch (Exception ex)
        {
            _log.Error(ex.Message);
            SetUiState(ConnectionUiState.Failed);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void TestAll_Click(object sender, RoutedEventArgs e)
    {
        if (_uiState is ConnectionUiState.Testing or ConnectionUiState.Connecting or ConnectionUiState.Degraded) return;
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        SetBusy(true);
        SetUiState(ConnectionUiState.Testing);
        try
        {
            var discovery = new DiscoveryService(_log, _cred);
            await discovery.RunAsync(_methods.ToList(), new Progress<ProtocolMethod>(_ => RefreshGrid()), _cts.Token);
            RefreshGrid();
            SetUiState(_connection.IsConnected ? ConnectionUiState.Connected : ConnectionUiState.Disconnected);
        }
        catch (Exception ex)
        {
            _log.Error(ex.Message);
            SetUiState(ConnectionUiState.Failed);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void SpeedTest_Click(object sender, RoutedEventArgs e)
    {
        SetBusy(true);
        try
        {
            if (!_connection.IsConnected)
            {
                _directSpeed = await _speed.RunAsync("DIRECT", null, null, CancellationToken.None);
                TxtSpeedDirect.Text = FormatSpeed("DIRECT", _directSpeed);
            }
            else
            {
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
        }
    }

    private static string FormatSpeed(string label, SpeedTestResult r)
    {
        if (!r.Success)
        {
            return $"{label}: FAILED — {r.Error}";
        }
        return $"{label}: ↓ {r.DownloadMbps:F2} Mbps  ↑ {r.UploadMbps:F2} Mbps  " +
               $"lat {r.LatencyMs:F0} ms  jitter {r.JitterMs:F0} ms";
    }

    private async void Disconnect_Click(object sender, RoutedEventArgs e) => await DoDisconnectAsync();

    private async Task DoDisconnectAsync()
    {
        _healthTimer.Stop();
        _cts?.Cancel();
        await _connection.DisconnectAsync();
        ClearConnInfo();
        SetUiState(ConnectionUiState.Disconnected);
    }

    private async Task HealthTickAsync()
    {
        if (Interlocked.CompareExchange(ref _healthGate, 1, 0) != 0)
        {
            return; // overlap prevention
        }

        try
        {
            if (!_connection.IsConnected)
            {
                if (_uiState == ConnectionUiState.Connected)
                {
                    SetUiState(ConnectionUiState.Failed);
                    _log.Fail("Connection no longer verified");
                }
                return;
            }

            var (ok, exitIp, detail) = await _connection.VerifyHealthAsync(CancellationToken.None);
            if (ok)
            {
                return;
            }

            _log.Warn($"Health check failed: {detail}");
            SetUiState(ConnectionUiState.Degraded);
            _log.Info("Attempting controlled recovery after cleanup of previous method");

            var ranked = _methods.Where(m => m.Status == TestStatus.Pass).OrderBy(m => m.Rank).ToList();
            await _connection.DisconnectAsync();

            var (reOk, msg) = await _connection.ConnectBestAsync(ranked, CancellationToken.None);
            if (reOk && _connection.IsConnected)
            {
                SetUiState(ConnectionUiState.Connected);
                var a = _connection.ActiveMethod!;
                TxtProtocol.Text = $"Protocol: {a.Protocol}";
                TxtTransport.Text = $"Transport: {a.Transport}";
                TxtExitIp.Text = $"Exit IP: {a.ExitIp ?? exitIp ?? "—"}";
                TxtConnStatus.Text = "Status: Connected";
            }
            else
            {
                ClearConnInfo();
                SetUiState(ConnectionUiState.Failed);
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

    private void RefreshGrid()
    {
        var view = _methods
            .Where(m => m.Status is TestStatus.Pass or TestStatus.Unverified or TestStatus.Fail or TestStatus.Skipped)
            .OrderBy(m => m.Status == TestStatus.Pass ? 0 : 1)
            .ThenBy(m => m.Rank == 0 ? 999 : m.Rank)
            .ToList();
        GridMethods.ItemsSource = null;
        GridMethods.ItemsSource = view;
    }

    private void ClearConnInfo()
    {
        TxtProtocol.Text = "Protocol: —";
        TxtTransport.Text = "Transport: —";
        TxtExitIp.Text = "Exit IP: —";
        TxtLatency.Text = "Latency: —";
        TxtConnTime.Text = "Connection Time: —";
        TxtConnStatus.Text = "Status: Disconnected";
    }

    private void SetBusy(bool busy)
    {
        BtnTestAll.IsEnabled = !busy;
        BtnSpeed.IsEnabled = !busy;
        BtnConnect.IsEnabled = !busy || _uiState == ConnectionUiState.Connected;
    }

    private void SetUiState(ConnectionUiState state)
    {
        _uiState = state;
        TxtStatus.Text = state.ToString();
        TxtConnStatus.Text = $"Status: {state}";
        BtnDisconnect.IsEnabled = state is ConnectionUiState.Connected or ConnectionUiState.Degraded;

        var ring = FindRing();
        var label = FindLabel();
        if (ring == null || label == null) return;

        switch (state)
        {
            case ConnectionUiState.Disconnected:
                _pulseTimer.Stop();
                ring.Stroke = Brush("#3A4450");
                ring.Fill = Brush("#1E2329");
                label.Text = "CONNECT";
                break;
            case ConnectionUiState.Testing:
                _pulseTimer.Start();
                ring.Stroke = Brush("#2EC4FF");
                ring.Fill = Brush("#15202A");
                label.Text = "TESTING";
                break;
            case ConnectionUiState.Connecting:
                _pulseTimer.Start();
                ring.Stroke = Brush("#F0B429");
                ring.Fill = Brush("#2A2415");
                label.Text = "CONNECTING";
                break;
            case ConnectionUiState.Connected:
                _pulseTimer.Stop();
                ring.Stroke = Brush("#2ECC71");
                ring.Fill = Brush("#143022");
                label.Text = "CONNECTED";
                break;
            case ConnectionUiState.Degraded:
                _pulseTimer.Start();
                ring.Stroke = Brush("#F0B429");
                ring.Fill = Brush("#2A2415");
                label.Text = "RECOVERING";
                break;
            case ConnectionUiState.Failed:
                _pulseTimer.Stop();
                ring.Stroke = Brush("#E74C3C");
                ring.Fill = Brush("#2A1515");
                label.Text = "FAILED";
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(state), state, null);
        }
    }

    private void AnimatePulse()
    {
        var ring = FindRing();
        if (ring == null) return;
        _pulse += 0.12;
        var alpha = 0.45 + 0.35 * Math.Sin(_pulse);
        if (ring.Stroke is SolidColorBrush b)
        {
            var c = b.Color;
            ring.Stroke = new SolidColorBrush(Color.FromArgb((byte)(alpha * 255), c.R, c.G, c.B));
        }
    }

    private Ellipse? FindRing() =>
        BtnConnect.Template?.FindName("Ring", BtnConnect) as Ellipse;

    private System.Windows.Controls.TextBlock? FindLabel() =>
        BtnConnect.Template?.FindName("Label", BtnConnect) as System.Windows.Controls.TextBlock;

    private static SolidColorBrush Brush(string hex) =>
        (SolidColorBrush)new BrushConverter().ConvertFrom(hex)!;
}
