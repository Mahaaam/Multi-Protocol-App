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
    private bool _shutdownRequested;
    private int _healthGate;
    private int _opGate;
    private PersistedLabState _state;
    private PersistedLabState _lastCompleteState;
    private PersistedLabState? _testAllBaseline;
    private TaskCompletionSource? _activeOpCompletion;
    private DateTime? _connectedSince;
    private int _healthFailStreak;
    private bool _userRequestedDisconnect;

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
        _lastCompleteState = CloneState(_state);
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
        _shutdownRequested = true;
        _healthTimer.Stop();
        _durationTimer.Stop();
        SetBusy(true);
        try
        {
            // Cancel any in-flight TEST ALL / CONNECT and wait for real completion + cleanup
            _cts?.Cancel();
            await WaitForActiveOpAsync(TimeSpan.FromSeconds(45));

            // If discovery was interrupted, never persist partial method rows
            if (_testAllBaseline != null)
            {
                AbortDiscoveryToBaseline("Shutdown during TEST ALL — restoring last complete results (partial discarded)");
            }
            else if (_uiState == ConnectionUiState.Testing)
            {
                RestoreLastCompleteToUi("Shutdown during TEST ALL — reloading last complete results");
            }

            PersistUiPrefsPreservingCompleteResults();
            var (ok, msg) = await _connection.DisconnectAsync();
            if (!ok) _log.Fail($"Shutdown cleanup incomplete: {msg}");
            else _log.Info("Shutdown cleanup finished");
            _closingCleanupDone = true;
            Close();
        }
        catch (Exception ex)
        {
            try
            {
                if (_testAllBaseline != null)
                {
                    AbortDiscoveryToBaseline("Shutdown error path — restoring last complete results");
                }
                PersistUiPrefsPreservingCompleteResults();
                await _connection.DisconnectAsync();
            }
            catch
            {
                // best-effort cleanup
            }
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

        // Cancel in-flight TEST ALL / CONNECT
        if (_uiState is ConnectionUiState.Testing or ConnectionUiState.Connecting
            or ConnectionUiState.Verifying or ConnectionUiState.Switching)
        {
            _log.Warn("Cancel requested");
            _cts?.Cancel();
            return;
        }

        if (!TryBeginOp()) return;
        BeginOpTracking();

        // Re-evaluate network freshness before Quick Connect (Wi-Fi/Hotspot/server/engine)
        _state = _persist.LoadOrCreate(_cred);
        if (_state.ResultsStale)
        {
            _log.Warn($"Cached ranking stale: {_state.StaleReason}");
            foreach (var m in _methods.Where(x => x.Status == TestStatus.Pass))
            {
                m.IsHistorical = true;
            }
            RefreshGrids();
        }

        var fatal = _connection.CheckFatalPrerequisites();
        if (fatal != null)
        {
            _log.Fail(fatal);
            SetUiState(ConnectionUiState.Failed, fatal);
            EndOp();
            EndOpTracking();
            return;
        }

        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        SetBusy(true);
        try
        {
            // Quick Connect: cached PASS only — never runs full TEST ALL
            var passed = _methods
                .Where(m => m.Status == TestStatus.Pass)
                .OrderBy(m => m.Id == _state.BestMethodId ? 0 : 1)
                .ThenBy(m => m.Rank == 0 ? int.MaxValue : m.Rank)
                .ThenByDescending(m => m.QualityScore)
                .ToList();

            if (passed.Count == 0)
            {
                SetUiState(ConnectionUiState.Failed, "No PASS methods — run TEST ALL first");
                _log.Fail("CONNECTION FAILED — no PASS methods. Run TEST ALL first.");
                return;
            }

            _userRequestedDisconnect = false;
            _healthFailStreak = 0;
            var netFp = PersistenceService.CaptureNetworkFingerprint();
            var blocked = new HashSet<string>(
                _persist.GetTunFailureIdsForNetwork(_state, netFp),
                StringComparer.OrdinalIgnoreCase);

            var candidates = passed
                .Where(m => !blocked.Contains(m.Id))
                .ToList();
            if (candidates.Count == 0)
            {
                _log.Warn("All PASS methods are temporarily blocked for this network after TUN health failures — clearing blocklist for retry");
                _persist.ClearTunFailuresForNetwork(_state, netFp);
                candidates = passed.ToList();
            }
            else if (blocked.Count > 0)
            {
                _log.Info($"Skipping {blocked.Count} method(s) with recent TUN health failures on this network: {string.Join(",", blocked)}");
            }

            SetUiState(ConnectionUiState.Connecting);
            var discovery = new DiscoveryService(_log, _cred);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            string? lastFail = null;

            void OnPhase(string phase, string detail)
            {
                Dispatcher.Invoke(() =>
                {
                    if (phase == "VERIFYING")
                        SetUiState(ConnectionUiState.Verifying, detail);
                    else if (phase == "SWITCHING")
                        SetUiState(ConnectionUiState.Switching, detail);
                    else if (phase == "CONNECTING")
                        SetUiState(ConnectionUiState.Connecting, detail);
                });
            }

            void OnCandidateFailed(ProtocolMethod failedMethod, string failMsg)
            {
                var cat = _connection.LastHealthFailureCategory
                          ?? ConnectionService.ClassifyHealthCategory(failMsg);
                _persist.RecordTunFailure(_state, failedMethod.Id, netFp, cat, failMsg);
                failedMethod.IsHistorical = true;
                failedMethod.LastError = failMsg;
                _log.Warn($"Recorded TUN health failure for {failedMethod.Id} [{cat}] on network {netFp}");
            }

            // Sequential Quick Connect: recheck ONE → TUN+health → next only on failure
            for (var i = 0; i < candidates.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                if (_userRequestedDisconnect) break;

                var m = candidates[i];
                if (i > 0)
                {
                    SetUiState(ConnectionUiState.Switching, $"Next: {m.Id} {m.DisplayName}");
                    _log.Info($"SWITCHING → Quick Connect next candidate {m.Id} {m.DisplayName}");
                }
                else
                {
                    SetUiState(ConnectionUiState.Connecting, $"Recheck {m.Id}");
                }

                _log.Info($"Quick Connect candidate {m.Id} {m.DisplayName} — recheck then TUN (not waiting for others)");
                var (reOk, reDetail) = await discovery.QuickRecheckAsync(m, ct);
                if (!reOk)
                {
                    m.IsHistorical = true;
                    m.LastError = reDetail;
                    lastFail = $"{m.Id}: {reDetail}";
                    _log.Warn($"Quick recheck failed (cached Pass retained) — trying next: {lastFail}");
                    continue;
                }

                m.IsHistorical = false;
                m.LastTestedAtUtc = DateTime.UtcNow;
                _log.Info($"Recheck OK — starting TUN immediately for {m.Id} ({reDetail})");
                SetUiState(ConnectionUiState.Connecting, $"TUN {m.Id}");

                var (connOk, msg) = await _connection.ConnectBestAsync(
                    new[] { m }, ct, OnPhase, OnCandidateFailed);

                if (connOk && _connection.IsConnected && _connection.UsableInternetVerified)
                {
                    sw.Stop();
                    var active = _connection.ActiveMethod!;
                    _persist.ClearTunFailure(_state, active.Id, netFp);

                    ApplyConnectedUi(active, sw.Elapsed);
                    _state.BestMethodId = active.Id;
                    _state.LastExitIp = active.ExitIp;
                    if (!_state.ResultsStale) _state.StaleReason = null;
                    _state.LastTestIncomplete = false;
                    _persist.UpsertMethod(_state, active);
                    foreach (var other in _methods.Where(x => x.Id != active.Id))
                    {
                        other.IsHistorical = true;
                        _persist.UpsertMethod(_state, other);
                    }
                    _persist.Save(_state, _cred);
                    _lastCompleteState = CloneState(_state);
                    UpdatePersistMeta();
                    _healthTimer.Start();
                    _log.Info($"Quick Connect finished in {sw.Elapsed.TotalSeconds:F1}s via {active.Id} (usable internet OK)");
                    return;
                }

                lastFail = msg;
                _log.Warn($"Connect candidate {m.Id} failed: {msg}");

                if (ConnectionService.IsFatalMessage(msg) ||
                    ConnectionService.IsSharedTunConfigFailure(msg) ||
                    msg.Contains("Cleanup Error", StringComparison.OrdinalIgnoreCase) ||
                    ConnectionService.ShouldStopCascadeForSharedEvidence(
                        _connection.LastHealthFailureCategory ?? ConnectionService.ClassifyHealthCategory(msg),
                        2, msg))
                {
                    _persist.Save(_state, _cred);
                    _lastCompleteState = CloneState(_state);
                    sw.Stop();
                    SetUiState(ConnectionUiState.Failed, msg);
                    _log.Fail(msg);
                    ClearConnInfo();
                    return;
                }
            }

            _persist.Save(_state, _cred);
            _lastCompleteState = CloneState(_state);

            sw.Stop();
            SetUiState(ConnectionUiState.Failed, lastFail ?? "CONNECTION FAILED — no usable VPN path");
            _log.Fail(lastFail ?? "CONNECTION FAILED — no usable VPN path");
            ClearConnInfo();
        }
        catch (OperationCanceledException)
        {
            _log.Warn("Quick Connect cancelled — cleaning up");
            try { await _connection.DisconnectAsync(); } catch { /* ignore */ }
            ClearConnInfo();
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
            EndOpTracking();
        }
    }

    private void ApplyConnectedUi(ProtocolMethod active, TimeSpan setup)
    {
        TxtProtocol.Text = $"Method: {active.Id} {active.DisplayName}";
        TxtTransport.Text = $"Transport: {active.Transport}";
        TxtExitIp.Text = $"Exit IP: {active.ExitIp ?? "—"}";
        TxtLatency.Text = $"Latency: {active.LatencyMs:F0} ms";
        TxtConnStatus.Text = "Status: Connected";
        _connectedSince = DateTime.Now;
        UpdateDuration();
        _durationTimer.Start();
        SetUiState(ConnectionUiState.Connected);
        _ = setup;
    }

    private async void TestAll_Click(object sender, RoutedEventArgs e)
    {
        if (_connection.IsConnected || _uiState == ConnectionUiState.Connected)
        {
            _log.Warn("TEST ALL disabled while VPN Connected");
            return;
        }

        if (_uiState is ConnectionUiState.Testing or ConnectionUiState.Connecting)
        {
            _log.Warn("Cancel requested");
            _cts?.Cancel();
            return;
        }

        if (!TryBeginOp()) return;
        BeginOpTracking();

        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        SetBusy(true);
        SetUiState(ConnectionUiState.Testing);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        // Snapshot for cancel/error/shutdown rollback — must not replace last complete DPAPI results
        _testAllBaseline = _persist.CaptureFromMethods(
            _methods,
            _cred,
            _state.LastTestAtUtc,
            _state.BestMethodId,
            resultsStale: _state.ResultsStale,
            staleReason: _state.StaleReason,
            lastTestIncomplete: _state.LastTestIncomplete,
            tunFailures: _state.TunFailures);
        _testAllBaseline.Ui = CloneUi(_state.Ui);
        try
        {
            var discovery = new DiscoveryService(_log, _cred);
            await discovery.RunAsync(_methods.ToList(), new Progress<ProtocolMethod>(_ => RefreshGrids()), _cts.Token);
            RefreshGrids();

            // Fresh ranking re-validates; clear network TUN health blocks so discovery Pass can be tried again
            var fp = PersistenceService.CaptureNetworkFingerprint();
            _persist.ClearTunFailuresForNetwork(_state, fp);

            _state = _persist.CaptureFromMethods(
                _methods,
                _cred,
                DateTime.UtcNow,
                _methods.Where(m => m.Status == TestStatus.Pass).OrderBy(m => m.Rank).FirstOrDefault()?.Id,
                resultsStale: false,
                staleReason: null,
                lastTestIncomplete: false,
                tunFailures: _state.TunFailures);
            _state.Ui = CloneUi(_lastCompleteState.Ui);
            _state.Ui.AutoScrollLog = ChkAutoScroll.IsChecked == true;
            _persist.Save(_state, _cred);
            _lastCompleteState = CloneState(_state);
            _testAllBaseline = null;
            UpdatePersistMeta();
            sw.Stop();
            SetUiState(ConnectionUiState.Disconnected);
            _log.Info($"TEST ALL finished in {sw.Elapsed.TotalSeconds:F1}s — results saved locally");
        }
        catch (OperationCanceledException)
        {
            AbortDiscoveryToBaseline(
                _shutdownRequested
                    ? "TEST ALL cancelled by shutdown — last complete results restored (not saved as new test)"
                    : "TEST ALL cancelled — restoring last complete results (partial run discarded)");
            if (!_shutdownRequested)
            {
                SetUiState(ConnectionUiState.Disconnected);
            }
        }
        catch (Exception ex)
        {
            _log.Error($"TEST ALL failed unexpectedly: {ex.Message}");
            AbortDiscoveryToBaseline(
                "TEST ALL aborted after unexpected error — restoring last complete results (partial discarded)");
            if (!_shutdownRequested)
            {
                SetUiState(ConnectionUiState.Failed, ex.Message);
            }
        }
        finally
        {
            if (_testAllBaseline != null && !_shutdownRequested)
            {
                // Safety net if an unexpected path left baseline set
                AbortDiscoveryToBaseline("TEST ALL ended incompletely — restoring last complete results");
            }
            SetBusy(false);
            EndOp();
            EndOpTracking();
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
                if (!_connection.TunnelPathVerified || !_connection.UsableInternetVerified || !_connection.IsConnected)
                {
                    _log.Warn("VPN Speed Test blocked — usable TUN internet not verified");
                    TxtSpeedVpn.Text = "VPN: BLOCKED — usable internet not verified";
                    return;
                }

                var health = await _connection.VerifyHealthAsync(CancellationToken.None);
                if (!health.ok || !string.Equals(health.exitIp, _cred.server_ip, StringComparison.Ordinal))
                {
                    _log.Warn($"VPN Speed Test blocked — health/exit IP check failed: {health.detail}");
                    TxtSpeedVpn.Text = $"VPN: BLOCKED — {health.detail}";
                    return;
                }

                using var speedCts = new CancellationTokenSource(TimeSpan.FromSeconds(90));
                var p = _connection.ActiveMethod;
                _vpnSpeed = await _speed.RunAsync("VPN", p?.DisplayName, null, speedCts.Token);
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

    private async void DiagC01_Click(object sender, RoutedEventArgs e)
    {
        if (_connection.IsTunnelRunning || _uiState is ConnectionUiState.Connected or ConnectionUiState.Degraded)
        {
            _log.Warn("DIAG C01 refused — disconnect VPN first");
            return;
        }

        if (!TryBeginOp()) return;
        BeginOpTracking();
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _userRequestedDisconnect = false;
        SetBusy(true);
        SetUiState(ConnectionUiState.Testing, "DIAG C01 proxy vs TUN");
        try
        {
            var c01 = _methods.FirstOrDefault(m => m.Id == "C01")
                      ?? ProtocolCatalog.BuildMethods(_cred).First(m => m.Id == "C01");
            var diag = new ProxyTunCompareDiagnostic(_log, _cred, _connection);
            var report = await diag.RunAsync(c01, ct);
            TxtSpeedVpn.Text =
                $"DIAG: P={report.Proxy.DownloadStatus}/{report.Proxy.BytesReceived}B " +
                $"T={report.Tun.DownloadStatus}/{report.Tun.BytesReceived}B [{report.Confidence}]";
            SetUiState(
                report.CleanupOk ? ConnectionUiState.Disconnected : ConnectionUiState.Failed,
                report.CleanupOk ? Truncate(report.Summary, 78) : report.CleanupDetail);
            _log.Info($"DIAG hypothesis[{report.Confidence}]: {report.Hypothesis}");
            if (!string.IsNullOrWhiteSpace(report.NextStep))
                _log.Info($"DIAG nextStep: {report.NextStep}");
        }
        catch (OperationCanceledException)
        {
            _log.Warn("DIAG C01 cancelled — forcing cleanup");
            try { await _connection.DisconnectAsync(); } catch { /* ignore */ }
            SetUiState(ConnectionUiState.Disconnected);
        }
        catch (Exception ex)
        {
            _log.Error($"DIAG C01 error: {ex.Message}");
            try { await _connection.DisconnectAsync(); } catch { /* ignore */ }
            SetUiState(ConnectionUiState.Failed, ex.Message);
        }
        finally
        {
            SetBusy(false);
            EndOp();
            EndOpTracking();
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

    private async void Disconnect_Click(object sender, RoutedEventArgs e)
    {
        if (_uiState is ConnectionUiState.Testing or ConnectionUiState.Connecting
            or ConnectionUiState.Verifying or ConnectionUiState.Switching)
        {
            _log.Warn("Cancel requested");
            _userRequestedDisconnect = true;
            _cts?.Cancel();
            return;
        }

        await DoDisconnectAsync();
    }

    private async Task DoDisconnectAsync()
    {
        // Manual disconnect wins: stop monitor/auto-failover first, then wait for other ops
        _userRequestedDisconnect = true;
        _healthFailStreak = 0;
        _healthTimer.Stop();
        _durationTimer.Stop();
        _cts?.Cancel();

        var deadline = DateTime.UtcNow.AddSeconds(20);
        var acquiredOp = false;
        while (!(acquiredOp = TryBeginOp()))
        {
            if (DateTime.UtcNow >= deadline)
            {
                _log.Warn("Disconnect: timed out waiting for connect/failover lock — forcing cleanup");
                break;
            }
            await Task.Delay(100);
        }

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
            if (acquiredOp) EndOp();
        }
    }

    private async Task HealthTickAsync()
    {
        if (_userRequestedDisconnect) return;
        if (_uiState is not (ConnectionUiState.Connected or ConnectionUiState.Degraded)) return;
        if (Interlocked.CompareExchange(ref _healthGate, 1, 0) != 0) return;

        try
        {
            // TUN dead → do not wait for a second soft failure
            if (!_connection.IsTunnelRunning)
            {
                _log.Warn("Health monitor: TUN no longer running — immediate failover path");
                _healthFailStreak = 2;
                SetUiState(ConnectionUiState.Degraded, "TUN stopped");
                await FailoverAfterHealthAsync(null, "TUN stopped");
                return;
            }

            var (ok, exitIp, detail) = await _connection.VerifyHealthAsync(CancellationToken.None);
            if (_userRequestedDisconnect) return;

            if (ok)
            {
                var recovered = _healthFailStreak > 0 || _uiState == ConnectionUiState.Degraded;
                _healthFailStreak = 0;
                if (recovered || _uiState != ConnectionUiState.Connected)
                {
                    _log.Info("Health recovered — returning to CONNECTED");
                    SetUiState(ConnectionUiState.Connected);
                    if (_connection.ActiveMethod != null)
                    {
                        TxtExitIp.Text = $"Exit IP: {_connection.ActiveMethod.ExitIp ?? exitIp ?? "—"}";
                        TxtConnStatus.Text = "Status: CONNECTED";
                    }
                }
                return;
            }

            // First failure: DEGRADED; keep TUN up so the next tick can confirm
            _healthFailStreak++;
            _log.Warn($"Health check failed ({_healthFailStreak}): {detail}");
            SetUiState(ConnectionUiState.Degraded, detail);

            if (_healthFailStreak < 2) return;
            if (_userRequestedDisconnect) return;

            await FailoverAfterHealthAsync(exitIp, detail);
        }
        finally
        {
            Interlocked.Exchange(ref _healthGate, 0);
        }
    }

    private async Task FailoverAfterHealthAsync(string? previousExitIp, string detail)
    {
        if (_userRequestedDisconnect) return;
        if (!TryBeginOp())
        {
            _log.Warn("Failover skipped — another operation in progress");
            return;
        }

        _healthTimer.Stop();
        try
        {
            var failedId = _connection.ActiveMethod?.Id;
            var netFp = PersistenceService.CaptureNetworkFingerprint();
            if (!string.IsNullOrEmpty(failedId))
            {
                _persist.RecordTunFailure(_state, failedId, netFp,
                    _connection.LastHealthFailureCategory ?? ConnectionService.ClassifyHealthCategory(detail),
                    detail);
                _log.Warn($"Recorded post-connect TUN failure for {failedId} on network {netFp}");
            }

            var nextPreview = _methods
                .Where(m => m.Status == TestStatus.Pass)
                .Where(m => failedId == null || !string.Equals(m.Id, failedId, StringComparison.OrdinalIgnoreCase))
                .Where(m => !_persist.GetTunFailureIdsForNetwork(_state, netFp).Contains(m.Id, StringComparer.OrdinalIgnoreCase))
                .OrderBy(m => m.Rank == 0 ? int.MaxValue : m.Rank)
                .ThenByDescending(m => m.QualityScore)
                .FirstOrDefault();

            SetUiState(ConnectionUiState.Switching,
                nextPreview == null
                    ? "No alternate protocol"
                    : $"From {failedId ?? "?"} → {nextPreview.Id}");
            _log.Info(
                $"SWITCHING after sustained health failure — next candidate: {(nextPreview == null ? "(none)" : nextPreview.Id)}");

            var (discOk, discMsg) = await _connection.DisconnectAsync();
            if (!discOk)
            {
                ClearConnInfo();
                SetUiState(ConnectionUiState.Failed, discMsg);
                _log.Fail($"Recovery aborted — cleanup failed: {discMsg}");
                return;
            }

            if (_userRequestedDisconnect)
            {
                ClearConnInfo();
                SetUiState(ConnectionUiState.Disconnected);
                return;
            }

            var ranked = _methods
                .Where(m => m.Status == TestStatus.Pass)
                .Where(m => failedId == null || !string.Equals(m.Id, failedId, StringComparison.OrdinalIgnoreCase))
                .Where(m => !_persist.GetTunFailureIdsForNetwork(_state, netFp).Contains(m.Id, StringComparer.OrdinalIgnoreCase))
                .OrderBy(m => m.Rank == 0 ? int.MaxValue : m.Rank)
                .ThenByDescending(m => m.QualityScore)
                .ToList();

            var discovery = new DiscoveryService(_log, _cred);
            string? lastFail = null;

            void OnPhase(string phase, string d)
            {
                Dispatcher.Invoke(() =>
                {
                    if (phase == "VERIFYING") SetUiState(ConnectionUiState.Verifying, d);
                    else if (phase == "SWITCHING") SetUiState(ConnectionUiState.Switching, d);
                    else if (phase == "CONNECTING") SetUiState(ConnectionUiState.Connecting, d);
                });
            }

            void OnFailed(ProtocolMethod failedMethod, string failMsg)
            {
                var cat = _connection.LastHealthFailureCategory
                          ?? ConnectionService.ClassifyHealthCategory(failMsg);
                _persist.RecordTunFailure(_state, failedMethod.Id, netFp, cat, failMsg);
            }

            foreach (var m in ranked)
            {
                if (_userRequestedDisconnect) break;

                SetUiState(ConnectionUiState.Switching, $"Trying {m.Id} {m.DisplayName}");
                _log.Info($"Failover recheck+TUN for {m.Id} (sequential, not bulk recheck)");
                var (rOk, rDetail) = await discovery.QuickRecheckAsync(m, CancellationToken.None);
                if (!rOk)
                {
                    lastFail = $"{m.Id}: {rDetail}";
                    _log.Warn($"Failover recheck failed: {lastFail}");
                    continue;
                }

                var (reOk, msg) = await _connection.ConnectBestAsync(
                    new[] { m }, CancellationToken.None, OnPhase, OnFailed);
                if (reOk && _connection.IsConnected && _connection.UsableInternetVerified)
                {
                    _healthFailStreak = 0;
                    var a = _connection.ActiveMethod!;
                    _persist.ClearTunFailure(_state, a.Id, netFp);
                    ApplyConnectedUi(a, TimeSpan.Zero);
                    TxtExitIp.Text = $"Exit IP: {a.ExitIp ?? previousExitIp ?? "—"}";
                    _persist.Save(_state, _cred);
                    _healthTimer.Start();
                    _log.Info($"Failover CONNECTED via {a.Id}");
                    return;
                }

                lastFail = msg;
                if (ConnectionService.IsFatalMessage(msg) ||
                    msg.Contains("Cleanup Error", StringComparison.OrdinalIgnoreCase) ||
                    ConnectionService.ShouldStopCascadeForSharedEvidence(
                        _connection.LastHealthFailureCategory ?? ConnectionService.ClassifyHealthCategory(msg),
                        2, msg))
                {
                    break;
                }
            }

            ClearConnInfo();
            var failMsg = lastFail ?? "No usable alternate protocol after health failure";
            SetUiState(ConnectionUiState.Failed, failMsg);
            _log.Fail(failMsg);
            _persist.Save(_state, _cred);
        }
        finally
        {
            EndOp();
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
        // Only persist when UI methods reflect a complete/consistent session — never mid TEST ALL
        if (_testAllBaseline != null || _uiState == ConnectionUiState.Testing)
        {
            _log.Warn("SaveResultsSnapshot skipped — TEST ALL in progress; refusing to overwrite complete results");
            return;
        }

        var ui = _state.Ui;
        ui.AutoScrollLog = ChkAutoScroll.IsChecked == true;
        _state = _persist.CaptureFromMethods(
            _methods,
            _cred,
            _state.LastTestAtUtc,
            _state.BestMethodId ?? _methods.Where(m => m.Status == TestStatus.Pass).OrderBy(m => m.Rank).FirstOrDefault()?.Id,
            resultsStale: _state.ResultsStale,
            staleReason: _state.StaleReason,
            lastTestIncomplete: false,
            tunFailures: _state.TunFailures);
        _state.Ui = ui;
        _persist.Save(_state, _cred);
        _lastCompleteState = CloneState(_state);
        UpdatePersistMeta();
    }

    private void PersistUiPrefsPreservingCompleteResults()
    {
        var complete = CloneState(_lastCompleteState);
        complete.Ui.AutoScrollLog = ChkAutoScroll.IsChecked == true;
        // Keep last complete method rows from disk baseline — do not capture in-progress grid
        _persist.ApplyToMethods(complete, _methods);
        DiscoveryService.Rank(_methods.ToList());
        _state = complete;
        _lastCompleteState = CloneState(complete);
        _persist.Save(complete, _cred);
        RefreshGrids();
        UpdatePersistMeta();
        _log.Info("UI prefs saved; last complete protocol results preserved");
    }

    private void AbortDiscoveryToBaseline(string reason)
    {
        var baseline = _testAllBaseline ?? _lastCompleteState;
        _log.Warn(reason);
        _persist.ApplyToMethods(baseline, _methods);
        DiscoveryService.Rank(_methods.ToList());
        _state = CloneState(baseline);
        _state.LastTestIncomplete = true; // in-memory note only — disk keeps last complete Save
        _testAllBaseline = null;
        RefreshGrids();
        UpdatePersistMeta();
    }

    private void RestoreLastCompleteToUi(string reason)
    {
        _log.Warn(reason);
        _persist.ApplyToMethods(_lastCompleteState, _methods);
        DiscoveryService.Rank(_methods.ToList());
        _state = CloneState(_lastCompleteState);
        _testAllBaseline = null;
        RefreshGrids();
        UpdatePersistMeta();
    }

    private void BeginOpTracking()
    {
        _activeOpCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private void EndOpTracking()
    {
        _activeOpCompletion?.TrySetResult();
        _activeOpCompletion = null;
    }

    private async Task WaitForActiveOpAsync(TimeSpan timeout)
    {
        var tcs = _activeOpCompletion;
        if (tcs == null) return;
        var finished = await Task.WhenAny(tcs.Task, Task.Delay(timeout));
        if (finished != tcs.Task)
        {
            _log.Warn($"Timed out waiting for active operation after {timeout.TotalSeconds:F0}s");
        }
    }

    private static PersistedLabState CloneState(PersistedLabState src) => new()
    {
        SchemaVersion = src.SchemaVersion,
        ServerIp = src.ServerIp,
        EngineVersion = src.EngineVersion,
        NetworkFingerprint = src.NetworkFingerprint,
        LastTestAtUtc = src.LastTestAtUtc,
        BestMethodId = src.BestMethodId,
        LastExitIp = src.LastExitIp,
        ResultsStale = src.ResultsStale,
        StaleReason = src.StaleReason,
        LastTestIncomplete = src.LastTestIncomplete,
        Ui = CloneUi(src.Ui),
        TunFailures = src.TunFailures.Select(f => new TunFailureRecord
        {
            MethodId = f.MethodId,
            NetworkFingerprint = f.NetworkFingerprint,
            ReasonCategory = f.ReasonCategory,
            Detail = f.Detail,
            FailedAtUtc = f.FailedAtUtc
        }).ToList(),
        Methods = src.Methods.Select(m => new PersistedMethodResult
        {
            Id = m.Id,
            Status = m.Status,
            LatencyMs = m.LatencyMs,
            JitterMs = m.JitterMs,
            ConnectTimeMs = m.ConnectTimeMs,
            SuccessRate = m.SuccessRate,
            QualityScore = m.QualityScore,
            Rank = m.Rank,
            ExitIp = m.ExitIp,
            LastError = m.LastError,
            SkipReason = m.SkipReason,
            TestedAtUtc = m.TestedAtUtc,
            ProbeAttempts = m.ProbeAttempts,
            ProbeSuccesses = m.ProbeSuccesses,
            FailureKind = m.FailureKind,
            IsHistorical = m.IsHistorical
        }).ToList()
    };

    private static UiPrefs CloneUi(UiPrefs ui) => new()
    {
        AutoScrollLog = ui.AutoScrollLog,
        LastSelectedMethodId = ui.LastSelectedMethodId
    };

    private void UpdatePersistMeta()
    {
        if (_state.LastTestAtUtc == null && _state.Methods.Count == 0)
        {
            TxtPersistMeta.Text = "Results: none saved yet";
            return;
        }

        var local = _state.LastTestAtUtc?.ToLocalTime();
        var cached = _methods.Count(m => m.IsHistorical);
        var parts = new List<string>();
        if (local != null)
        {
            parts.Add($"Last test: {local:yyyy-MM-dd HH:mm}");
        }
        if (!string.IsNullOrWhiteSpace(_state.BestMethodId))
        {
            parts.Add($"best {_state.BestMethodId}");
        }
        parts.Add(cached > 0 ? $"{cached} cached" : "live session marks only");
        if (_state.ResultsStale)
        {
            parts.Add($"STALE: {_state.StaleReason}");
        }
        if (_state.LastTestIncomplete)
        {
            parts.Add("last TEST ALL cancelled");
        }
        TxtPersistMeta.Text = string.Join(" · ", parts);
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
        var cancellable = _uiState is ConnectionUiState.Testing or ConnectionUiState.Connecting
            or ConnectionUiState.Verifying or ConnectionUiState.Switching;
        var op = busy || cancellable || _uiState == ConnectionUiState.Degraded;
        BtnTestAll.IsEnabled = (!op && !vpnActive) || cancellable;
        BtnSpeed.IsEnabled = !busy && !cancellable;
        BtnDiagC01.IsEnabled = !busy && !cancellable && !vpnActive &&
                               _uiState is ConnectionUiState.Disconnected or ConnectionUiState.Failed;
        BtnConnectTop.IsEnabled = (!busy || _uiState == ConnectionUiState.Connected) || cancellable;
        BtnConnect.IsEnabled = BtnConnectTop.IsEnabled;
        BtnDisconnect.IsEnabled = cancellable ||
                                  (!busy && _uiState is ConnectionUiState.Connected or ConnectionUiState.Degraded);
        BtnDisconnect.Content = cancellable ? "CANCEL" : "DISCONNECT";
    }

    private void SetUiState(ConnectionUiState state, string? detail = null)
    {
        _uiState = state;
        var label = state switch
        {
            ConnectionUiState.Disconnected => "DISCONNECTED",
            ConnectionUiState.Testing => "TESTING",
            ConnectionUiState.Connecting => "CONNECTING",
            ConnectionUiState.Verifying => "VERIFYING",
            ConnectionUiState.Connected => "CONNECTED",
            ConnectionUiState.Degraded => "DEGRADED",
            ConnectionUiState.Switching => "SWITCHING",
            ConnectionUiState.Failed => "FAILED",
            _ => state.ToString()
        };
        TxtStatus.Text = string.IsNullOrWhiteSpace(detail) ||
                         state is not (ConnectionUiState.Failed or ConnectionUiState.Verifying or ConnectionUiState.Switching or ConnectionUiState.Degraded)
            ? label
            : Truncate($"{label}: {detail}", 78);
        TxtConnStatus.Text = $"Status: {label}";

        var vpnActive = state == ConnectionUiState.Connected || _connection.IsConnected;
        var cancellable = state is ConnectionUiState.Testing or ConnectionUiState.Connecting
            or ConnectionUiState.Verifying or ConnectionUiState.Switching;
        BtnTestAll.IsEnabled = (!vpnActive && state is not (ConnectionUiState.Connecting or ConnectionUiState.Verifying
            or ConnectionUiState.Switching or ConnectionUiState.Degraded)) || state == ConnectionUiState.Testing;
        BtnDiagC01.IsEnabled = state is ConnectionUiState.Disconnected or ConnectionUiState.Failed;
        BtnDisconnect.IsEnabled = cancellable || state is ConnectionUiState.Connected or ConnectionUiState.Degraded;
        BtnDisconnect.Content = cancellable ? "CANCEL" : "DISCONNECT";
        BtnConnectTop.Content = "CONNECT";

        var (fg, bg) = state switch
        {
            ConnectionUiState.Connected => ("#2ECC71", "#143022"),
            ConnectionUiState.Connecting => ("#E6B450", "#2A2415"),
            ConnectionUiState.Verifying => ("#3DB9F5", "#15202A"),
            ConnectionUiState.Switching => ("#E6B450", "#2A2415"),
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
