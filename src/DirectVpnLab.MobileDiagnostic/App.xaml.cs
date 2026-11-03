using System.Windows;

namespace DirectVpnLab.MobileDiagnostic;

public partial class App : Application
{
    private void App_OnStartup(object sender, StartupEventArgs e)
    {
        MobileDiagnosticEngine.ApplyIsolatedRuntime();

        if (e.Args.Any(a => string.Equals(a, "--write-sample-report", StringComparison.OrdinalIgnoreCase)))
        {
            var (json, txt) = MobileDiagnosticEngine.WriteSampleReportForValidation();
            Console.WriteLine("SAMPLE_JSON=" + json);
            Console.WriteLine("SAMPLE_TXT=" + txt);
            Shutdown(0);
            return;
        }

        if (e.Args.Any(a => string.Equals(a, "--self-test-safety", StringComparison.OrdinalIgnoreCase)))
        {
            var result = MobileDiagnosticEngine.RunSafetySelfTests();
            Console.WriteLine(result);
            var code = result.Contains("SAFETY_SELFTEST=PASS", StringComparison.Ordinal) ? 0 : 2;
            Shutdown(code);
            return;
        }

        if (e.Args.Any(a => string.Equals(a, "--check-only", StringComparison.OrdinalIgnoreCase)))
        {
            var log = new DirectVpnLab.Services.LiveLogService(Current.Dispatcher);
            var engine = new MobileDiagnosticEngine(log);
            engine.EnsureReady();
            var path = engine.CheckNetwork();
            Console.WriteLine($"PathOk={path.PathOk}");
            Console.WriteLine($"Status={path.MobileNetworkStatus}");
            Console.WriteLine($"Effective={path.EffectiveToServer}");
            Console.WriteLine($"Interface={path.EffectiveInterface}");
            Console.WriteLine($"NextHop={path.EffectiveNextHop}");
            Console.WriteLine($"Gateway={path.Gateway}");
            Console.WriteLine($"Public={path.PublicIpv4}");
            Console.WriteLine($"RuntimeDir={DirectVpnLab.Services.AppPaths.RuntimeDir}");
            Console.WriteLine($"WireGuardEffective={path.WireGuardEffective}");
            Shutdown(path.PathOk ? 0 : 3);
            return;
        }

        MainWindow = new MainWindow();
        MainWindow.Show();
    }
}
