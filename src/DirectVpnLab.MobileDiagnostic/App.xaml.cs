using System.Windows;

namespace DirectVpnLab.MobileDiagnostic;

public partial class App : Application
{
    private void App_OnStartup(object sender, StartupEventArgs e)
    {
        if (e.Args.Any(a => string.Equals(a, "--write-sample-report", StringComparison.OrdinalIgnoreCase)))
        {
            var (json, txt) = MobileDiagnosticEngine.WriteSampleReportForValidation();
            Console.WriteLine("SAMPLE_JSON=" + json);
            Console.WriteLine("SAMPLE_TXT=" + txt);
            Shutdown(0);
            return;
        }

        MainWindow = new MainWindow();
        MainWindow.Show();
    }
}
