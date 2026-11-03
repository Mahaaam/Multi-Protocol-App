using System.Threading;
using System.Windows;

namespace DirectVpnLab;

public partial class App : Application
{
    private static Mutex? _mutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        const string name = @"Global\DirectVpnLab_SingleInstance_v1";
        _mutex = new Mutex(true, name, out var created);
        if (!created)
        {
            MessageBox.Show(
                "Direct VPN Lab is already running.\nنسخه دیگری از برنامه در حال اجرا است.",
                "Direct VPN Lab",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            Shutdown(1);
            return;
        }

        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            _mutex?.ReleaseMutex();
            _mutex?.Dispose();
        }
        catch
        {
            // ignore
        }
        base.OnExit(e);
    }
}
