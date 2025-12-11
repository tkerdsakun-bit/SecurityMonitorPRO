using Microsoft.Win32;

namespace SecurityMonitorPro.Core;

public class StartupScanner
{
    public List<StartupItem> ScanStartupPrograms()
    {
        var items = new List<StartupItem>();

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            if (key != null)
            {
                foreach (var valueName in key.GetValueNames())
                {
                    items.Add(new StartupItem
                    {
                        Name = valueName,
                        Path = key.GetValue(valueName)?.ToString() ?? "",
                        Location = "HKCU\\Run"
                    });
                }
            }

            using var key2 = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            if (key2 != null)
            {
                foreach (var valueName in key2.GetValueNames())
                {
                    items.Add(new StartupItem
                    {
                        Name = valueName,
                        Path = key2.GetValue(valueName)?.ToString() ?? "",
                        Location = "HKLM\\Run"
                    });
                }
            }
        }
        catch { }

        return items;
    }
}

public record StartupItem
{
    public required string Name { get; init; }
    public required string Path { get; init; }
    public required string Location { get; init; }
}