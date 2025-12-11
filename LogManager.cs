using System;
using System.IO;
using System.Text;

namespace SecurityMonitorPro.Core;

public class LogManager
{
    private static readonly string LogDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");
    private static readonly string LogFilePath = Path.Combine(LogDirectory, $"SecurityMonitor_{DateTime.Now:yyyy-MM-dd}.log");
    private static readonly object _lockObject = new();

    public static void Initialize()
    {
        try
        {
            if (!Directory.Exists(LogDirectory))
            {
                Directory.CreateDirectory(LogDirectory);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to create log directory: {ex.Message}");
        }
    }

    public static void WriteLog(string message, LogLevel level = LogLevel.Info)
{
    try
    {
        lock (_lockObject)
        {
            var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            var levelStr = level.ToString().ToUpper().PadRight(7);
            var logEntry = $"[{timestamp}] [{levelStr}] {message}";
            
            // Write to console with color
            var originalColor = Console.ForegroundColor;
            Console.ForegroundColor = level switch
            {
                LogLevel.Info => ConsoleColor.Cyan,
                LogLevel.Warning => ConsoleColor.Yellow,
                LogLevel.Error => ConsoleColor.Red,
                LogLevel.Success => ConsoleColor.Green,
                LogLevel.Debug => ConsoleColor.Gray,
                _ => ConsoleColor.White
            };
            Console.WriteLine(logEntry);
            Console.ForegroundColor = originalColor;
            
            // Write to file
            File.AppendAllText(LogFilePath, logEntry + Environment.NewLine);
            
            // Rotate logs if file gets too large (>10MB)
            var fileInfo = new FileInfo(LogFilePath);
            if (fileInfo.Exists && fileInfo.Length > 10 * 1024 * 1024)
            {
                RotateLogs();
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Failed to write log: {ex.Message}");
    }
}


    private static void RotateLogs()
    {
        try
        {
            var archivePath = Path.Combine(LogDirectory, $"SecurityMonitor_{DateTime.Now:yyyy-MM-dd_HHmmss}_archived.log");
            File.Move(LogFilePath, archivePath);
            
            // Keep only last 10 log files
            var logFiles = Directory.GetFiles(LogDirectory, "*.log")
                .OrderByDescending(f => File.GetCreationTime(f))
                .Skip(10)
                .ToArray();
            
            foreach (var file in logFiles)
            {
                File.Delete(file);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to rotate logs: {ex.Message}");
        }
    }

    public static string[] GetRecentLogs(int maxLines = 1000)
    {
        try
        {
            if (!File.Exists(LogFilePath))
                return Array.Empty<string>();
            
            var allLines = File.ReadAllLines(LogFilePath);
            return allLines.TakeLast(maxLines).ToArray();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to read logs: {ex.Message}");
            return new[] { $"Error reading logs: {ex.Message}" };
        }
    }

    public static void ClearLogs()
    {
        try
        {
            lock (_lockObject)
            {
                if (File.Exists(LogFilePath))
                {
                    File.Delete(LogFilePath);
                }
                WriteLog("Logs cleared by user", LogLevel.Info);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to clear logs: {ex.Message}");
        }
    }

    public static string ExportLogs()
    {
        try
        {
            var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            var exportPath = Path.Combine(desktopPath, $"SecurityMonitor_Logs_{DateTime.Now:yyyy-MM-dd_HHmmss}.txt");
            
            if (File.Exists(LogFilePath))
            {
                File.Copy(LogFilePath, exportPath, true);
                return exportPath;
            }
            
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to export logs: {ex.Message}");
            return null;
        }
    }

    public static string GetLogFilePath() => LogFilePath;
}

public enum LogLevel
{
    Info,
    Warning,
    Error,
    Success,
    Debug
}