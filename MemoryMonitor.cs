using System.Diagnostics;

namespace SecurityMonitorPro.Core;

public class MemoryMonitor : IDisposable
{
    public event Action<string, long>? SuspiciousActivityDetected;
    
    private System.Threading.Timer? _timer;
    private readonly long _threshold = 500 * 1024 * 1024;
    private readonly Dictionary<int, long> _memoryCache = new();

    public void Start() => 
        _timer = new System.Threading.Timer(CheckMemory, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));

    public void Stop() => _timer?.Dispose();

    private void CheckMemory(object? state)
    {
        try
        {
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    var mem = process.WorkingSet64;
                    if (mem > _threshold)
                    {
                        if (_memoryCache.TryGetValue(process.Id, out var prev))
                        {
                            var growth = mem - prev;
                            if (growth > 100 * 1024 * 1024 && (growth / (double)prev) > 0.5)
                            {
                                SuspiciousActivityDetected?.Invoke(process.ProcessName, mem);
                            }
                        }
                        _memoryCache[process.Id] = mem;
                    }
                }
                finally { process.Dispose(); }
            }
            
            if (_memoryCache.Count > 100) _memoryCache.Clear();
        }
        catch { }
    }

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}