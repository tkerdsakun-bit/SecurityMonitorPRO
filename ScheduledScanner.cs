using SecurityMonitorPro.Models;

namespace SecurityMonitorPro.Core;

public class ScheduledScanner : IDisposable
{
    public event Action? ScanTriggered;
    public event Action<string>? StatusChanged;
    
    private System.Threading.Timer? _timer;
    private ScanSchedule? _schedule;

    public void Start(int intervalMinutes)
    {
        Stop();
        
        _schedule = new ScanSchedule
        {
            Enabled = true,
            IntervalMinutes = intervalMinutes,
            LastScan = null,
            NextScan = DateTime.Now.AddMinutes(intervalMinutes)
        };

        var intervalMs = intervalMinutes * 60 * 1000;
        _timer = new System.Threading.Timer(OnTimerTick, null, intervalMs, intervalMs);
        
        StatusChanged?.Invoke($"Auto-scan scheduled every {intervalMinutes} minutes");
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
        if (_schedule != null)
        {
            _schedule.Enabled = false;
        }
        StatusChanged?.Invoke("Auto-scan disabled");
    }

    private void OnTimerTick(object? state)
    {
        if (_schedule?.Enabled == true)
        {
            _schedule.LastScan = DateTime.Now;
            _schedule.NextScan = DateTime.Now.AddMinutes(_schedule.IntervalMinutes);
            ScanTriggered?.Invoke();
        }
    }

    public ScanSchedule? GetSchedule() => _schedule;

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}