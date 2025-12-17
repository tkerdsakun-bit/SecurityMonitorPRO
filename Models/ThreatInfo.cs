namespace SecurityMonitorPro.Models;

public record ThreatInfo
{
    public required string Type { get; init; }
    public required string FileName { get; init; }
    public required string FilePath { get; init; }
    public long Size { get; init; }
    public required string SizeString { get; init; }
    public required string RiskLevel { get; init; }
    public DateTime DetectedAt { get; init; } = DateTime.Now;
    public bool IsQuarantined { get; set; }
    public string? VirusTotalResult { get; set; }
    public int? VirusTotalDetections { get; set; }
}

public record ScanSchedule
{
    public bool Enabled { get; set; }
    public int IntervalMinutes { get; set; }
    public DateTime? LastScan { get; set; }
    public DateTime? NextScan { get; set; }
}

public record RansomwareSignature
{
    public required string Name { get; init; }
    public required string Extension { get; init; }
    public required string Family { get; init; }
    public DateTime AddedDate { get; init; } = DateTime.Now;
}
