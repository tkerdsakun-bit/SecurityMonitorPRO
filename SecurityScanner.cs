using SecurityMonitorPro.Models;

namespace SecurityMonitorPro.Core;

public class SecurityScanner
{
    // Performance Mode controls
    public static int MaxThreads = 2;        // Default = Normal Mode
    public static int ScanDelayMs = 0;       // Default = no delay

    // Semaphore for limiting CPU / threads
    private static SemaphoreSlim _sem = new SemaphoreSlim(MaxThreads);

    public event Action<int>? ProgressChanged;
    public event Action<ThreatInfo>? ThreatDetected;
    public event Action<int, int>? ScanCompleted;
    public event Action<string>? StatusChanged;

    private readonly ThreatDatabase _threatDb;
    private readonly VirusTotalAPI _virusTotal;
    private int _skippedFolders = 0;

    public SecurityScanner(string? virusTotalApiKey = null)
    {
        _threatDb = new ThreatDatabase();
        _virusTotal = new VirusTotalAPI(virusTotalApiKey ?? "");
    }

    public async Task ScanDirectoryAsync(string path, CancellationToken cancellationToken, bool checkVirusTotal = false)
    {
        var threatsFound = 0;
        var totalFiles = 0;
        _skippedFolders = 0;

        StatusChanged?.Invoke("Enumerating files...");

        try
        {
            var files = GetAccessibleFiles(path, cancellationToken).ToList();
            totalFiles = files.Count;

            if (_skippedFolders > 0)
            {
                StatusChanged?.Invoke($"Found {totalFiles} files ({_skippedFolders} folders skipped)");
                await Task.Delay(1000);
            }

            var processedFiles = 0;

            foreach (var file in files)
            {
                if (cancellationToken.IsCancellationRequested) break;

                // LIMIT RESOURCE USAGE
                await _sem.WaitAsync(cancellationToken);
                try
                {
                    if (ScanDelayMs > 0)
                        await Task.Delay(ScanDelayMs, cancellationToken);

                    try
                    {
                        var fileInfo = new FileInfo(file);
                        StatusChanged?.Invoke($"Scanning: {fileInfo.Name} ({processedFiles}/{totalFiles})");

                        // --- 0 KB FILE ---
                        if (fileInfo.Length == 0 && !IsSystemFile(fileInfo))
                        {
                            ThreatDetected?.Invoke(new ThreatInfo
                            {
                                Type = "0KB File",
                                FileName = fileInfo.Name,
                                FilePath = fileInfo.FullName,
                                Size = 0,
                                SizeString = "0 KB",
                                RiskLevel = "Low"
                            });
                            threatsFound++;
                        }

                        // --- EXTENSION CHECK ---
                        var extension = Path.GetExtension(file);
                        var (isThreat, family) = _threatDb.CheckExtension(extension);

                        if (isThreat)
                        {
                            var threat = new ThreatInfo
                            {
                                Type = $"Ransomware ({family})",
                                FileName = fileInfo.Name,
                                FilePath = fileInfo.FullName,
                                Size = fileInfo.Length,
                                SizeString = FormatFileSize(fileInfo.Length),
                                RiskLevel = "Critical"
                            };

                            if (checkVirusTotal)
                            {
                                try
                                {
                                    var (isMalicious, detections, result) = await _virusTotal.CheckFileHashAsync(file);
                                    threat.VirusTotalResult = result;
                                    threat.VirusTotalDetections = detections;
                                }
                                catch { }
                            }

                            ThreatDetected?.Invoke(threat);
                            threatsFound++;
                        }

                        // --- NAME CHECK ---
                        if (IsSuspiciousName(fileInfo.Name))
                        {
                            ThreatDetected?.Invoke(new ThreatInfo
                            {
                                Type = "Suspicious",
                                FileName = fileInfo.Name,
                                FilePath = fileInfo.FullName,
                                Size = fileInfo.Length,
                                SizeString = FormatFileSize(fileInfo.Length),
                                RiskLevel = "Suspicious"
                            });
                            threatsFound++;
                        }
                    }
                    catch { /* skip failed files */ }

                    processedFiles++;
                    if (totalFiles > 0)
                    {
                        var progress = (int)((double)processedFiles / totalFiles * 100);
                        ProgressChanged?.Invoke(progress);
                    }
                }
                finally
                {
                    _sem.Release();
                }
            }
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke($"Scan error: {ex.Message}");
        }

        var summary = _skippedFolders > 0
            ? $"Scan completed - {_skippedFolders} folders skipped"
            : "Scan completed";

        StatusChanged?.Invoke(summary);
        ScanCompleted?.Invoke(threatsFound, totalFiles);
    }

    private IEnumerable<string> GetAccessibleFiles(string rootPath, CancellationToken cancellationToken)
    {
        var foldersToScan = new Queue<string>();
        foldersToScan.Enqueue(rootPath);

        while (foldersToScan.Count > 0 && !cancellationToken.IsCancellationRequested)
        {
            var currentFolder = foldersToScan.Dequeue();

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(currentFolder); }
            catch { _skippedFolders++; continue; }

            foreach (var file in files)
            {
                if (cancellationToken.IsCancellationRequested) yield break;
                yield return file;
            }

            string[] subFolders = Array.Empty<string>();
            try { subFolders = Directory.GetDirectories(currentFolder); }
            catch { _skippedFolders++; continue; }

            foreach (var folder in subFolders)
            {
                var folderName = Path.GetFileName(folder);
                if (ShouldSkipFolder(folderName))
                {
                    _skippedFolders++;
                    continue;
                }

                foldersToScan.Enqueue(folder);
            }
        }
    }

    private static readonly HashSet<string> _foldersToSkip = new(StringComparer.OrdinalIgnoreCase)
    {
        "$Recycle.Bin",
        "System Volume Information",
        "$Windows.~BT",
        "$Windows.~WS",
        "WindowsApps",
        "OneDriveTemp"
    };

    private bool ShouldSkipFolder(string folderName)
        => _foldersToSkip.Contains(folderName);

    public async Task ScanEntirePCAsync(CancellationToken cancellationToken, bool checkVirusTotal = false)
    {
        StatusChanged?.Invoke("Scanning all drives...");
        var drives = DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed);

        foreach (var drive in drives)
        {
            if (cancellationToken.IsCancellationRequested) break;

            StatusChanged?.Invoke($"Scanning drive: {drive.Name}");
            await ScanDirectoryAsync(drive.RootDirectory.FullName, cancellationToken, checkVirusTotal);
        }
    }

    public bool IsRansomwarePattern(string filePath)
    {
        var extension = Path.GetExtension(filePath);
        var (isThreat, _) = _threatDb.CheckExtension(extension);
        return isThreat;
    }

    private static readonly HashSet<string> _suspiciousNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "DECRYPT_INSTRUCTION", "HOW_TO_DECRYPT", "README",
        "RESTORE_FILES", "YOUR_FILES_ARE_ENCRYPTED", "HELP_DECRYPT",
        "RECOVER_FILES", "FILES_ENCRYPTED"
    };

    private bool IsSuspiciousName(string fileName)
        => _suspiciousNames.Any(s => fileName.Contains(s, StringComparison.OrdinalIgnoreCase));

    private static bool IsSystemFile(FileInfo fi)
        => (fi.Attributes & FileAttributes.System) == FileAttributes.System;

    private static string FormatFileSize(long bytes)
    {
        string[] sizes = ["B", "KB", "MB", "GB", "TB"];
        double len = bytes;
        int order = 0;

        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }

        return $"{len:0.##} {sizes[order]}";
    }

    public int GetDatabaseSignatureCount()
        => _threatDb.GetSignatureCount();
}
