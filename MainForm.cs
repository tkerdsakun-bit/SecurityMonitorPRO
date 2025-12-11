using SecurityMonitorPro.Core;
using SecurityMonitorPro.Models;
using System.Windows.Forms;
using System.Collections;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Configuration;


namespace SecurityMonitorPro.Forms;

public class ListViewItemComparer : IComparer
{
    private readonly int _column;
    private readonly bool _ascending;

    public ListViewItemComparer(int column, bool ascending)
    {
        _column = column;
        _ascending = ascending;
    }

    public int Compare(object? x, object? y)
    {
        var a = x as ListViewItem;
        var b = y as ListViewItem;
        if (a == null || b == null)
            return 0;

        string s1 = a.SubItems[_column].Text;
        string s2 = b.SubItems[_column].Text;

        return _ascending
            ? string.Compare(s1, s2, StringComparison.OrdinalIgnoreCase)
            : string.Compare(s2, s1, StringComparison.OrdinalIgnoreCase);
    }
}


public class MainForm : Form
{
    private int _performanceModeIndex = 1; // Normal

// Define a constant for the default API key
    private const string DefaultVirusTotalApiKey = "1f68b9d312ad4f8cf49c14c8c5a174b60ff26523ebd2131c41f2fe0f53232cd6";

    private bool _isScanning = false;

    private Panel? _sidePanel, _mainPanel, _headerPanel;
    private Button? _btnDashboard, _btnScanner, _btnSchedule, _btnQuarantine, _btnStartup, _btnSettings;
    private Label? _lblZero, _lblSuspicious, _lblMemory, _lblDeleted, _lblStatus, _lblCurrentScan;
    private Label? _lblDbCount, _lblNextScan;
    private ListView? _lvThreats;
    private ProgressBar? _progress;
    private Button? _btnScan, _btnScanPC, _btnStop, _btnQuarantineSelected, _btnDelete;
    private CheckBox? _chkMemory, _chkFiles, _chkVirusTotal;
    private ComboBox? _cmbPath, _cmbInterval;
    private NotifyIcon? _trayIcon;
    private TextBox? _txtVirusTotalKey;
    private ComboBox? _cmbLanguage;

private string _currentFilter = "Show All";    
    // sorting state for the ListView
    private int _lastSortColumn = -1;
    private bool _sortAscending = true;

    private readonly SecurityScanner _scanner;
    private readonly MemoryMonitor _monitor = new();
    private readonly QuarantineManager _quarantine = new();
    private readonly ScheduledScanner _scheduler = new();
    private FileSystemWatcher? _watcher;
    private CancellationTokenSource? _cts;
    
    private int _cntZero, _cntSusp, _cntMem, _cntDel;
    private string _currentView = "dashboard";
    private string? _virusTotalApiKey;

    private bool _isFileMonitoringEnabled = false;
    private bool _isMemoryMonitoringEnabled = false;
    private int _selectedScanLocationIndex = 0;
    private int _selectedIntervalIndex = 3;

    private readonly List<ThreatInfo> _detectedThreats = new();

    public MainForm()
    {
        
        LogManager.Initialize();
        CreateApplicationFolders();

        _scanner = new SecurityScanner();
        InitUI();
        InitEvents();
        InitTrayIcon();
    }

    private void CreateApplicationFolders()
{
    try
    {
        // Get the application's base directory (where the EXE is running from)
        var appDirectory = AppDomain.CurrentDomain.BaseDirectory;
        
        // Create Quarantine folder
        var quarantinePath = Path.Combine(appDirectory, "Quarantine");
        if (!Directory.Exists(quarantinePath))
        {
            Directory.CreateDirectory(quarantinePath);
            Console.WriteLine($"[STARTUP] Created Quarantine folder: {quarantinePath}");
        }
        
        // Create Logs folder (optional, for future use)
        var logsPath = Path.Combine(appDirectory, "Logs");
        if (!Directory.Exists(logsPath))
        {
            Directory.CreateDirectory(logsPath);
            Console.WriteLine($"[STARTUP] Created Logs folder: {logsPath}");
        }
        
        // Create Database folder (optional, for threat signatures)
        var dbPath = Path.Combine(appDirectory, "Database");
        if (!Directory.Exists(dbPath))
        {
            Directory.CreateDirectory(dbPath);
            Console.WriteLine($"[STARTUP] Created Database folder: {dbPath}");
        }
        
        Console.WriteLine("[STARTUP] All application folders verified/created successfully");
    }
    catch (Exception ex)
    {
        MessageBox.Show(
            $"Error creating application folders:\n{ex.Message}\n\nThe Quarantine feature may not work correctly.",
            "Folder Creation Error",
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning
        );
    }
}

    private void InitUI()
    {
        Text = "Security Monitor Pro v1";
        Size = new Size(1400, 900);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(15, 15, 25);
        ForeColor = Color.White;
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimumSize = new Size(1200, 700);

        _mainPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.FromArgb(15, 15, 25),
            Padding = new Padding(20),
            AutoScroll = true
        };
        Controls.Add(_mainPanel);

        _sidePanel = new Panel
        {
            Dock = DockStyle.Right,
            Width = 220,
            BackColor = Color.FromArgb(25, 25, 40)
        };

        var lblSideTitle = new Label
        {
            Text = "🛡️ SECURITY\nMONITOR PRO",
            Font = new Font("Segoe UI", 14F, FontStyle.Bold),
            ForeColor = Color.FromArgb(147, 51, 234),
            Location = new Point(15, 20),
            Size = new Size(190, 60),
            TextAlign = ContentAlignment.MiddleCenter
        };
        _sidePanel.Controls.Add(lblSideTitle);

        var lblVersion = new Label
        {
            Text = "Made By Thitiwat Kerdsakun",
            Font = new Font("Segoe UI", 8F),
            ForeColor = Color.Gray,
            Location = new Point(15, 80),
            Size = new Size(190, 20),
            TextAlign = ContentAlignment.MiddleCenter
        };
        _sidePanel.Controls.Add(lblVersion);

_btnDashboard = CreateNavButton("Dashboard", 120);
_btnScanner = CreateNavButton("Scanner", 180);
_btnSchedule = CreateNavButton("AutoScan", 240);
_btnQuarantine = CreateNavButton("Quarantine", 300);
_btnStartup = CreateNavButton("Startup", 360);
_btnSettings = CreateNavButton("Settings", 420);
var _btnLogs = CreateNavButton("ViewLogs", 480);

_sidePanel.Controls.AddRange(new Control[] { _btnDashboard, _btnScanner, _btnSchedule, _btnQuarantine, _btnStartup, _btnSettings, _btnLogs });
        Controls.Add(_sidePanel);

        ShowDashboard();
    }

private void ApplyThreatFilter(string filter)
{
    if (_lvThreats == null) return;

    _lvThreats.BeginUpdate();
    _lvThreats.Items.Clear();

    foreach (var t in _detectedThreats)
    {
        if (ShouldShowThreat(t, filter))  // ← Uses the new helper method
        {
            var vtText = t.VirusTotalDetections.HasValue ? $"{t.VirusTotalDetections}" : "-";

            var item = new ListViewItem(new[]
            {
                t.Type,
                t.FileName,
                t.FilePath,
                t.SizeString,
                t.RiskLevel,
                vtText,
                "-"
            });
            
            item.ForeColor =
                t.RiskLevel == "Critical" ? Color.Red :
                t.RiskLevel == "High"     ? Color.Orange :
                Color.Yellow;

            item.Tag = t;
            _lvThreats.Items.Add(item);
        }
    }

    _lvThreats.EndUpdate();
}


    private Button CreateNavButton(string key, int y)
{
    var btn = new Button
    {
        Text = Localization.Get(key),
        Location = new Point(10, y),
        Size = new Size(200, 50),
        FlatStyle = FlatStyle.Flat,
        BackColor = Color.FromArgb(35, 35, 55),
        ForeColor = Color.White,
        Font = new Font("Segoe UI", 11F, FontStyle.Bold),
        TextAlign = ContentAlignment.MiddleLeft,
        Cursor = Cursors.Hand,
        Tag = key
    };
    btn.FlatAppearance.BorderSize = 0;
    btn.Click += (s, e) =>
    {
        var clickedKey = btn.Tag?.ToString() ?? "";
        switch (clickedKey)
        {
            case "Dashboard":
                ShowDashboard();
                break;
            case "Scanner":
                ShowScanner();
                break;
            case "AutoScan":
                ShowSchedule();
                break;
            case "Quarantine":
                ShowQuarantine();
                break;
            case "Startup":
                ShowStartup();
                break;
            case "Settings":
                ShowSettings();
                break;
             case "ViewLogs":  // ✅ ADD THIS
                ShowLogs();
                break;
        }
    };
    return btn;
}


private void ShowLogs()
{
    _currentView = "logs";
    _mainPanel?.Controls.Clear();
    
    var container = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20) };

    var lblTitle = new Label
    {
        Text = Localization.Get("ApplicationLogs"),
        Location = new Point(0, 0),
        AutoSize = true,
        Font = new Font("Segoe UI", 18F, FontStyle.Bold),
        ForeColor = Color.FromArgb(147, 51, 234)
    };
    container.Controls.Add(lblTitle);

    // ✅ Changed to RichTextBox for color support
    var rtbLogs = new RichTextBox
    {
        Location = new Point(0, 50),
        Size = new Size(1100, 500),
        ReadOnly = true,
        BackColor = Color.FromArgb(25, 25, 40),
        ForeColor = Color.LightGray,
        Font = new Font("Consolas", 9F),
        WordWrap = false,
        BorderStyle = BorderStyle.FixedSingle
    };
    
    // Load and colorize logs
    var logs = LogManager.GetRecentLogs(1000);
    if (logs.Length > 0)
    {
        ColorizeLogsInRichTextBox(rtbLogs, logs);
    }
    else
    {
        rtbLogs.Text = Localization.Get("NoLogsAvailable");
    }
    
    container.Controls.Add(rtbLogs);

    // Info Panel - Show statistics
    var infoPanel = new Panel
    {
        Location = new Point(0, 560),
        Size = new Size(1100, 60),
        BackColor = Color.FromArgb(35, 35, 55),
        BorderStyle = BorderStyle.FixedSingle
    };

    var stats = GetLogStatistics(logs);
    var lblStats = new Label
    {
        Text = $"📊 Total: {stats.Total} | ✅ Info: {stats.Info} | ⚠️ Warning: {stats.Warning} | ❌ Error: {stats.Error} | ✨ Success: {stats.Success}",
        Location = new Point(10, 20),
        AutoSize = true,
        Font = new Font("Segoe UI", 10F, FontStyle.Bold),
        ForeColor = Color.White
    };
    infoPanel.Controls.Add(lblStats);
    container.Controls.Add(infoPanel);

    // Buttons
    var btnRefresh = CreateGlowButton(Localization.Get("RefreshLogs"), new Point(0, 630), new Size(150, 40));
    btnRefresh.Click += (s, e) =>
    {
        var refreshedLogs = LogManager.GetRecentLogs(1000);
        if (refreshedLogs.Length > 0)
        {
            ColorizeLogsInRichTextBox(rtbLogs, refreshedLogs);
            var newStats = GetLogStatistics(refreshedLogs);
            lblStats.Text = $"📊 Total: {newStats.Total} | ✅ Info: {newStats.Info} | ⚠️ Warning: {newStats.Warning} | ❌ Error: {newStats.Error} | ✨ Success: {newStats.Success}";
        }
        else
        {
            rtbLogs.Text = Localization.Get("NoLogsAvailable");
            lblStats.Text = "📊 No logs available";
        }
    };
    container.Controls.Add(btnRefresh);

    var btnClear = new Button
    {
        Text = Localization.Get("ClearLogs"),
        Location = new Point(160, 630),
        Size = new Size(150, 40),
        BackColor = Color.Crimson,
        ForeColor = Color.White,
        FlatStyle = FlatStyle.Flat,
        Font = new Font("Segoe UI", 11F, FontStyle.Bold)
    };
    btnClear.FlatAppearance.BorderSize = 0;
    btnClear.Click += (s, e) =>
    {
        var result = MessageBox.Show(
            "Clear all logs?\n\nThis cannot be undone!",
            Localization.Get("ClearLogs"),
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning
        );
        
        if (result == DialogResult.Yes)
        {
            LogManager.ClearLogs();
            rtbLogs.Text = Localization.Get("NoLogsAvailable");
            lblStats.Text = "📊 No logs available";
            ShowNotification(Localization.Get("LogsCleared"), Localization.Get("LogsClearedMsg"));
        }
    };
    container.Controls.Add(btnClear);

    var btnExport = CreateGlowButton(Localization.Get("ExportLogs"), new Point(320, 630), new Size(150, 40));
    btnExport.Click += (s, e) =>
    {
        var exportPath = LogManager.ExportLogs();
        if (exportPath != null)
        {
            ShowNotification(Localization.Get("LogsExported"), Localization.Get("LogsExportedMsg", exportPath));
            MessageBox.Show(
                $"Logs exported to:\n{exportPath}",
                Localization.Get("LogsExported"),
                MessageBoxButtons.OK,
                MessageBoxIcon.Information
            );
        }
        else
        {
            MessageBox.Show(
                "Failed to export logs or no logs available.",
                "Error",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error
            );
        }
    };
    container.Controls.Add(btnExport);

    var btnOpenFolder = CreateGlowButton("📁 Open Log Folder", new Point(480, 630), new Size(180, 40));
    btnOpenFolder.Click += (s, e) =>
    {
        try
        {
            var logDirectory = Path.GetDirectoryName(LogManager.GetLogFilePath());
            if (Directory.Exists(logDirectory))
            {
                System.Diagnostics.Process.Start("explorer.exe", logDirectory);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to open folder: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    };
    container.Controls.Add(btnOpenFolder);

    var lblLogPath = new Label
    {
        Text = $"📄 Log file: {LogManager.GetLogFilePath()}",
        Location = new Point(0, 680),
        AutoSize = true,
        Font = new Font("Segoe UI", 9F),
        ForeColor = Color.Gray
    };
    container.Controls.Add(lblLogPath);

    _mainPanel?.Controls.Add(container);
}

private void ColorizeLogsInRichTextBox(RichTextBox rtb, string[] logs)
{
    rtb.Clear();
    
    foreach (var log in logs)
    {
        // Determine color based on log level
        Color logColor = Color.LightGray;
        
        if (log.Contains("[Info]"))
            logColor = Color.Cyan;
        else if (log.Contains("[Warning]"))
            logColor = Color.Orange;
        else if (log.Contains("[Error]"))
            logColor = Color.Red;
        else if (log.Contains("[Success]"))
            logColor = Color.LimeGreen;
        else if (log.Contains("[Debug]"))
            logColor = Color.Gray;
        
        // Append text with color
        rtb.SelectionStart = rtb.TextLength;
        rtb.SelectionLength = 0;
        rtb.SelectionColor = logColor;
        rtb.AppendText(log + Environment.NewLine);
    }
    
    // Scroll to bottom
    rtb.SelectionStart = rtb.TextLength;
    rtb.ScrollToCaret();
}


// ============================================
// Helper method to get log statistics
// ============================================

private (int Total, int Info, int Warning, int Error, int Success, int Debug) GetLogStatistics(string[] logs)
{
    if (logs == null || logs.Length == 0)
        return (0, 0, 0, 0, 0, 0);
    
    var total = logs.Length;
    var info = logs.Count(l => l.Contains("[Info]"));
    var warning = logs.Count(l => l.Contains("[Warning]"));
    var error = logs.Count(l => l.Contains("[Error]"));
    var success = logs.Count(l => l.Contains("[Success]"));
    var debug = logs.Count(l => l.Contains("[Debug]"));
    
    return (total, info, warning, error, success, debug);
}
private void ShowDashboard()
{
    _mainPanel?.Controls.Clear();
    
    var container = new Panel 
    { 
        Dock = DockStyle.Fill, 
        AutoScroll = true,
        BackColor = Color.FromArgb(15, 15, 25)
    };

    var lblTitle = new Label
    {
        Text = Localization.Get("DashboardOverview"),  // ✅ Changed
        Font = new Font("Segoe UI", 18F, FontStyle.Bold),
        ForeColor = Color.White,
        Location = new Point(20, 10),
        AutoSize = true
    };
    container.Controls.Add(lblTitle);

    var statsFlow = new FlowLayoutPanel
    {
        Location = new Point(20, 60),
        Size = new Size(1120, 150),
        FlowDirection = FlowDirection.LeftToRight,
        WrapContents = true
    };

    statsFlow.Controls.Add(CreateStatCard(Localization.Get("0KBFiles"), "0", Color.FromArgb(59, 130, 246), out _lblZero));  // ✅ Changed
    statsFlow.Controls.Add(CreateStatCard(Localization.Get("Threats"), "0", Color.FromArgb(239, 68, 68), out _lblSuspicious));  // ✅ Changed
    statsFlow.Controls.Add(CreateStatCard(Localization.Get("MemoryAlerts"), "0", Color.FromArgb(234, 179, 8), out _lblMemory));  // ✅ Changed
    statsFlow.Controls.Add(CreateStatCard(Localization.Get("Removed"), "0", Color.FromArgb(34, 197, 94), out _lblDeleted));  // ✅ Changed
    
    container.Controls.Add(statsFlow);

    var protPanel = CreateGlowPanel(Localization.Get("RealTimeProtection"), new Point(20, 230), new Size(540, 250));  // ✅ Changed
    
    _chkFiles = new CheckBox
    {
        Text = Localization.Get("MonitorFileSystem"),  // ✅ Changed
        Location = new Point(20, 60),
        ForeColor = Color.White,
        AutoSize = true,
        Font = new Font("Segoe UI", 11F),
        Checked = _isFileMonitoringEnabled
    };
    _chkFiles.CheckedChanged += (s, e) =>
    {
        _isFileMonitoringEnabled = _chkFiles.Checked;
        if (_chkFiles.Checked) StartMonitor();
        else StopMonitor();
        UpdateStatus();
    };
    protPanel.Controls.Add(_chkFiles);

    _chkMemory = new CheckBox
    {
        Text = Localization.Get("MonitorMemoryUsage"),  // ✅ Changed
        Location = new Point(20, 100),
        ForeColor = Color.White,
        AutoSize = true,
        Font = new Font("Segoe UI", 11F),
        Checked = _isMemoryMonitoringEnabled
    };
    _chkMemory.CheckedChanged += (s, e) =>
    {
        _isMemoryMonitoringEnabled = _chkMemory.Checked;
        if (_chkMemory.Checked) { _monitor.Start(); Log("Memory monitoring started"); }
        else { _monitor.Stop(); Log("Memory monitoring stopped"); }
        UpdateStatus();
    };
    protPanel.Controls.Add(_chkMemory);

    _lblStatus = new Label
    {
        Text = Localization.Get("StatusInactive"),  // ✅ Changed
        Location = new Point(20, 140),
        ForeColor = Color.Gray,
        Font = new Font("Segoe UI", 12F, FontStyle.Bold),
        AutoSize = true
    };
    protPanel.Controls.Add(_lblStatus);

    _lblDbCount = new Label
    {
        Text = Localization.Get("ThreatDatabase", _scanner.GetDatabaseSignatureCount()),  // ✅ Changed
        Location = new Point(20, 180),
        ForeColor = Color.Cyan,
        Font = new Font("Segoe UI", 10F),
        AutoSize = true
    };
    protPanel.Controls.Add(_lblDbCount);

    container.Controls.Add(protPanel);

    var sysPanel = CreateGlowPanel(Localization.Get("SystemInformation"), new Point(580, 230), new Size(540, 250));  // ✅ Changed
    
    var drives = DriveInfo.GetDrives().Where(d => d.IsReady).ToList();
    var yPos = 60;
    foreach (var drive in drives)
    {
        var lblDrive = new Label
        {
            Text = $"{drive.Name} - {FormatBytes(drive.TotalFreeSpace)} free of {FormatBytes(drive.TotalSize)}",
            Location = new Point(20, yPos),
            ForeColor = Color.LightGray,
            AutoSize = true,
            Font = new Font("Segoe UI", 10F)
        };
        sysPanel.Controls.Add(lblDrive);
        yPos += 30;
    }

    _lblNextScan = new Label
    {
        Text = "Auto-scan: Not scheduled",
        Location = new Point(20, yPos + 10),
        ForeColor = Color.Yellow,
        Font = new Font("Segoe UI", 10F, FontStyle.Bold),
        AutoSize = true
    };
    sysPanel.Controls.Add(_lblNextScan);

    container.Controls.Add(sysPanel);

    var actionsPanel = CreateGlowPanel(Localization.Get("QuickActions"), new Point(20, 500), new Size(1100, 120));  // ✅ Changed
    
    var btnQuickScan = CreateActionButton(Localization.Get("QuickScan"), new Point(20, 50));  // ✅ Changed
    btnQuickScan.Click += async (s, e) =>
    {
        ShowScanner();
        await Task.Delay(100);
        _btnScan?.PerformClick();
    };
    actionsPanel.Controls.Add(btnQuickScan);

    var btnFullScan = CreateActionButton(Localization.Get("ScanPC"), new Point(180, 50));  // ✅ Changed
    btnFullScan.Click += async (s, e) =>
    {
        ShowScanner();
        await Task.Delay(100);
        _btnScanPC?.PerformClick();
    };
    actionsPanel.Controls.Add(btnFullScan);

    var btnViewSchedule = CreateActionButton(Localization.Get("Schedule"), new Point(340, 50));  // ✅ Changed
    btnViewSchedule.Click += (s, e) => ShowSchedule();
    actionsPanel.Controls.Add(btnViewSchedule);

    container.Controls.Add(actionsPanel);

    _mainPanel?.Controls.Add(container);
    
    UpdateStats();
    UpdateStatus();
    UpdateNextScanLabel();
}
private bool CanAccessDirectory(string path)
{
    try
    {
        Directory.GetDirectories(path);
        Directory.GetFiles(path);
        return true;
    }
    catch
    {
        return false;
    }
}

private void SelectAllThreats()
{
    if (_lvThreats == null) return;

    _lvThreats.BeginUpdate();  // stop redraw while selecting

    foreach (ListViewItem item in _lvThreats.Items)
    {
        item.Selected = true;
    }

    _lvThreats.EndUpdate();    // redraw once (no crash)
}

    // ============================================
// Find your ShowScanner() method and update the ListView and button positions
// The issue is the ListView is covering the buttons
// ============================================

private void ShowScanner()
{
    _currentView = "scanner";
    _mainPanel?.Controls.Clear();

    var container = new Panel
    {
        Dock = DockStyle.Fill,
        AutoScroll = true,
        Padding = new Padding(20)
    };

    // Title
    var lblPath = new Label
    {
        Text = Localization.Get("SelectScanLocation"),
        Location = new Point(0, 0),
        AutoSize = true,
        Font = new Font("Segoe UI", 12F, FontStyle.Bold)
    };
    container.Controls.Add(lblPath);

    // Prepare scan locations
    var scanLocations = new Dictionary<string, string>();

    var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    if (Directory.Exists(desktop)) scanLocations["Desktop"] = desktop;

    var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    if (Directory.Exists(documents)) scanLocations["Documents"] = documents;

    var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    if (Directory.Exists(userProfile)) scanLocations["User Profile"] = userProfile;

    var downloads = Path.Combine(userProfile, "Downloads");
    if (Directory.Exists(downloads)) scanLocations["Downloads"] = downloads;

    foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed))
        scanLocations[$"Drive {drive.Name}"] = drive.RootDirectory.FullName;

    // ComboBox
    _cmbPath = new ComboBox
    {
        Location = new Point(0, 30),
        Size = new Size(450, 30),
        DropDownStyle = ComboBoxStyle.DropDownList,
        Font = new Font("Segoe UI", 11F),
        BackColor = Color.FromArgb(35, 35, 55),
        ForeColor = Color.White,
        Tag = scanLocations
    };

    foreach (var location in scanLocations)
        _cmbPath.Items.Add($"{location.Key} ({location.Value})");

    _cmbPath.Items.Add("Custom Folder...");

    _cmbPath.SelectedIndex = _selectedScanLocationIndex;
    _cmbPath.SelectedIndexChanged += (s, e) => _selectedScanLocationIndex = _cmbPath.SelectedIndex;
    container.Controls.Add(_cmbPath);

    // Warning
    var lblWarning = new Label
    {
        Text = "⚠️ Some system folders may be skipped due to permissions",
        Location = new Point(0, 65),
        AutoSize = true,
        Font = new Font("Segoe UI", 9F),
        ForeColor = Color.Orange
    };
    container.Controls.Add(lblWarning);

    // VirusTotal checkbox
    _chkVirusTotal = new CheckBox
    {
        Text = "Check VirusTotal (slower)",
        Location = new Point(0, 90),
        ForeColor = Color.White,
        AutoSize = true,
        Font = new Font("Segoe UI", 10F),
        Enabled = !string.IsNullOrEmpty(_virusTotalApiKey)
    };
    container.Controls.Add(_chkVirusTotal);

    // Filter dropdown
    var cmbFilter = new ComboBox
    {
        Location = new Point(200, 90),
        Width = 180,
        DropDownStyle = ComboBoxStyle.DropDownList,
        BackColor = Color.FromArgb(35, 35, 55),
        ForeColor = Color.White,
        Font = new Font("Segoe UI", 10F)
    };

    cmbFilter.Items.AddRange(new object[]
    {
        "Show All", "Ransomware", "0KB File", "Suspicious", "Malware", "Unknown"
    });
    cmbFilter.SelectedIndex = 0;

    cmbFilter.SelectedIndexChanged += (s, e) =>
    {
        _currentFilter = cmbFilter.SelectedItem!.ToString()!;
        ApplyThreatFilter(_currentFilter);
    };
    container.Controls.Add(cmbFilter);

    // Start scan buttons
    _btnScan = CreateGlowButton(Localization.Get("StartScan"), new Point(460, 30), new Size(140, 35));
    _btnScan.Click += async (s, e) => await StartScan();
    container.Controls.Add(_btnScan);

    _btnScanPC = CreateGlowButton(Localization.Get("ScanEntirePC"), new Point(610, 30), new Size(160, 35));
    _btnScanPC.Click += async (s, e) => await StartFullPCScan();
    container.Controls.Add(_btnScanPC);

    // Stop button
    _btnStop = new Button
    {
        Text = Localization.Get("Stop"),
        Location = new Point(780, 30),
        Size = new Size(100, 35),
        BackColor = Color.Crimson,
        ForeColor = Color.White,
        FlatStyle = FlatStyle.Flat,
        Enabled = _isScanning, // <-- FIX FOR SWITCH PAGE
        Font = new Font("Segoe UI", 10F, FontStyle.Bold)
    };
    _btnStop.FlatAppearance.BorderSize = 0;

    _btnStop.Click += (s, e) =>
    {
        if (_cts != null && !_cts.IsCancellationRequested)
        {
            _cts.Cancel();
            Log("Stop button clicked - cancelling scan...");
            if (_lblCurrentScan != null) _lblCurrentScan.Text = "Stopping scan...";
        }
    };
    container.Controls.Add(_btnStop);

    // Progress bar
    _progress = new ProgressBar
    {
        Location = new Point(0, 140),
        Size = new Size(1100, 30),
        Style = ProgressBarStyle.Continuous
    };
    container.Controls.Add(_progress);

    // Status label
    _lblCurrentScan = new Label
    {
        Text = _isScanning ? "Scanning..." : Localization.Get("ReadyToScan"),
        Location = new Point(0, 175),
        AutoSize = true,
        Font = new Font("Segoe UI", 9F),
        ForeColor = Color.Gray
    };
    container.Controls.Add(_lblCurrentScan);

    // Threat list
    _lvThreats = new ListView
    {
        Location = new Point(0, 210),
        Size = new Size(1100, 350),
        View = View.Details,
        FullRowSelect = true,
        GridLines = true,
        BackColor = Color.FromArgb(35, 35, 55),
        ForeColor = Color.White,
        Font = new Font("Consolas", 9F)
    };

    _lvThreats.Columns.Add("Type", 150);
    _lvThreats.Columns.Add("File Name", 200);
    _lvThreats.Columns.Add("Path", 350);
    _lvThreats.Columns.Add("Size", 80);
    _lvThreats.Columns.Add("Risk", 80);
    _lvThreats.Columns.Add("VT", 80);

    LoadThreatsToListView();
    container.Controls.Add(_lvThreats);

    //
    // ===== YOUR ORIGINAL BUTTONS BELOW =====
    //

    _btnQuarantineSelected = CreateGlowButton(Localization.Get("QuarantineBtn"), new Point(0, 580), new Size(150, 40));
    _btnQuarantineSelected.Click += (s, e) => QuarantineSelected();
    container.Controls.Add(_btnQuarantineSelected);

    _btnDelete = new Button
    {
        Text = Localization.Get("Delete"),
        Location = new Point(160, 580),
        Size = new Size(150, 40),
        BackColor = Color.Crimson,
        ForeColor = Color.White,
        FlatStyle = FlatStyle.Flat,
        Font = new Font("Segoe UI", 11F, FontStyle.Bold)
    };
    _btnDelete.FlatAppearance.BorderSize = 0;
    _btnDelete.Click += (s, e) => DeleteSelected();
    container.Controls.Add(_btnDelete);

    var btnSelectAll = new Button
    {
        Text = Localization.Get("SelectAll"),
        Location = new Point(480, 580),
        Size = new Size(150, 40),
        BackColor = Color.FromArgb(60, 120, 200),
        ForeColor = Color.White,
        FlatStyle = FlatStyle.Flat,
        Font = new Font("Segoe UI", 11F, FontStyle.Bold)
    };
    btnSelectAll.FlatAppearance.BorderSize = 0;
    btnSelectAll.Click += (s, e) => SelectAllThreats();
    container.Controls.Add(btnSelectAll);

    //
    // FIX: restore button states if switching pages while scanning
    //
    UpdateScannerButtons();

    _mainPanel?.Controls.Add(container);
}


    private async Task StartScan()
{
    if (_cmbPath == null) return;

    var selectedText = _cmbPath.SelectedItem?.ToString();
    if (string.IsNullOrEmpty(selectedText)) return;

    if (selectedText == "Custom Folder...")
    {
        using var dialog = new FolderBrowserDialog();
        if (dialog.ShowDialog() == DialogResult.OK)
        {
            await ScanPath(dialog.SelectedPath);
        }
        return;
    }

    var scanLocations = _cmbPath.Tag as Dictionary<string, string>;
    if (scanLocations == null)
    {
        MessageBox.Show("Invalid scan configuration!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        return;
    }

    var keyName = selectedText.Contains('(')
        ? selectedText.Substring(0, selectedText.IndexOf('(')).Trim()
        : selectedText;

    if (!scanLocations.ContainsKey(keyName))
    {
        MessageBox.Show($"Location '{keyName}' not found!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        return;
    }

    var path = scanLocations[keyName];
    if (!Directory.Exists(path))
    {
        MessageBox.Show($"Directory does not exist:\n{path}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        return;
    }

    if (!CanAccessDirectory(path))
    {
        var result = MessageBox.Show(
            $"Limited access to:\n{path}\n\nThe scan will skip protected folders.\nContinue anyway?",
            "Permission Warning",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning
        );
        if (result != DialogResult.Yes) return;
    }

    // Begin scanning
    _isScanning = true;
    UpdateScannerButtons();

    await ScanPath(path);
}


   private async Task ScanPath(string path)
{
    if (string.IsNullOrEmpty(path)) return;

    _detectedThreats.Clear();
    _cntZero = _cntSusp = _cntMem = _cntDel = 0;
    UpdateStats();

    if (_lvThreats != null) _lvThreats.Items.Clear();
    if (_progress != null) _progress.Value = 0;

    Log($"Starting scan: {path}");
    ShowNotification("Scan Started", $"Scanning: {path}");

    _cts = new CancellationTokenSource();

    try
    {
        await Task.Run(() => _scanner.ScanDirectoryAsync(path, _cts.Token, _chkVirusTotal?.Checked ?? false));
    }
    catch (OperationCanceledException)
    {
        Log("Scan cancelled");
        ShowNotification("Scan Cancelled", "Scan was stopped");
    }
    catch (UnauthorizedAccessException)
    {
        Log("Some folders were skipped");
        ShowNotification("Scan Complete", "Some folders could not be scanned");
    }
    catch (Exception ex)
    {
        Log($"Scan error: {ex.Message}");
        MessageBox.Show($"Scan encountered errors:\n{ex.Message}", "Scan Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }
    finally
    {
        _isScanning = false;
        UpdateScannerButtons();

        _cts?.Dispose();
        _cts = null;
    }
}

private void UpdateScannerButtons()
{
    if (_btnStop != null)
        _btnStop.Enabled = _isScanning;

    if (_btnScan != null)
        _btnScan.Enabled = !_isScanning;

    if (_btnScanPC != null)
        _btnScanPC.Enabled = !_isScanning;

    if (_lblCurrentScan != null)
    {
        _lblCurrentScan.Text = _isScanning
            ? "Scanning..."
            : Localization.Get("ReadyToScan");
    }
}


private async Task StartFullPCScan()
{
    var result = MessageBox.Show(
        "This will scan ALL drives on your PC. This may take a long time!\n\nContinue?",
        "Full PC Scan",
        MessageBoxButtons.YesNo,
        MessageBoxIcon.Warning
    );

    if (result != DialogResult.Yes) return;

    // Begin scanning
    _isScanning = true;
    UpdateScannerButtons();

    _detectedThreats.Clear();
    _cntZero = _cntSusp = _cntMem = _cntDel = 0;
    UpdateStats();
    _lvThreats?.Items.Clear();

    Log("Starting full PC scan...");
    ShowNotification("Full PC Scan", "Scanning all drives...");

    _cts = new CancellationTokenSource();

    try
    {
        await Task.Run(() => _scanner.ScanEntirePCAsync(_cts.Token, _chkVirusTotal?.Checked ?? false));
    }
    catch (OperationCanceledException)
    {
        Log("Full PC scan cancelled");
        ShowNotification("Scan Cancelled", "Full PC scan was stopped");
    }
    catch (Exception ex)
    {
        Log($"Scan error: {ex.Message}");
        MessageBox.Show($"Scan error:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
    finally
    {
        _isScanning = false;
        UpdateScannerButtons();

        _cts?.Dispose();
        _cts = null;
    }
}


private void RefreshCurrentView()
{
    switch (_currentView)
    {
        case "dashboard":
            ShowDashboard();
            break;
        case "scanner":
            ShowScanner();
            break;
        case "schedule":
            ShowSchedule();
            break;
        case "quarantine":
            ShowQuarantine();
            break;
        case "startup":
            ShowStartup();
            break;
        case "settings":
            ShowSettings();
            break;
                case "logs":  // ✅ ADD THIS
            ShowLogs();
            break;
    }
    
    UpdateNavigationButtons();
}

private void UpdateNavigationButtons()
{
    if (_btnDashboard != null) _btnDashboard.Text = Localization.Get("Dashboard");
    if (_btnScanner != null) _btnScanner.Text = Localization.Get("Scanner");
    if (_btnSchedule != null) _btnSchedule.Text = Localization.Get("AutoScan");
    if (_btnQuarantine != null) _btnQuarantine.Text = Localization.Get("Quarantine");
    if (_btnStartup != null) _btnStartup.Text = Localization.Get("Startup");
    if (_btnSettings != null) _btnSettings.Text = Localization.Get("Settings");
}

    private void ShowSchedule()
{
    _currentView = "schedule";
    _mainPanel?.Controls.Clear();
    
    var container = new Panel { Dock = DockStyle.Fill };

    var lblTitle = new Label
    {
        Text = Localization.Get("ScheduledAutoScan"),  // ✅
        Location = new Point(0, 10),
        AutoSize = true,
        Font = new Font("Segoe UI", 18F, FontStyle.Bold),
        ForeColor = Color.FromArgb(147, 51, 234)
    };
    container.Controls.Add(lblTitle);

    var schedulePanel = CreateGlowPanel(Localization.Get("ConfigureAutoScan"), new Point(0, 60), new Size(600, 300));  // ✅

    var lblInterval = new Label
    {
        Text = Localization.Get("ScanInterval"),  // ✅
        Location = new Point(20, 60),
        AutoSize = true,
        Font = new Font("Segoe UI", 12F, FontStyle.Bold),
        ForeColor = Color.White
    };
    schedulePanel.Controls.Add(lblInterval);

    _cmbInterval = new ComboBox
    {
        Location = new Point(20, 90),
        Size = new Size(200, 30),
        DropDownStyle = ComboBoxStyle.DropDownList,
        Font = new Font("Segoe UI", 11F),
        BackColor = Color.FromArgb(35, 35, 55),
        ForeColor = Color.White
    };
    _cmbInterval.Items.AddRange(new object[]
    {
        Localization.Get("5MinutesDemo"),   // ✅
        Localization.Get("15Minutes"),      // ✅
        Localization.Get("30Minutes"),      // ✅
        Localization.Get("1Hour"),          // ✅
        Localization.Get("2Hours"),         // ✅
        Localization.Get("6Hours"),         // ✅
        Localization.Get("12Hours"),        // ✅
        Localization.Get("24Hours")         // ✅
    });
    _cmbInterval.SelectedIndex = _selectedIntervalIndex;
    _cmbInterval.SelectedIndexChanged += (s, e) =>
    {
        _selectedIntervalIndex = _cmbInterval.SelectedIndex;
    };
    schedulePanel.Controls.Add(_cmbInterval);

    var btnStartSchedule = CreateGlowButton(Localization.Get("StartAutoScan"), new Point(20, 140), new Size(180, 40));  // ✅
    btnStartSchedule.Click += (s, e) =>
    {
        var selected = _cmbInterval.SelectedItem?.ToString() ?? "";
        var minutes = _selectedIntervalIndex switch
        {
            0 => 5,
            1 => 15,
            2 => 30,
            3 => 60,
            4 => 120,
            5 => 360,
            6 => 720,
            7 => 1440,
            _ => 60
        };
        
        _scheduler.Start(minutes);
        UpdateNextScanLabel();
        ShowNotification(Localization.Get("ScanStarted"), Localization.Get("AutoScanStartedMsg", selected));  // ✅
    };
    schedulePanel.Controls.Add(btnStartSchedule);

    var btnStopSchedule = new Button
    {
        Text = Localization.Get("StopAutoScan"),  // ✅
        Location = new Point(210, 140),
        Size = new Size(180, 40),
        BackColor = Color.Crimson,
        ForeColor = Color.White,
        FlatStyle = FlatStyle.Flat,
        Font = new Font("Segoe UI", 11F, FontStyle.Bold)
    };
    btnStopSchedule.FlatAppearance.BorderSize = 0;
    btnStopSchedule.Click += (s, e) =>
    {
        _scheduler.Stop();
        UpdateNextScanLabel();
        ShowNotification(Localization.Get("AutoScanStoppedMsg"), Localization.Get("AutoScanStoppedMsg"));  // ✅
    };
    schedulePanel.Controls.Add(btnStopSchedule);

    var lblInfo = new Label
    {
        Text = Localization.Get("AutoScanInfo"),  // ✅
        Location = new Point(20, 200),
        Size = new Size(550, 60),
        Font = new Font("Segoe UI", 10F),
        ForeColor = Color.LightGray
    };
    schedulePanel.Controls.Add(lblInfo);

    container.Controls.Add(schedulePanel);

    var statusPanel = CreateGlowPanel(Localization.Get("CurrentStatus"), new Point(620, 60), new Size(460, 300));  // ✅

    var schedule = _scheduler.GetSchedule();
    var lblStatus = new Label
    {
        Text = schedule?.Enabled == true ? Localization.Get("AutoScanActive") : Localization.Get("AutoScanInactive"),  // ✅
        Location = new Point(20, 60),
        AutoSize = true,
        Font = new Font("Segoe UI", 14F, FontStyle.Bold),
        ForeColor = schedule?.Enabled == true ? Color.LimeGreen : Color.Gray
    };
    statusPanel.Controls.Add(lblStatus);

    if (schedule?.Enabled == true)
    {
        var lblLastScan = new Label
        {
            Text = Localization.Get("LastScan", schedule.LastScan?.ToString("g") ?? Localization.Get("NotYetRun")),  // ✅
            Location = new Point(20, 100),
            AutoSize = true,
            Font = new Font("Segoe UI", 11F),
            ForeColor = Color.White
        };
        statusPanel.Controls.Add(lblLastScan);

        var lblNextScanFull = new Label
        {
            Text = Localization.Get("NextScan", schedule.NextScan?.ToString("g")),  // ✅
            Location = new Point(20, 130),
            AutoSize = true,
            Font = new Font("Segoe UI", 11F),
            ForeColor = Color.Yellow
        };
        statusPanel.Controls.Add(lblNextScanFull);

        var lblInterval2 = new Label
        {
            Text = Localization.Get("IntervalMinutes", schedule.IntervalMinutes),  // ✅
            Location = new Point(20, 160),
            AutoSize = true,
            Font = new Font("Segoe UI", 11F),
            ForeColor = Color.Cyan
        };
        statusPanel.Controls.Add(lblInterval2);
    }

    container.Controls.Add(statusPanel);

    _mainPanel?.Controls.Add(container);
}

// Replace your ShowQuarantine() method with this version:

// Replace your ShowQuarantine() method with this version:

private void ShowQuarantine()
{
    _currentView = "quarantine";
    _mainPanel?.Controls.Clear();
    
    var container = new Panel { Dock = DockStyle.Fill };

    var lblTitle = new Label
    {
        Text = Localization.Get("QuarantinedFiles"),  // ✅
        Location = new Point(0, 10),
        AutoSize = true,
        Font = new Font("Segoe UI", 18F, FontStyle.Bold),
        ForeColor = Color.FromArgb(147, 51, 234)
    };
    container.Controls.Add(lblTitle);

    var lvQuarantine = new ListView
    {
        Location = new Point(0, 60),
        Size = new Size(1100, 500),
        View = View.Details,
        FullRowSelect = true,
        GridLines = true,
        BackColor = Color.FromArgb(35, 35, 55),
        ForeColor = Color.White
    };
    lvQuarantine.Columns.Add(Localization.Get("FileName"), 400);          // ✅
    lvQuarantine.Columns.Add(Localization.Get("QuarantineDate"), 200);    // ✅
    lvQuarantine.Columns.Add(Localization.Get("Size"), 150);              // ✅
    
    foreach (var file in _quarantine.GetQuarantinedFiles())
    {
        var fi = new FileInfo(file);
        var item = new ListViewItem(fi.Name);
        item.SubItems.Add(fi.CreationTime.ToString());
        item.SubItems.Add(FormatBytes(fi.Length));
        item.Tag = file;
        lvQuarantine.Items.Add(item);
    }
    container.Controls.Add(lvQuarantine);

    var btnRestore = CreateGlowButton(Localization.Get("Restore"), new Point(0, 580), new Size(120, 40));  // ✅
    btnRestore.Click += (s, e) =>
    {
        if (lvQuarantine.SelectedItems.Count == 0)
        {
            MessageBox.Show(
                Localization.Get("SelectFilesFirst", Localization.Get("Restore").Replace("↩️ ", "")),  // ✅
                Localization.Get("Restore"),
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning
            );
            return;
        }

        var result = MessageBox.Show(
            Localization.Get("ConfirmRestore", lvQuarantine.SelectedItems.Count),  // ✅
            Localization.Get("Restore"),
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question
        );

        if (result != DialogResult.Yes) return;

        int successCount = 0;
        int failCount = 0;

        foreach (ListViewItem item in lvQuarantine.SelectedItems.Cast<ListViewItem>().ToList())
        {
            string quarantinedFile = item.Tag.ToString();

            if (_quarantine.RestoreFile(quarantinedFile))
            {
                lvQuarantine.Items.Remove(item);
                successCount++;
            }
            else
            {
                failCount++;
            }
        }

        MessageBox.Show(
            Localization.Get("RestoredCount", successCount, failCount),  // ✅
            Localization.Get("RestoreComplete"),
            MessageBoxButtons.OK,
            failCount > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information
        );
    };
    container.Controls.Add(btnRestore);

    var btnDeletePermanent = new Button
    {
        Text = Localization.Get("Delete"),  // ✅
        Location = new Point(130, 580),
        Size = new Size(120, 40),
        BackColor = Color.Crimson,
        ForeColor = Color.White,
        FlatStyle = FlatStyle.Flat,
        Font = new Font("Segoe UI", 10F, FontStyle.Bold)
    };
    btnDeletePermanent.FlatAppearance.BorderSize = 0;
    btnDeletePermanent.Click += (s, e) =>
    {
        if (lvQuarantine.SelectedItems.Count == 0)
        {
            MessageBox.Show(
                Localization.Get("SelectFilesFirst", Localization.Get("Delete").Replace("🗑️ ", "")),  // ✅
                Localization.Get("Delete"),
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning
            );
            return;
        }

        var result = MessageBox.Show(
            Localization.Get("ConfirmDelete", lvQuarantine.SelectedItems.Count),  // ✅
            Localization.Get("Delete"),
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning
        );

        if (result != DialogResult.Yes) return;

        int successCount = 0;
        int failCount = 0;

        foreach (ListViewItem item in lvQuarantine.SelectedItems.Cast<ListViewItem>().ToList())
        {
            string quarantinedFile = item.Tag.ToString();

            if (_quarantine.DeleteQuarantined(quarantinedFile))
            {
                lvQuarantine.Items.Remove(item);
                successCount++;
            }
            else
            {
                failCount++;
            }
        }

        MessageBox.Show(
            Localization.Get("DeletedCount", successCount, failCount),  // ✅
            Localization.Get("DeleteComplete"),
            MessageBoxButtons.OK,
            failCount > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information
        );
    };
    container.Controls.Add(btnDeletePermanent);

    var btnSelectAll = new Button
    {
        Text = Localization.Get("SelectAll"),  // ✅
        Location = new Point(260, 580),
        Size = new Size(120, 40),
        BackColor = Color.FromArgb(60, 120, 200),
        ForeColor = Color.White,
        FlatStyle = FlatStyle.Flat,
        Font = new Font("Segoe UI", 10F, FontStyle.Bold)
    };
    btnSelectAll.FlatAppearance.BorderSize = 0;
    btnSelectAll.Click += (s, e) =>
    {
        lvQuarantine.BeginUpdate();
        foreach (ListViewItem item in lvQuarantine.Items)
        {
            item.Selected = true;
        }
        lvQuarantine.EndUpdate();
    };
    container.Controls.Add(btnSelectAll);

    var btnClearSelection = new Button
    {
        Text = Localization.Get("ClearSelection"),  // ✅
        Location = new Point(390, 580),
        Size = new Size(150, 40),
        BackColor = Color.FromArgb(75, 75, 90),
        ForeColor = Color.White,
        FlatStyle = FlatStyle.Flat,
        Font = new Font("Segoe UI", 10F, FontStyle.Bold)
    };
    btnClearSelection.FlatAppearance.BorderSize = 0;
    btnClearSelection.Click += (s, e) =>
    {
        lvQuarantine.SelectedItems.Clear();
    };
    container.Controls.Add(btnClearSelection);

    _mainPanel?.Controls.Add(container);
}

  private void ShowStartup()
{
    _currentView = "startup";
    _mainPanel?.Controls.Clear();
    
    var container = new Panel { Dock = DockStyle.Fill };

    var lblTitle = new Label
    {
        Text = Localization.Get("StartupPrograms"),  // ✅
        Location = new Point(0, 10),
        AutoSize = true,
        Font = new Font("Segoe UI", 18F, FontStyle.Bold),
        ForeColor = Color.FromArgb(147, 51, 234)
    };
    container.Controls.Add(lblTitle);

    var lvStartup = new ListView
    {
        Location = new Point(0, 60),
        Size = new Size(1100, 550),
        View = View.Details,
        FullRowSelect = true,
        GridLines = true,
        BackColor = Color.FromArgb(35, 35, 55),
        ForeColor = Color.White
    };
    lvStartup.Columns.Add(Localization.Get("Program"), 300);   // ✅
    lvStartup.Columns.Add(Localization.Get("Path"), 500);      // ✅
    lvStartup.Columns.Add(Localization.Get("Location"), 250);  // ✅

    var scanner = new StartupScanner();
    foreach (var item in scanner.ScanStartupPrograms())
    {
        var lvItem = new ListViewItem(item.Name);
        lvItem.SubItems.Add(item.Path);
        lvItem.SubItems.Add(item.Location);
        lvStartup.Items.Add(lvItem);
    }
    
    container.Controls.Add(lvStartup);
    _mainPanel?.Controls.Add(container);
}

private void ApplyPerformanceMode()
{
    switch (_performanceModeIndex)
    {
        case 0: // LOW
            SecurityScanner.MaxThreads = 1;
            SecurityScanner.ScanDelayMs = 10;
            break;

        case 1: // NORMAL
            SecurityScanner.MaxThreads = 2;
            SecurityScanner.ScanDelayMs = 0;
            break;

        case 2: // HIGH
            SecurityScanner.MaxThreads = 8;
            SecurityScanner.ScanDelayMs = 0;
            break;
    }
}

private void ShowSettings()
{
    _currentView = "settings";
    _mainPanel?.Controls.Clear();
    
    var container = new Panel { Dock = DockStyle.Fill };

    var lblTitle = new Label
    {
        Text = Localization.Get("SettingsTitle"),
        Location = new Point(0, 10),
        AutoSize = true,
        Font = new Font("Segoe UI", 18F, FontStyle.Bold),
        ForeColor = Color.FromArgb(147, 51, 234)
    };
    container.Controls.Add(lblTitle);

    var settingsPanel = CreateGlowPanel(Localization.Get("ApplicationSettings"), new Point(0, 60), new Size(600, 500));

    // -------------------------------
    // LANGUANGE SELECTOR
    // -------------------------------
    var lblLanguage = new Label
    {
        Text = Localization.Get("Language"),
        Location = new Point(20, 60),
        AutoSize = true,
        Font = new Font("Segoe UI", 11F, FontStyle.Bold),
        ForeColor = Color.White
    };
    settingsPanel.Controls.Add(lblLanguage);

    _cmbLanguage = new ComboBox
    {
        Location = new Point(20, 90),
        Size = new Size(200, 30),
        DropDownStyle = ComboBoxStyle.DropDownList,
        Font = new Font("Segoe UI", 11F),
        BackColor = Color.FromArgb(35, 35, 55),
        ForeColor = Color.White
    };
    _cmbLanguage.Items.AddRange(new object[] { "English", "ภาษาไทย" });
    _cmbLanguage.SelectedItem = Localization.CurrentLanguage;
    _cmbLanguage.SelectedIndexChanged += (s, e) =>
    {
        var newLang = _cmbLanguage.SelectedItem?.ToString() ?? "English";
        Localization.CurrentLanguage = newLang;

        ShowSettings();
        ShowNotification(Localization.Get("SettingsSaved"), Localization.Get("LanguageChanged", newLang));
    };
    settingsPanel.Controls.Add(_cmbLanguage);

    // -------------------------------
    // OTHER SETTINGS
    // -------------------------------
    var chkMinimizeToTray = new CheckBox
    {
        Text = Localization.Get("MinimizeToTray"),
        Location = new Point(20, 140),
        ForeColor = Color.White,
        AutoSize = true,
        Font = new Font("Segoe UI", 11F)
    };
    settingsPanel.Controls.Add(chkMinimizeToTray);

    var chkSound = new CheckBox
    {
        Text = Localization.Get("SoundNotifications"),
        Location = new Point(20, 180),
        ForeColor = Color.White,
        AutoSize = true,
        Font = new Font("Segoe UI", 11F),
        Checked = true
    };
    settingsPanel.Controls.Add(chkSound);

    // -------------------------------
    // VIRUSTOTAL KEY
    // -------------------------------
    var lblVT = new Label
    {
        Text = Localization.Get("VirusTotalAPIKey"),
        Location = new Point(20, 230),
        AutoSize = true,
        Font = new Font("Segoe UI", 11F, FontStyle.Bold),
        ForeColor = Color.White
    };
    settingsPanel.Controls.Add(lblVT);

    _txtVirusTotalKey = new TextBox
    {
        Location = new Point(20, 260),
        Size = new Size(550, 30),
        Font = new Font("Segoe UI", 10F),
        BackColor = Color.FromArgb(35, 35, 55),
        ForeColor = Color.White,
        Text = _virusTotalApiKey ?? ""
    };
    settingsPanel.Controls.Add(_txtVirusTotalKey);

    var lblVTInfo = new Label
    {
        Text = "Get your free API key at: virustotal.com",
        Location = new Point(20, 295),
        AutoSize = true,
        Font = new Font("Segoe UI", 9F),
        ForeColor = Color.Gray
    };
    settingsPanel.Controls.Add(lblVTInfo);

var btnSaveVT = CreateGlowButton(Localization.Get("SaveAPIKey"), new Point(20, 330), new Size(150, 35));
btnSaveVT.Click += (s, e) =>
{
    // Use default key if the text box is empty
    _virusTotalApiKey = string.IsNullOrWhiteSpace(_txtVirusTotalKey?.Text)
        ? DefaultVirusTotalApiKey
        : _txtVirusTotalKey.Text;

    // Optional: If you have a checkbox depending on VT key
    if (_chkVirusTotal != null)
        _chkVirusTotal.Enabled = !string.IsNullOrEmpty(_virusTotalApiKey);

    ShowNotification(
        Localization.Get("SettingsSaved"),
        Localization.Get("VirusTotalUpdated")
    );
};
settingsPanel.Controls.Add(btnSaveVT);
// Add the "Load Default Key" button
var btnLoadDefaultKey = CreateGlowButton(Localization.Get("LoadDefaultKey"), new Point(180, 330), new Size(150, 35));
btnLoadDefaultKey.Click += (s, e) =>
{
    // Reset the TextBox text to the default key
    _txtVirusTotalKey.Text = DefaultVirusTotalApiKey;
    
    // Optionally, save the default key as the active key
    _virusTotalApiKey = DefaultVirusTotalApiKey;

    // Optional: Disable certain controls if needed, or show a confirmation
    if (_chkVirusTotal != null)
        _chkVirusTotal.Enabled = !string.IsNullOrEmpty(_virusTotalApiKey);

    // Show a notification confirming that the default key is loaded
    ShowNotification(
        Localization.Get("SettingsSaved"),
        Localization.Get("VirusTotalDefaultKeyLoaded")
    );
};
settingsPanel.Controls.Add(btnLoadDefaultKey);

    // ---------------------------------------------------------
    // ⭐ NEW BLOCK: PERFORMANCE MODE
    // ---------------------------------------------------------
    var lblPerformance = new Label
    {
        Text = "Performance Mode",
        Location = new Point(20, 380),
        AutoSize = true,
        Font = new Font("Segoe UI", 11F, FontStyle.Bold),
        ForeColor = Color.White
    };
    settingsPanel.Controls.Add(lblPerformance);

    var cmbPerformance = new ComboBox
    {
        Location = new Point(20, 410),
        Size = new Size(200, 30),
        DropDownStyle = ComboBoxStyle.DropDownList,
        Font = new Font("Segoe UI", 11F),
        BackColor = Color.FromArgb(35, 35, 55),
        ForeColor = Color.White
    };

    cmbPerformance.Items.AddRange(new object[]
    {
        "Low (Lowest RAM & CPU)",
        "Normal",
        "High (Fastest)"
    });

    cmbPerformance.SelectedIndex = _performanceModeIndex;

    cmbPerformance.SelectedIndexChanged += (s, e) =>
    {
        _performanceModeIndex = cmbPerformance.SelectedIndex;
        ApplyPerformanceMode();

        ShowNotification(
            Localization.Get("SettingsSaved"),
            $"Performance Mode set to: {cmbPerformance.SelectedItem}"
        );
    };

    settingsPanel.Controls.Add(cmbPerformance);

    // ---------------------------------------------------------

    container.Controls.Add(settingsPanel);
    _mainPanel?.Controls.Add(container);
}


private Panel CreateGlowPanel(string title, Point location, Size size)
{
    var panel = new Panel
    {
        Location = location,
        Size = size,
        BackColor = Color.FromArgb(25, 25, 40),
        BorderStyle = BorderStyle.FixedSingle
    };

    var lblTitle = new Label
    {
        Text = title,
        Location = new Point(15, 15),
        AutoSize = true,
        Font = new Font("Segoe UI", 14F, FontStyle.Bold),
        ForeColor = Color.White
    };
    panel.Controls.Add(lblTitle);

    return panel;
}

private Button CreateGlowButton(string text, Point location, Size size)
{
    var btn = new Button
    {
        Text = text,
        Location = location,
        Size = size,
        BackColor = Color.FromArgb(147, 51, 234),
        ForeColor = Color.White,
        FlatStyle = FlatStyle.Flat,
        Font = new Font("Segoe UI", 10F, FontStyle.Bold),
        Cursor = Cursors.Hand
    };
    btn.FlatAppearance.BorderSize = 0;
    return btn;
}

private Button CreateActionButton(string text, Point location)
{
    return CreateGlowButton(text, location, new Size(150, 50));
}

private Panel CreateStatCard(string title, string value, Color color, out Label lbl)
{
    var card = new Panel
    {
        Size = new Size(260, 120),
        BackColor = Color.FromArgb(25, 25, 40),
        BorderStyle = BorderStyle.FixedSingle,
        Margin = new Padding(10)
    };

    var lblTitle = new Label
    {
        Text = title,
        Location = new Point(15, 15),
        AutoSize = true,
        ForeColor = Color.Gray,
        Font = new Font("Segoe UI", 11F)
    };
    card.Controls.Add(lblTitle);

    lbl = new Label
    {
        Text = value,
        Location = new Point(15, 45),
        AutoSize = true,
        Font = new Font("Segoe UI", 28F, FontStyle.Bold),
        ForeColor = color
    };
    card.Controls.Add(lbl);

    return card;
}

private void InitEvents()
{
    _scanner.ProgressChanged += p => Invoke(() => { if (_progress != null) _progress.Value = p; });
    _scanner.StatusChanged += s => Invoke(() => { if (_lblCurrentScan != null) _lblCurrentScan.Text = s; });
    _scanner.ThreatDetected += t => Invoke(() => AddThreat(t));
_scanner.ScanCompleted += (threats, total) => Invoke(() =>
{
    // Mark scanning as finished
    _isScanning = false;

    // Update all scanner buttons
    UpdateScannerButtons();

    // UI updates
    if (_lblCurrentScan != null)
        _lblCurrentScan.Text = "Scan complete";

    Log($"Scan complete: {threats} threats in {total} files");
    ShowNotification("Scan Complete", $"Found {threats} threats in {total} files");

    // Clean up the CTS
    _cts?.Dispose();
    _cts = null;
});
    _monitor.SuspiciousActivityDetected += (n, m) => Invoke(() =>
    {
        _cntMem++;
        UpdateStats();
        Log($"Memory alert: {n} ({m / 1024 / 1024} MB)");
        ShowNotification("Memory Alert", $"Suspicious activity: {n}");
    });
    _scheduler.ScanTriggered += () => Invoke(async () =>
    {
        Log("Auto-scan triggered");
        ShowNotification("Auto-Scan Started", "Scanning entire PC...");
        _cts = new CancellationTokenSource();
        await Task.Run(() => _scanner.ScanEntirePCAsync(_cts.Token, _chkVirusTotal?.Checked ?? false));
        UpdateNextScanLabel();
    });
    _scheduler.StatusChanged += s => Invoke(() => Log(s));
}

private void InitTrayIcon()
{
    _trayIcon = new NotifyIcon
    {
        Icon = SystemIcons.Shield,
        Text = "Security Monitor Pro",
        Visible = false
    };
    
    var menu = new ContextMenuStrip();
    menu.Items.Add("Show", null, (s, e) => { Show(); WindowState = FormWindowState.Normal; _trayIcon.Visible = false; });
    menu.Items.Add("Exit", null, (s, e) => Application.Exit());
    _trayIcon.ContextMenuStrip = menu;
    _trayIcon.DoubleClick += (s, e) => { Show(); WindowState = FormWindowState.Normal; _trayIcon.Visible = false; };
}

private void DeleteSelected()
{
    if (_lvThreats?.SelectedItems.Count == 0) return;

    var result = MessageBox.Show(
        $"Delete {_lvThreats.SelectedItems.Count} file(s) permanently?\n\n⚠️ THIS CANNOT BE UNDONE!",
        "Confirm Delete",
        MessageBoxButtons.YesNo,
        MessageBoxIcon.Warning
    );

    if (result != DialogResult.Yes) return;

    foreach (ListViewItem item in _lvThreats.SelectedItems.Cast<ListViewItem>().ToList())
    {
        try
        {
            File.Delete(item.SubItems[2].Text);
            _cntDel++;
            Log($"Deleted: {item.SubItems[1].Text}");
            
            // Remove from stored threats list
            var threat = item.Tag as ThreatInfo;
            if (threat != null)
            {
                _detectedThreats.Remove(threat);
            }
            
            _lvThreats.Items.Remove(item);
        }
        catch (Exception ex)
        {
            Log($"Error: {ex.Message}");
        }
    }
    UpdateStats();
}

// 7. UPDATE QuarantineSelected() to also remove from the list:
private void QuarantineSelected()
{
    if (_lvThreats?.SelectedItems.Count == 0)
    {
        MessageBox.Show("Select threats to quarantine", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
        return;
    }

    foreach (ListViewItem item in _lvThreats.SelectedItems.Cast<ListViewItem>().ToList())
    {
        var path = item.SubItems[2].Text;
        if (_quarantine.QuarantineFile(path))
        {
            item.SubItems[6].Text = "Quarantined";
            item.ForeColor = Color.Orange;
            Log($"Quarantined: {item.SubItems[1].Text}");
            
            // Remove from stored threats list
            var threat = item.Tag as ThreatInfo;
            if (threat != null)
            {
                _detectedThreats.Remove(threat);
            }
            
            // Remove from ListView
            _lvThreats.Items.Remove(item);
        }
    }
}

private void AddThreat(ThreatInfo t)
{
    // Always store the threat
    _detectedThreats.Add(t);
    
    // Update counters based on threat type
    if (t.Type.Contains("Ransomware"))
    {
        _cntSusp++;  // Only Ransomware counts as "Threats"
    }
    else if (t.Type == "0KB File")
    {
        _cntZero++;  // 0KB files have their own counter
    }
    
    UpdateStats();
    
    // Only add to ListView if it exists (Scanner page is active) AND matches filter
    if (_lvThreats != null && ShouldShowThreat(t, _currentFilter))
    {
        var item = new ListViewItem(t.Type);
        var vtText = t.VirusTotalDetections.HasValue ? $"{t.VirusTotalDetections}" : "-";
        item.SubItems.AddRange(new[] { t.FileName, t.FilePath, t.SizeString, t.RiskLevel, vtText, "Active" });
        item.ForeColor = t.RiskLevel == "Critical" ? Color.Red : t.RiskLevel == "High" ? Color.Orange : Color.Yellow;
        item.Tag = t;
        _lvThreats.Items.Add(item);
    }
}

private bool ShouldShowThreat(ThreatInfo t, string filter)
{
    switch (filter)
    {
        case "Show All":
            return true;

        case "Ransomware":
            // Only show if type contains "Ransomware"
            return t.Type.Contains("Ransomware", StringComparison.OrdinalIgnoreCase);

        case "0KB File":
            // Only show if type is exactly "0KB File"
            return t.Type.Equals("0KB File", StringComparison.OrdinalIgnoreCase);

        case "Suspicious":
            // ✅ FIXED: Only show files with "Suspicious" risk level
            // This is SEPARATE from High/Critical malware
            return t.RiskLevel.Equals("Suspicious", StringComparison.OrdinalIgnoreCase);

        case "Malware":
            // ✅ FIXED: Only show High/Critical risk files
            // Does NOT include "Suspicious" anymore
            return t.RiskLevel.Equals("High", StringComparison.OrdinalIgnoreCase) ||
                   t.RiskLevel.Equals("Critical", StringComparison.OrdinalIgnoreCase);

        case "Unknown":
            // Show files with Unknown risk level
            return t.RiskLevel.Equals("Unknown", StringComparison.OrdinalIgnoreCase);

        default:
            return true;
    }
}

private void LoadSettings()
{
    // Check if a custom VirusTotal API key is saved, otherwise use the default key
    _virusTotalApiKey = string.IsNullOrEmpty(_virusTotalApiKey) ? DefaultVirusTotalApiKey : _virusTotalApiKey;
}

private void LoadThreatsToListView()
{
    if (_lvThreats == null) return;
    
    _lvThreats.Items.Clear();
    
    foreach (var t in _detectedThreats)
    {
        var item = new ListViewItem(t.Type);
        var vtText = t.VirusTotalDetections.HasValue ? $"{t.VirusTotalDetections}" : "-";
        item.SubItems.AddRange(new[] { t.FileName, t.FilePath, t.SizeString, t.RiskLevel, vtText, "Active" });
        item.ForeColor = t.RiskLevel == "Critical" ? Color.Red : t.RiskLevel == "High" ? Color.Orange : Color.Yellow;
        item.Tag = t;
        _lvThreats.Items.Add(item);
    }
}
private void StartMonitor()
{
    try
    {
        var path = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        _watcher = new FileSystemWatcher(path)
        {
            EnableRaisingEvents = true,
            IncludeSubdirectories = true
        };
        _watcher.Created += (s, e) =>
        {
            if (_scanner.IsRansomwarePattern(e.FullPath))
                Invoke(() =>
                {
                    Log($"ALERT: {e.Name}");
                    ShowNotification("Threat Detected!", $"Ransomware pattern: {e.Name}");
                });
        };
        Log($"File monitoring started: {path}");
    }
    catch (Exception ex)
    {
        Log($"Monitor error: {ex.Message}");
    }
}

private void StopMonitor()
{
    _watcher?.Dispose();
    _watcher = null;
    Log("File monitoring stopped");
}

private void UpdateStats()
{
    if (_lblZero != null) _lblZero.Text = _cntZero.ToString();
    if (_lblSuspicious != null) _lblSuspicious.Text = _cntSusp.ToString();
    if (_lblMemory != null) _lblMemory.Text = _cntMem.ToString();
    if (_lblDeleted != null) _lblDeleted.Text = _cntDel.ToString();
}

private void UpdateStatus()
{
    var active = _chkFiles?.Checked == true || _chkMemory?.Checked == true;
    if (_lblStatus != null)
    {
        _lblStatus.Text = active ? Localization.Get("StatusProtected") : Localization.Get("StatusInactive");  // ✅ Changed
        _lblStatus.ForeColor = active ? Color.LimeGreen : Color.Gray;
    }
}
private void UpdateNextScanLabel()
{
    var schedule = _scheduler.GetSchedule();
    if (_lblNextScan != null)
    {
        if (schedule?.Enabled == true)
        {
            _lblNextScan.Text = $"Next auto-scan: {schedule.NextScan?.ToString("g")}";
            _lblNextScan.ForeColor = Color.Yellow;
        }
        else
        {
            _lblNextScan.Text = "Auto-scan: Not scheduled";
            _lblNextScan.ForeColor = Color.Gray;
        }
    }
}

private void Log(string msg, LogLevel level = LogLevel.Info)
{
    LogManager.WriteLog(msg, level);
}

private void ShowNotification(string title, string message)
{
    _trayIcon?.ShowBalloonTip(3000, title, message, ToolTipIcon.Info);
}

private string FormatBytes(long bytes)
{
    string[] sizes = ["B", "KB", "MB", "GB", "TB"];
    double len = bytes;
    var order = 0;
    while (len >= 1024 && order < sizes.Length - 1)
    {
        order++;
        len /= 1024;
    }
    return $"{len:0.##} {sizes[order]}";
}

protected override void OnFormClosing(FormClosingEventArgs e)
{
    _cts?.Cancel();
    _monitor.Stop();
    _scheduler.Stop();
    _watcher?.Dispose();
    _trayIcon?.Dispose();
    base.OnFormClosing(e);
}

protected override void OnResize(EventArgs e)
{
    if (WindowState == FormWindowState.Minimized)
    {
        Hide();
        if (_trayIcon != null) _trayIcon.Visible = true;
    }
    base.OnResize(e);
}
}