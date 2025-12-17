namespace SecurityMonitorPro.Core;

public static class Localization
{
    private static string _currentLanguage = "English";
    
    public static string CurrentLanguage
    {
        get => _currentLanguage;
        set => _currentLanguage = value;
    }
    
    private static readonly Dictionary<string, Dictionary<string, string>> Translations = new()
    {
        ["English"] = new()
        {
            // Navigation
            ["Dashboard"] = "📊 Dashboard",
            ["Scanner"] = "🔍 Scanner",
            ["AutoScan"] = "⏰ Auto-Scan",
            ["Quarantine"] = "🔒 Quarantine",
            ["Startup"] = "🚀 Startup",
            ["Settings"] = "⚙️ Settings",
            
            // Dashboard
            ["DashboardOverview"] = "Dashboard Overview",
            ["0KBFiles"] = "0KB Files",
            ["Threats"] = "Threats",
            ["MemoryAlerts"] = "Memory Alerts",
            ["Removed"] = "Removed",
            ["RealTimeProtection"] = "⚡ Real-Time Protection",
            ["MonitorFileSystem"] = "Monitor File System",
            ["MonitorMemoryUsage"] = "Monitor Memory Usage",
            ["StatusInactive"] = "Status: Inactive",
            ["StatusProtected"] = "Status: ✓ PROTECTED",
            ["ThreatDatabase"] = "Threat Database: {0} signatures",
            ["SystemInformation"] = "💻 System Information",
            ["QuickActions"] = "⚡ Quick Actions",
            ["QuickScan"] = "🔍 Quick Scan",
            ["ScanPC"] = "💿 Scan PC",
            ["Schedule"] = "⏰ Schedule",
            
            // Scanner
            ["SelectScanLocation"] = "Select Scan Location:",
            ["StartScan"] = "🔍 Start Scan",
            ["ScanEntirePC"] = "💿 Scan Entire PC",
            ["Stop"] = "⏹️ Stop",
            ["ReadyToScan"] = "Ready to scan",
            ["QuarantineBtn"] = "🔒 Quarantine",
            ["Delete"] = "🗑️ Delete",
            ["ClearAll"] = "🗑️ Clear All",
            ["SelectAll"] = "✔ Select All",
            
            // Settings
            ["SettingsTitle"] = "⚙️ Settings",
            ["ApplicationSettings"] = "Application Settings",
            ["Language"] = "Language:",
            ["MinimizeToTray"] = "Minimize to System Tray",
            ["SoundNotifications"] = "Sound Notifications",
            ["VirusTotalAPIKey"] = "VirusTotal API Key:",
            ["SaveAPIKey"] = "💾 Save API Key",
            
            // Messages
            ["ScanStarted"] = "Scan Started",
            ["ScanComplete"] = "Scan Complete",
            ["SettingsSaved"] = "Settings Saved",
            ["VirusTotalUpdated"] = "VirusTotal API key updated",
            ["LanguageChanged"] = "Language changed to {0}",

            // Schedule Page
    ["ScheduledAutoScan"] = "⏰ Scheduled Auto-Scan",
    ["ConfigureAutoScan"] = "Configure Auto-Scan",
    ["ScanInterval"] = "Scan Interval:",
    ["StartAutoScan"] = "▶️ Start Auto-Scan",
    ["StopAutoScan"] = "⏹️ Stop Auto-Scan",
    ["AutoScanInfo"] = "💡 Auto-scan will scan your entire PC at the selected interval.\n    This runs in the background and alerts you of threats.",
    ["CurrentStatus"] = "Current Status",
    ["AutoScanActive"] = "✓ Auto-scan is ACTIVE",
    ["AutoScanInactive"] = "Auto-scan is INACTIVE",
    ["LastScan"] = "Last scan: {0}",
    ["NextScan"] = "Next scan: {0}",
    ["IntervalMinutes"] = "Interval: Every {0} minutes",
    ["NotYetRun"] = "Not yet run",
    ["AutoScanNotScheduled"] = "Auto-scan: Not scheduled",
    ["NextAutoScan"] = "Next auto-scan: {0}",
    
    // Quarantine Page
    ["QuarantinedFiles"] = "🔒 Quarantined Files",
    ["FileName"] = "File Name",
    ["QuarantineDate"] = "Quarantine Date",
    ["Size"] = "Size",
    ["Restore"] = "↩️ Restore",
    ["SelectFilesFirst"] = "Select file(s) to {0} first!",
    ["ConfirmRestore"] = "Restore {0} file(s) to their original locations?",
    ["ConfirmDelete"] = "Permanently delete {0} file(s)?\n\n⚠️ THIS CANNOT BE UNDONE!",
    ["RestoreComplete"] = "Restore Complete",
    ["DeleteComplete"] = "Delete Complete",
    ["RestoredCount"] = "✅ Restored: {0}\n❌ Failed: {1}",
    ["DeletedCount"] = "✅ Deleted: {0}\n❌ Failed: {1}",
    ["ClearSelection"] = "✖ Clear Selection",
    
    // Startup Page
    ["StartupPrograms"] = "🚀 Startup Programs",
    ["Program"] = "Program",
    ["Path"] = "Path",
    ["Location"] = "Location",
    
    // Scanner Messages
    ["ScanningPath"] = "Scanning: {0}",
    ["FullPCScanConfirm"] = "This will scan ALL drives on your PC. This may take a long time!\n\nContinue?",
    ["FullPCScan"] = "Full PC Scan",
    ["ScanningAllDrives"] = "Scanning all drives...",
    ["ScanCancelled"] = "Scan Cancelled",
    ["ScanStopped"] = "Scan was stopped by user",
    ["FullPCScanStopped"] = "Full PC scan was stopped by user",
    ["ClearThreatsConfirm"] = "Clear all threats from the list?\n\nThis won't delete the files, just removes them from this list.",
    ["ClearThreats"] = "Clear Threats",
    ["ThreatListCleared"] = "Threat list cleared",
    
    // Scan intervals
    ["5MinutesDemo"] = "5 minutes (Demo)",
    ["15Minutes"] = "15 minutes",
    ["30Minutes"] = "30 minutes",
    ["1Hour"] = "1 hour",
    ["2Hours"] = "2 hours",
    ["6Hours"] = "6 hours",
    ["12Hours"] = "12 hours",
    ["24Hours"] = "24 hours (Daily)",
    
    // Notifications
    ["AutoScanStartedMsg"] = "Scanning every {0}",
    ["AutoScanStoppedMsg"] = "Scheduled scanning disabled",

    ["ViewLogs"] = "📋 View Logs",
["Logs"] = "📋 Logs",
["ApplicationLogs"] = "Application Logs",
["ClearLogs"] = "🗑️ Clear Logs",
["ExportLogs"] = "💾 Export Logs",
["RefreshLogs"] = "🔄 Refresh",
["LogsCleared"] = "Logs Cleared",
["LogsClearedMsg"] = "All logs have been cleared",
["LogsExported"] = "Logs Exported",
["LogsExportedMsg"] = "Logs exported to: {0}",
["NoLogsAvailable"] = "No logs available",

        },
        
        ["ภาษาไทย"] = new()
        {
            // Navigation
            ["Dashboard"] = "📊 แดชบอร์ด",
            ["Scanner"] = "🔍 สแกน",
            ["AutoScan"] = "⏰ สแกนอัตโนมัติ",
            ["Quarantine"] = "🔒 กักกัน",
            ["Startup"] = "🚀 โปรแกรมเริ่มต้น",
            ["Settings"] = "⚙️ ตั้งค่า",
            
            // Dashboard
            ["DashboardOverview"] = "ภาพรวมแดชบอร์ด",
            ["0KBFiles"] = "ไฟล์ 0KB",
            ["Threats"] = "ภัยคุกคาม",
            ["MemoryAlerts"] = "การแจ้งเตือนหน่วยความจำ",
            ["Removed"] = "ลบแล้ว",
            ["RealTimeProtection"] = "⚡ การป้องกันแบบเรียลไทม์",
            ["MonitorFileSystem"] = "ตรวจสอบระบบไฟล์",
            ["MonitorMemoryUsage"] = "ตรวจสอบการใช้หน่วยความจำ",
            ["StatusInactive"] = "สถานะ: ไม่ทำงาน",
            ["StatusProtected"] = "สถานะ: ✓ ได้รับการป้องกัน",
            ["ThreatDatabase"] = "ฐานข้อมูลภัยคุกคาม: {0} ลายเซ็น",
            ["SystemInformation"] = "💻 ข้อมูลระบบ",
            ["QuickActions"] = "⚡ การดำเนินการด่วน",
            ["QuickScan"] = "🔍 สแกนด่วน",
            ["ScanPC"] = "💿 สแกนพีซี",
            ["Schedule"] = "⏰ กำหนดการ",
            
            // Scanner
            ["SelectScanLocation"] = "เลือกตำแหน่งการสแกน:",
            ["StartScan"] = "🔍 เริ่มสแกน",
            ["ScanEntirePC"] = "💿 สแกนพีซีทั้งหมด",
            ["Stop"] = "⏹️ หยุด",
            ["ReadyToScan"] = "พร้อมสแกน",
            ["QuarantineBtn"] = "🔒 กักกัน",
            ["Delete"] = "🗑️ ลบ",
            ["ClearAll"] = "🗑️ ล้างทั้งหมด",
            ["SelectAll"] = "✔ เลือกทั้งหมด",
            
            // Settings
            ["SettingsTitle"] = "⚙️ ตั้งค่า",
            ["ApplicationSettings"] = "การตั้งค่าแอปพลิเคชัน",
            ["Language"] = "ภาษา:",
            ["MinimizeToTray"] = "ย่อเล็กสุดไปที่ถาดระบบ",
            ["SoundNotifications"] = "การแจ้งเตือนเสียง",
            ["VirusTotalAPIKey"] = "คีย์ API ของ VirusTotal:",
            ["SaveAPIKey"] = "💾 บันทึกคีย์ API",
            
            // Messages
            ["ScanStarted"] = "เริ่มสแกนแล้ว",
            ["ScanComplete"] = "สแกนเสร็จสิ้น",
            ["SettingsSaved"] = "บันทึกการตั้งค่าแล้ว",
            ["VirusTotalUpdated"] = "อัปเดตคีย์ API ของ VirusTotal แล้ว",
            ["LanguageChanged"] = "เปลี่ยนภาษาเป็น {0} แล้ว",
            // Schedule Page
    ["ScheduledAutoScan"] = "⏰ สแกนอัตโนมัติตามกำหนดเวลา",
    ["ConfigureAutoScan"] = "ตั้งค่าการสแกนอัตโนมัติ",
    ["ScanInterval"] = "ช่วงเวลาการสแกน:",
    ["StartAutoScan"] = "▶️ เริ่มสแกนอัตโนมัติ",
    ["StopAutoScan"] = "⏹️ หยุดสแกนอัตโนมัติ",
    ["AutoScanInfo"] = "💡 การสแกนอัตโนมัติจะสแกนพีซีทั้งหมดตามช่วงเวลาที่เลือก\n    ทำงานในพื้นหลังและแจ้งเตือนภัยคุกคาม",
    ["CurrentStatus"] = "สถานะปัจจุบัน",
    ["AutoScanActive"] = "✓ สแกนอัตโนมัติกำลังทำงาน",
    ["AutoScanInactive"] = "สแกนอัตโนมัติไม่ทำงาน",
    ["LastScan"] = "สแกนครั้งล่าสุด: {0}",
    ["NextScan"] = "สแกนครั้งถัดไป: {0}",
    ["IntervalMinutes"] = "ช่วงเวลา: ทุก {0} นาที",
    ["NotYetRun"] = "ยังไม่ได้รัน",
    ["AutoScanNotScheduled"] = "สแกนอัตโนมัติ: ไม่ได้กำหนดเวลา",
    ["NextAutoScan"] = "สแกนอัตโนมัติครั้งถัดไป: {0}",
    
    // Quarantine Page
    ["QuarantinedFiles"] = "🔒 ไฟล์ที่ถูกกักกัน",
    ["FileName"] = "ชื่อไฟล์",
    ["QuarantineDate"] = "วันที่กักกัน",
    ["Size"] = "ขนาด",
    ["Restore"] = "↩️ กู้คืน",
    ["SelectFilesFirst"] = "เลือกไฟล์ที่จะ{0}ก่อน!",
    ["ConfirmRestore"] = "กู้คืน {0} ไฟล์ไปยังตำแหน่งเดิม?",
    ["ConfirmDelete"] = "ลบ {0} ไฟล์ถาวร?\n\n⚠️ ไม่สามารถยกเลิกได้!",
    ["RestoreComplete"] = "กู้คืนเสร็จสิ้น",
    ["DeleteComplete"] = "ลบเสร็จสิ้น",
    ["RestoredCount"] = "✅ กู้คืน: {0}\n❌ ล้มเหลว: {1}",
    ["DeletedCount"] = "✅ ลบแล้ว: {0}\n❌ ล้มเหลว: {1}",
    ["ClearSelection"] = "✖ ยกเลิกการเลือก",
    
    // Startup Page
    ["StartupPrograms"] = "🚀 โปรแกรมเริ่มต้น",
    ["Program"] = "โปรแกรม",
    ["Path"] = "เส้นทาง",
    ["Location"] = "ตำแหน่ง",
    
    // Scanner Messages
    ["ScanningPath"] = "กำลังสแกน: {0}",
    ["FullPCScanConfirm"] = "จะสแกนไดรฟ์ทั้งหมดบนพีซี อาจใช้เวลานาน!\n\nดำเนินการต่อ?",
    ["FullPCScan"] = "สแกนพีซีทั้งหมด",
    ["ScanningAllDrives"] = "กำลังสแกนไดรฟ์ทั้งหมด...",
    ["ScanCancelled"] = "ยกเลิกการสแกน",
    ["ScanStopped"] = "การสแกนถูกหยุดโดยผู้ใช้",
    ["FullPCScanStopped"] = "การสแกนพีซีทั้งหมดถูกหยุดโดยผู้ใช้",
    ["ClearThreatsConfirm"] = "ล้างภัยคุกคามทั้งหมดจากรายการ?\n\nจะไม่ลบไฟล์ เพียงแต่ลบออกจากรายการนี้",
    ["ClearThreats"] = "ล้างภัยคุกคาม",
    ["ThreatListCleared"] = "ล้างรายการภัยคุกคามแล้ว",
    
    // Scan intervals
    ["5MinutesDemo"] = "5 นาที (ทดสอบ)",
    ["15Minutes"] = "15 นาที",
    ["30Minutes"] = "30 นาที",
    ["1Hour"] = "1 ชั่วโมง",
    ["2Hours"] = "2 ชั่วโมง",
    ["6Hours"] = "6 ชั่วโมง",
    ["12Hours"] = "12 ชั่วโมง",
    ["24Hours"] = "24 ชั่วโมง (รายวัน)",
    
    // Notifications
    ["AutoScanStartedMsg"] = "สแกนทุก {0}",
    ["AutoScanStoppedMsg"] = "ปิดการสแกนตามกำหนดเวลา",

    ["ViewLogs"] = "📋 ดูบันทึก",
["Logs"] = "📋 บันทึก",
["ApplicationLogs"] = "บันทึกแอปพลิเคชัน",
["ClearLogs"] = "🗑️ ล้างบันทึก",
["ExportLogs"] = "💾 ส่งออกบันทึก",
["RefreshLogs"] = "🔄 รีเฟรช",
["LogsCleared"] = "ล้างบันทึกแล้ว",
["LogsClearedMsg"] = "ล้างบันทึกทั้งหมดแล้ว",
["LogsExported"] = "ส่งออกบันทึกแล้ว",
["LogsExportedMsg"] = "ส่งออกบันทึกไปที่: {0}",
["NoLogsAvailable"] = "ไม่มีบันทึก",

        }
    };
    
    public static string Get(string key, params object[] args)
    {
        if (Translations.ContainsKey(_currentLanguage) && 
            Translations[_currentLanguage].ContainsKey(key))
        {
            var text = Translations[_currentLanguage][key];
            return args.Length > 0 ? string.Format(text, args) : text;
        }
        return key; // Fallback to key if translation not found
    }
}