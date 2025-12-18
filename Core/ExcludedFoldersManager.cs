using System.Text.Json;

namespace SecurityMonitorPro.Core;

public class ExcludedFoldersManager
{
    private readonly string _configPath;
    private HashSet<string> _excludedFolders = new(StringComparer.OrdinalIgnoreCase);

    public ExcludedFoldersManager()
    {
        var appDirectory = AppDomain.CurrentDomain.BaseDirectory;
        _configPath = Path.Combine(appDirectory, "ExcludedFolders.json");
        LoadExcludedFolders();
    }

    public void AddFolder(string folderPath)
    {
        if (Directory.Exists(folderPath))
        {
            _excludedFolders.Add(folderPath);
            SaveExcludedFolders();
            LogManager.WriteLog($"Added to exclusion list: {folderPath}", LogLevel.Info);
        }
    }

    public void RemoveFolder(string folderPath)
    {
        if (_excludedFolders.Remove(folderPath))
        {
            SaveExcludedFolders();
            LogManager.WriteLog($"Removed from exclusion list: {folderPath}", LogLevel.Info);
        }
    }

    public bool IsExcluded(string folderPath)
    {
        // Check if the folder itself is excluded
        if (_excludedFolders.Contains(folderPath))
            return true;

        // Check if any parent folder is excluded
        foreach (var excluded in _excludedFolders)
        {
            if (folderPath.StartsWith(excluded, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    public List<string> GetExcludedFolders()
    {
        return _excludedFolders.ToList();
    }

    public void ClearAll()
    {
        _excludedFolders.Clear();
        SaveExcludedFolders();
        LogManager.WriteLog("Cleared all excluded folders", LogLevel.Info);
    }

    private void LoadExcludedFolders()
    {
        try
        {
            if (File.Exists(_configPath))
            {
                var json = File.ReadAllText(_configPath);
                var folders = JsonSerializer.Deserialize<List<string>>(json);
                if (folders != null)
                {
                    _excludedFolders = new HashSet<string>(folders, StringComparer.OrdinalIgnoreCase);
                    LogManager.WriteLog($"Loaded {_excludedFolders.Count} excluded folders", LogLevel.Info);
                }
            }
        }
        catch (Exception ex)
        {
            LogManager.WriteLog($"Error loading excluded folders: {ex.Message}", LogLevel.Error);
        }
    }

    private void SaveExcludedFolders()
    {
        try
        {
            var json = JsonSerializer.Serialize(_excludedFolders.ToList(), new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_configPath, json);
        }
        catch (Exception ex)
        {
            LogManager.WriteLog($"Error saving excluded folders: {ex.Message}", LogLevel.Error);
        }
    }
}