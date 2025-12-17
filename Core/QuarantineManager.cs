using System.Text.Json;

namespace SecurityMonitorPro.Core
{
    public class QuarantineManager
    {
        private readonly string _quarantinePath;

        public QuarantineManager()
        {
            // Use path relative to the EXE location (works anywhere!)
            var appDirectory = AppDomain.CurrentDomain.BaseDirectory;
            _quarantinePath = Path.Combine(appDirectory, "Quarantine");
            Directory.CreateDirectory(_quarantinePath);
        }

        public bool QuarantineFile(string filePath)
        {
            try
            {
                var fileName = Path.GetFileName(filePath);
                var stamp = DateTime.Now.ToString("yyyyMMddHHmmss");
                var quarantineFile = Path.Combine(_quarantinePath, $"{stamp}_{fileName}");

                File.Move(filePath, quarantineFile);

                // Store original path for restoring
                File.WriteAllText(quarantineFile + ".meta", filePath);

                return true;
            }
            catch
            {
                return false;
            }
        }

        public List<string> GetQuarantinedFiles()
        {
            return Directory.GetFiles(_quarantinePath)
                .Where(f => !f.EndsWith(".meta"))
                .ToList();
        }

        public bool RestoreFile(string quarantinedFile)
        {
            try
            {
                string meta = quarantinedFile + ".meta";
                if (!File.Exists(meta))
                    return false;

                string originalPath = File.ReadAllText(meta);

                Directory.CreateDirectory(Path.GetDirectoryName(originalPath)!);

                File.Move(quarantinedFile, originalPath);
                File.Delete(meta);

                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool DeleteQuarantined(string quarantinedFile)
        {
            try
            {
                File.Delete(quarantinedFile);

                string meta = quarantinedFile + ".meta";
                if (File.Exists(meta))
                    File.Delete(meta);

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}