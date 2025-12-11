using SecurityMonitorPro.Models;

namespace SecurityMonitorPro.Core;

public class ThreatDatabase
{
    private readonly List<RansomwareSignature> _signatures = new();
    private readonly string _dbPath;

    public ThreatDatabase()
    {
        _dbPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "SecurityMonitorPro", "ThreatDB.json");
        
        Directory.CreateDirectory(Path.GetDirectoryName(_dbPath)!);
        LoadDatabase();
    }

    private void LoadDatabase()
    {
        // Built-in ransomware signatures (2024 updated list)
        _signatures.AddRange(new[]
        {
            // LockBit variants
            new RansomwareSignature { Name = "LockBit", Extension = ".lockbit", Family = "LockBit" },
            new RansomwareSignature { Name = "LockBit 2.0", Extension = ".abcd", Family = "LockBit" },
            new RansomwareSignature { Name = "LockBit 3.0", Extension = ".lockbit3", Family = "LockBit" },
            
            // ALPHV/BlackCat
            new RansomwareSignature { Name = "BlackCat", Extension = ".sykdh", Family = "ALPHV" },
            new RansomwareSignature { Name = "ALPHV", Extension = ".alphv", Family = "ALPHV" },
            
            // Clop
            new RansomwareSignature { Name = "Clop", Extension = ".clop", Family = "Clop" },
            new RansomwareSignature { Name = "Clop", Extension = ".cIop", Family = "Clop" },
            
            // Akira
            new RansomwareSignature { Name = "Akira", Extension = ".akira", Family = "Akira" },
            
            // Play
            new RansomwareSignature { Name = "Play", Extension = ".play", Family = "Play" },
            
            // Royal
            new RansomwareSignature { Name = "Royal", Extension = ".royal", Family = "Royal" },
            
            // Classic ransomware
            new RansomwareSignature { Name = "WannaCry", Extension = ".wcry", Family = "WannaCry" },
            new RansomwareSignature { Name = "WannaCry", Extension = ".wncry", Family = "WannaCry" },
            new RansomwareSignature { Name = "Ryuk", Extension = ".ryk", Family = "Ryuk" },
            new RansomwareSignature { Name = "Ryuk", Extension = ".RYK", Family = "Ryuk" },
            new RansomwareSignature { Name = "Sodinokibi", Extension = ".sod", Family = "REvil" },
            new RansomwareSignature { Name = "REvil", Extension = ".revil", Family = "REvil" },
            new RansomwareSignature { Name = "DarkSide", Extension = ".darkside", Family = "DarkSide" },
            new RansomwareSignature { Name = "Maze", Extension = ".maze", Family = "Maze" },
            new RansomwareSignature { Name = "Conti", Extension = ".conti", Family = "Conti" },
            
            // File lockers
            new RansomwareSignature { Name = "CryptoLocker", Extension = ".encrypted", Family = "CryptoLocker" },
            new RansomwareSignature { Name = "Locky", Extension = ".locky", Family = "Locky" },
            new RansomwareSignature { Name = "Cerber", Extension = ".cerber", Family = "Cerber" },
            new RansomwareSignature { Name = "TeslaCrypt", Extension = ".micro", Family = "TeslaCrypt" },
            new RansomwareSignature { Name = "Petya", Extension = ".petya", Family = "Petya" },
            new RansomwareSignature { Name = "GoldenEye", Extension = ".goldeneye", Family = "Petya" },
            
            // Generic patterns
            new RansomwareSignature { Name = "Generic", Extension = ".locked", Family = "Generic" },
            new RansomwareSignature { Name = "Generic", Extension = ".crypto", Family = "Generic" },
            new RansomwareSignature { Name = "Generic", Extension = ".crypt", Family = "Generic" },
            new RansomwareSignature { Name = "Generic", Extension = ".encrypted", Family = "Generic" },
            new RansomwareSignature { Name = "Generic", Extension = ".coded", Family = "Generic" },
            new RansomwareSignature { Name = "Generic", Extension = ".crypted", Family = "Generic" },
            new RansomwareSignature { Name = "Generic", Extension = ".enc", Family = "Generic" },
        });
    }

    public async Task UpdateFromOnlineAsync()
    {
        // Simulate downloading latest signatures
        await Task.Delay(1000);
        // In production, download from threat intelligence feeds
    }

    public (bool isThreat, string? family) CheckExtension(string extension)
    {
        var match = _signatures.FirstOrDefault(s => 
            s.Extension.Equals(extension, StringComparison.OrdinalIgnoreCase));
        
        return match != null ? (true, match.Family) : (false, null);
    }

    public List<RansomwareSignature> GetAllSignatures() => _signatures;

    public int GetSignatureCount() => _signatures.Count;
}