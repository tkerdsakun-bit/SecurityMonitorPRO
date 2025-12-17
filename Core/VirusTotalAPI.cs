using System.Security.Cryptography;
using Newtonsoft.Json.Linq;

namespace SecurityMonitorPro.Core;

public class VirusTotalAPI
{
    private readonly string _apiKey;
    private readonly HttpClient _client;
    private const string API_URL = "https://www.virustotal.com/api/v3";
    
    public VirusTotalAPI(string apiKey = "")
    {
        _apiKey = apiKey;
        _client = new HttpClient();
        if (!string.IsNullOrEmpty(_apiKey))
        {
            _client.DefaultRequestHeaders.Add("x-apikey", _apiKey);
        }
    }

    public async Task<(bool isMalicious, int detections, string result)> CheckFileHashAsync(string filePath)
    {
        if (string.IsNullOrEmpty(_apiKey))
        {
            return (false, 0, "No API key configured");
        }

        try
        {
            var hash = CalculateSHA256(filePath);
            var response = await _client.GetAsync($"{API_URL}/files/{hash}");
            
            if (!response.IsSuccessStatusCode)
            {
                return (false, 0, "File not found in VirusTotal database");
            }

            var content = await response.Content.ReadAsStringAsync();
            var json = JObject.Parse(content);
            
            var stats = json["data"]?["attributes"]?["last_analysis_stats"];
            var malicious = stats?["malicious"]?.Value<int>() ?? 0;
            var suspicious = stats?["suspicious"]?.Value<int>() ?? 0;
            var total = malicious + suspicious;

            var isMalicious = malicious > 0;
            var result = $"{malicious}/{stats?["harmless"]?.Value<int>() + malicious} vendors flagged as malicious";

            return (isMalicious, total, result);
        }
        catch
        {
            return (false, 0, "Error checking VirusTotal");
        }
    }

    private static string CalculateSHA256(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hash = sha256.ComputeHash(stream);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }
}