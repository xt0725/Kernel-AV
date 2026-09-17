using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace KernelAV.Service;

public sealed partial class ScanEngine
{
    private const int SampleSize = 2 * 1024 * 1024;
    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".cmd", ".bat"
    };

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".cpl", ".msi"
    };

    public async Task<ScanResult> ScanAsync(string path, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                throw new FileNotFoundException("File disappeared before scanning", path);
            }

            string digest;
            await using (var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                digest = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken)).ToLowerInvariant();
            }

            var sample = new byte[Math.Min(SampleSize, checked((int)Math.Min(info.Length, int.MaxValue)))];
            await using (var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                _ = await stream.ReadAsync(sample, cancellationToken);
            }

            Inspect(path, sample, findings);
            var verdict = findings.Any(item => item.Severity >= 90)
                ? Verdict.Malicious
                : findings.Any(item => item.Severity >= 40) ? Verdict.Suspicious : Verdict.Clean;
            return new ScanResult(Path.GetFullPath(path), digest, info.Length, verdict, findings);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
        {
            return new ScanResult(Path.GetFullPath(path), null, 0, Verdict.Error, findings, exception.Message);
        }
    }

    private static void Inspect(string path, byte[] sample, List<Finding> findings)
    {
        var extension = Path.GetExtension(path);
        var filename = Path.GetFileName(path);
        var text = Encoding.UTF8.GetString(sample);

        if (ScriptExtensions.Contains(extension))
        {
            findings.Add(new Finding("script-file", 25, $"Script file ({extension})"));
        }

        if (DoubleExtensionRegex().IsMatch(filename))
        {
            findings.Add(new Finding("double-extension", 70, "Filename uses a misleading double extension"));
        }

        if (ExecutableExtensions.Contains(extension) && IsUserWritableLocation(path))
        {
            findings.Add(new Finding("unusual-executable-location", 45,
                "Executable is in a user-writable or startup directory"));
        }

        if (ScriptExtensions.Contains(extension) || text.Contains("powershell", StringComparison.OrdinalIgnoreCase))
        {
            var traits = new List<string>();
            if (EncodedCommandRegex().IsMatch(text)) traits.Add("encoded-command");
            if (DownloadCradleRegex().IsMatch(text)) traits.Add("download-cradle");
            if (MemoryLoaderRegex().IsMatch(text)) traits.Add("memory-loader");
            if (ExecutionBypassRegex().IsMatch(text)) traits.Add("execution-bypass");
            if (traits.Count > 0)
            {
                findings.Add(new Finding("suspicious-powershell", Math.Min(85, 35 + 15 * traits.Count),
                    "Suspicious PowerShell traits: " + string.Join(", ", traits)));
            }
        }
    }

    private static bool IsUserWritableLocation(string path)
    {
        var normalized = Path.GetFullPath(path).Replace('/', '\\').ToLowerInvariant();
        return new[] { "\\temp\\", "\\downloads\\", "\\startup\\", "\\appdata\\local\\" }
            .Any(normalized.Contains);
    }

    [GeneratedRegex(@"(?i)\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|com|bat|cmd|js)$")]
    private static partial Regex DoubleExtensionRegex();

    [GeneratedRegex(@"(?i)(?:-enc(?:odedcommand)?\s+)[A-Za-z0-9+/]{24,}={0,2}")]
    private static partial Regex EncodedCommandRegex();

    [GeneratedRegex(@"(?i)(invoke-webrequest|downloadstring|invoke-expression|\biex\b)")]
    private static partial Regex DownloadCradleRegex();

    [GeneratedRegex(@"(?i)(virtualalloc|writeprocessmemory|reflection\.assembly|frombase64string)")]
    private static partial Regex MemoryLoaderRegex();

    [GeneratedRegex(@"(?i)(executionpolicy\s+bypass|windowstyle\s+hidden)")]
    private static partial Regex ExecutionBypassRegex();
}

