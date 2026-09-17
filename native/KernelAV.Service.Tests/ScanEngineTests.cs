using KernelAV.Service;
using Xunit;

namespace KernelAV.Service.Tests;

public sealed class ScanEngineTests
{
    [Fact]
    public async Task CleanFileHasSha256AndCleanVerdict()
    {
        var path = Path.Combine(Path.GetTempPath(), $"kernel-av-{Guid.NewGuid():N}.txt");
        try
        {
            await File.WriteAllTextAsync(path, "ordinary text");
            var result = await new ScanEngine().ScanAsync(path, CancellationToken.None);
            Assert.Equal(Verdict.Clean, result.Verdict);
            Assert.Equal(64, result.Sha256?.Length);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task EncodedPowerShellIsSuspicious()
    {
        var path = Path.Combine(Path.GetTempPath(), $"kernel-av-{Guid.NewGuid():N}.ps1");
        try
        {
            await File.WriteAllTextAsync(path,
                "powershell -ExecutionPolicy Bypass -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            var result = await new ScanEngine().ScanAsync(path, CancellationToken.None);
            Assert.Equal(Verdict.Suspicious, result.Verdict);
            Assert.Contains(result.Findings, item => item.Rule == "suspicious-powershell");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void RansomwareBurstProducesAlert()
    {
        var detector = new ActivityDetector();
        BehaviorAlert? alert = null;
        var start = DateTimeOffset.UtcNow;
        for (var index = 0; index < 85; index++)
        {
            alert ??= detector.Observe(new FileActivity(
                $@"C:\Users\Public\Documents\folder-{index % 4}\document-{index}.locked",
                "moved",
                start.AddMilliseconds(index * 10)));
        }
        Assert.NotNull(alert);
        Assert.Equal("ransomware-like-file-activity", alert!.Category);
    }
}
