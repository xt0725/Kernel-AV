namespace KernelAV.Service;

public enum Verdict
{
    Clean,
    Suspicious,
    Malicious,
    Error
}

public sealed record Finding(string Rule, int Severity, string Description);

public sealed record ScanResult(
    string Path,
    string? Sha256,
    long Size,
    Verdict Verdict,
    IReadOnlyList<Finding> Findings,
    string? Error = null);

public sealed record FileActivity(string Path, string Kind, DateTimeOffset ObservedAt);

public sealed record BehaviorAlert(
    string Category,
    int Severity,
    string Subject,
    string Description,
    object Evidence);

