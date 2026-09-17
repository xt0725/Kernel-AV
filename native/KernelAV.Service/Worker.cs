using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace KernelAV.Service;

public sealed class Worker : BackgroundService
{
    private readonly ScanEngine _scanner;
    private readonly ActivityDetector _activityDetector;
    private readonly ILogger<Worker> _logger;
    private readonly Channel<FileActivity> _events = Channel.CreateBounded<FileActivity>(
        new BoundedChannelOptions(4096) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true });
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastSeen = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly SemaphoreSlim _logLock = new(1, 1);
    private readonly string _dataDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Kernel-AV");

    public Worker(ScanEngine scanner, ActivityDetector activityDetector, ILogger<Worker> logger)
    {
        _scanner = scanner;
        _activityDetector = activityDetector;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(_dataDirectory);
        StartWatchers();
        _logger.LogInformation("Kernel-AV native service started with {Count} watcher(s)", _watchers.Count);

        await foreach (var activity in _events.Reader.ReadAllAsync(stoppingToken))
        {
            var alert = _activityDetector.Observe(activity);
            if (alert is not null)
            {
                await WriteEventAsync("behavior", alert, stoppingToken);
            }

            if (!File.Exists(activity.Path)) continue;
            await Task.Delay(250, stoppingToken);
            var result = await _scanner.ScanAsync(activity.Path, stoppingToken);
            if (result.Verdict != Verdict.Clean)
            {
                await WriteEventAsync("scan", result, stoppingToken);
            }
        }
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        foreach (var watcher in _watchers) watcher.Dispose();
        _events.Writer.TryComplete();
        return base.StopAsync(cancellationToken);
    }

    private void StartWatchers()
    {
        var configured = Environment.GetEnvironmentVariable("KERNEL_AV_WATCH_ROOTS");
        var roots = string.IsNullOrWhiteSpace(configured)
            ? new[] { Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments) }
            : configured.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var root in roots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var watcher = new FileSystemWatcher(root)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                InternalBufferSize = 64 * 1024,
                EnableRaisingEvents = true
            };
            watcher.Created += (_, args) => Submit(args.FullPath, "created");
            watcher.Changed += (_, args) => Submit(args.FullPath, "modified");
            watcher.Renamed += (_, args) => Submit(args.FullPath, "moved");
            watcher.Error += (_, args) => _logger.LogError(args.GetException(), "Filesystem watcher overflow or failure");
            _watchers.Add(watcher);
        }
    }

    private void Submit(string path, string kind)
    {
        var now = DateTimeOffset.UtcNow;
        if (_lastSeen.TryGetValue(path, out var previous) &&
            now - previous < TimeSpan.FromMilliseconds(750))
        {
            _lastSeen[path] = now;
            return;
        }
        _lastSeen[path] = now;
        if (!_events.Writer.TryWrite(new FileActivity(path, kind, now)))
        {
            _logger.LogWarning("File event queue full; event dropped for {Path}", path);
        }
    }

    private async Task WriteEventAsync(string type, object payload, CancellationToken cancellationToken)
    {
        var envelope = JsonSerializer.Serialize(new { observedAt = DateTimeOffset.UtcNow, type, payload });
        var path = Path.Combine(_dataDirectory, "events.jsonl");
        await _logLock.WaitAsync(cancellationToken);
        try
        {
            await File.AppendAllTextAsync(path, envelope + Environment.NewLine, cancellationToken);
        }
        finally
        {
            _logLock.Release();
        }
    }
}
