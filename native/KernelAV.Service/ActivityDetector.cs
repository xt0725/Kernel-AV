namespace KernelAV.Service;

public sealed class ActivityDetector
{
    private readonly Queue<FileActivity> _events = new();
    private DateTimeOffset _lastAlert = DateTimeOffset.MinValue;

    public BehaviorAlert? Observe(FileActivity activity)
    {
        lock (_events)
        {
            _events.Enqueue(activity);
            var cutoff = activity.ObservedAt.AddSeconds(-10);
            while (_events.TryPeek(out var oldest) && oldest.ObservedAt < cutoff)
            {
                _events.Dequeue();
            }

            var paths = _events.Select(item => item.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var directories = _events.Select(item => Path.GetDirectoryName(item.Path) ?? string.Empty)
                .Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var renames = _events.Count(item => item.Kind == "moved");
            var note = _events.Any(item => IsRansomNote(Path.GetFileName(item.Path)));

            var score = 0;
            var reasons = new List<string>();
            if (_events.Count >= 80) { score += 30; reasons.Add("high event rate"); }
            if (paths >= 30) { score += 35; reasons.Add("many distinct files"); }
            if (directories >= 3) { score += 10; reasons.Add("multiple directories"); }
            if (renames >= 15) { score += 20; reasons.Add("rename burst"); }
            if (note) { score += 20; reasons.Add("possible ransom note"); }

            if (score < 70 || activity.ObservedAt - _lastAlert < TimeSpan.FromSeconds(30))
            {
                return null;
            }

            _lastAlert = activity.ObservedAt;
            return new BehaviorAlert(
                "ransomware-like-file-activity",
                Math.Min(100, score),
                Path.GetDirectoryName(activity.Path) ?? activity.Path,
                "Correlated filesystem activity: " + string.Join(", ", reasons),
                new { events = _events.Count, uniqueFiles = paths, directories, renames });
        }
    }

    private static bool IsRansomNote(string filename) => filename.ToLowerInvariant() is
        "readme.txt" or "decrypt.txt" or "how_to_decrypt.txt" or "restore_files.txt";
}

