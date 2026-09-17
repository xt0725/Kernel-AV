from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from time import monotonic


@dataclass(frozen=True, slots=True)
class FileActivity:
    path: Path
    kind: str
    observed_at: float


@dataclass(frozen=True, slots=True)
class BehaviorAlert:
    category: str
    severity: int
    subject: str
    description: str
    evidence: dict[str, object]


class RansomwareDetector:
    """Scores bursts of filesystem activity without taking destructive action."""

    NOTE_NAMES = {"readme.txt", "decrypt.txt", "how_to_decrypt.txt", "restore_files.txt"}

    def __init__(
        self,
        window_seconds: float = 10.0,
        event_threshold: int = 80,
        unique_file_threshold: int = 30,
        cooldown_seconds: float = 30.0,
    ):
        self.window_seconds = window_seconds
        self.event_threshold = event_threshold
        self.unique_file_threshold = unique_file_threshold
        self.cooldown_seconds = cooldown_seconds
        self.events: deque[FileActivity] = deque()
        self.last_alert = float("-inf")

    def observe(self, activity: FileActivity) -> BehaviorAlert | None:
        self.events.append(activity)
        cutoff = activity.observed_at - self.window_seconds
        while self.events and self.events[0].observed_at < cutoff:
            self.events.popleft()

        paths = {str(item.path).lower() for item in self.events}
        directories = {str(item.path.parent).lower() for item in self.events}
        suffixes = Counter(item.path.suffix.lower() for item in self.events if item.path.suffix)
        renames = sum(item.kind == "moved" for item in self.events)
        note_seen = any(item.path.name.lower() in self.NOTE_NAMES for item in self.events)

        score = 0
        reasons: list[str] = []
        if len(self.events) >= self.event_threshold:
            score += 30
            reasons.append("high event rate")
        if len(paths) >= self.unique_file_threshold:
            score += 35
            reasons.append("many distinct files")
        if len(directories) >= 3:
            score += 10
            reasons.append("multiple directories")
        if renames >= max(10, self.unique_file_threshold // 2):
            score += 20
            reasons.append("rename burst")
        if suffixes and suffixes.most_common(1)[0][1] >= 15:
            score += 10
            reasons.append("repeated output extension")
        if note_seen:
            score += 20
            reasons.append("possible ransom note")

        if score < 70 or activity.observed_at - self.last_alert < self.cooldown_seconds:
            return None
        self.last_alert = activity.observed_at
        return BehaviorAlert(
            category="ransomware-like-file-activity",
            severity=min(100, score),
            subject=str(activity.path.parent),
            description="Correlated filesystem activity: " + ", ".join(reasons),
            evidence={
                "window_seconds": self.window_seconds,
                "events": len(self.events),
                "unique_files": len(paths),
                "directories": len(directories),
                "renames": renames,
                "top_suffix": suffixes.most_common(1)[0] if suffixes else None,
            },
        )


class EventDeduplicator:
    def __init__(self, interval_seconds: float = 0.75):
        self.interval_seconds = interval_seconds
        self._last_seen: dict[str, float] = {}

    def accept(self, path: Path, kind: str, observed_at: float | None = None) -> bool:
        now = monotonic() if observed_at is None else observed_at
        key = str(path.resolve(strict=False)).casefold()
        previous = self._last_seen.get(key)
        self._last_seen[key] = now
        if len(self._last_seen) > 10_000:
            cutoff = now - self.interval_seconds * 4
            self._last_seen = {item: seen for item, seen in self._last_seen.items() if seen >= cutoff}
        return previous is None or now - previous >= self.interval_seconds
