from __future__ import annotations

import queue
import threading
from pathlib import Path
from time import monotonic
from typing import Callable

from .behavior import BehaviorAlert, EventDeduplicator, FileActivity, RansomwareDetector
from .database import Database
from .models import ScanResult
from .scanner import Scanner


class FileSensor:
    def __init__(
        self,
        root: Path,
        scanner: Scanner,
        database: Database,
        result_callback: Callable[[ScanResult], None] | None = None,
        alert_callback: Callable[[BehaviorAlert], None] | None = None,
        queue_size: int = 4096,
        ignored_paths: tuple[Path, ...] = (),
    ):
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("watch root must be a directory")
        self.scanner = scanner
        self.database = database
        self.result_callback = result_callback
        self.alert_callback = alert_callback
        database_path = database.path.resolve(strict=False)
        self.ignored_paths = {
            database_path,
            Path(str(database_path) + "-wal"),
            Path(str(database_path) + "-shm"),
            *(path.resolve(strict=False) for path in ignored_paths),
        }
        self.events: queue.Queue[FileActivity] = queue.Queue(maxsize=queue_size)
        self.deduplicator = EventDeduplicator()
        self.ransomware = RansomwareDetector()
        self._overflow = threading.Event()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._observer = None

    def submit(self, path: Path, kind: str, observed_at: float | None = None) -> bool:
        now = monotonic() if observed_at is None else observed_at
        target = path.resolve(strict=False)
        if target in self.ignored_paths:
            return False
        if not self.deduplicator.accept(target, kind, now):
            return False
        try:
            self.events.put_nowait(FileActivity(target, kind, now))
            return True
        except queue.Full:
            self._overflow.set()
            return False

    def start(self) -> None:
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError as exc:
            raise RuntimeError("watchdog is required for real-time file monitoring") from exc

        sensor = self

        class Handler(FileSystemEventHandler):
            def on_created(self, event: object) -> None:
                if not getattr(event, "is_directory", False):
                    sensor.submit(Path(str(getattr(event, "src_path"))), "created")

            def on_modified(self, event: object) -> None:
                if not getattr(event, "is_directory", False):
                    sensor.submit(Path(str(getattr(event, "src_path"))), "modified")

            def on_moved(self, event: object) -> None:
                if not getattr(event, "is_directory", False):
                    sensor.submit(Path(str(getattr(event, "dest_path"))), "moved")

        self._worker = threading.Thread(target=self._work, name="kernel-av-file-worker", daemon=True)
        self._worker.start()
        observer = Observer()
        observer.schedule(Handler(), str(self.root), recursive=True)
        observer.start()
        self._observer = observer

    def stop(self) -> None:
        self._stop.set()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
        if self._worker is not None:
            self._worker.join(timeout=5)

    def _work(self) -> None:
        while not self._stop.is_set() or not self.events.empty():
            if self._overflow.is_set():
                self._overflow.clear()
                self._rescan_tree()
            try:
                activity = self.events.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                alert = self.ransomware.observe(activity)
                if alert:
                    self.database.log_behavior(alert.category, alert.severity, alert.subject,
                                               {"description": alert.description, **alert.evidence})
                    if self.alert_callback:
                        self.alert_callback(alert)
                if activity.path.is_file():
                    result = self.scanner.scan_file(activity.path)
                    if self.result_callback:
                        self.result_callback(result)
            finally:
                self.events.task_done()

    def _rescan_tree(self) -> None:
        for path in self.root.rglob("*"):
            if self._stop.is_set():
                return
            if path.resolve(strict=False) not in self.ignored_paths and path.is_file():
                result = self.scanner.scan_file(path)
                if self.result_callback:
                    self.result_callback(result)
