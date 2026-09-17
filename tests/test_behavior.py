from __future__ import annotations

import unittest
from pathlib import Path

from kernel_av.behavior import EventDeduplicator, FileActivity, RansomwareDetector
from kernel_av.database import Database
from kernel_av.process_monitor import ProcessSnapshot, analyze_process
from kernel_av.scanner import Scanner
from kernel_av.sensor import FileSensor


class BehaviorTests(unittest.TestCase):
    def test_duplicate_file_events_are_suppressed(self) -> None:
        deduplicator = EventDeduplicator(interval_seconds=1.0)
        path = Path("sample.txt")
        self.assertTrue(deduplicator.accept(path, "modified", 10.0))
        self.assertFalse(deduplicator.accept(path, "created", 10.2))
        self.assertTrue(deduplicator.accept(path, "modified", 11.2))

    def test_ransomware_burst_generates_alert(self) -> None:
        detector = RansomwareDetector(event_threshold=20, unique_file_threshold=15)
        alert = None
        for index in range(25):
            alert = detector.observe(FileActivity(
                Path(f"root/folder-{index % 4}/document-{index}.locked"),
                "moved",
                float(index) / 10,
            )) or alert
        self.assertIsNotNone(alert)
        assert alert is not None
        self.assertEqual(alert.category, "ransomware-like-file-activity")
        self.assertGreaterEqual(alert.severity, 70)

    def test_office_spawned_encoded_powershell_is_high_severity(self) -> None:
        alert = analyze_process(ProcessSnapshot(
            pid=42,
            ppid=7,
            name="powershell.exe",
            executable=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=("powershell.exe", "-EncodedCommand", "AAAA"),
            parent_name="WINWORD.EXE",
        ))
        self.assertIsNotNone(alert)
        assert alert is not None
        self.assertEqual(alert.severity, 100)

    def test_normal_process_is_not_reported(self) -> None:
        self.assertIsNone(analyze_process(ProcessSnapshot(
            pid=1, ppid=0, name="notepad.exe", executable=r"C:\Windows\notepad.exe",
            command_line=("notepad.exe",), parent_name="explorer.exe"
        )))

    def test_sensor_marks_queue_overflow_for_recovery(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = Database(root / "state" / "db.sqlite")
            sensor = FileSensor(root, Scanner(database), database, queue_size=1)
            self.assertTrue(sensor.submit(root / "one.txt", "created", 1.0))
            self.assertFalse(sensor.submit(root / "two.txt", "created", 1.1))
            self.assertTrue(sensor._overflow.is_set())

    def test_sensor_ignores_its_database_files(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = Database(root / "db.sqlite")
            sensor = FileSensor(root, Scanner(database), database)
            self.assertFalse(sensor.submit(database.path, "modified", 1.0))
            self.assertFalse(sensor.submit(Path(str(database.path) + "-wal"), "modified", 1.0))
