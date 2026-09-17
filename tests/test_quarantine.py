from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from kernel_av.database import Database
from kernel_av.quarantine import Quarantine


class QuarantineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_quarantine_and_restore_round_trip(self) -> None:
        source = self.root / "input" / "sample.exe"
        source.parent.mkdir()
        source.write_bytes(b"MZ harmless fixture")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        quarantine = Quarantine(Database(self.root / "db.sqlite"), self.root / "vault")

        item_id = quarantine.contain(source, digest)
        self.assertFalse(source.exists())

        restored = quarantine.restore(item_id)
        self.assertTrue(restored.samefile(source))
        self.assertEqual(restored.read_bytes(), b"MZ harmless fixture")

    def test_quarantine_rejects_changed_file(self) -> None:
        source = self.root / "sample.bin"
        source.write_bytes(b"current")
        quarantine = Quarantine(Database(self.root / "db.sqlite"), self.root / "vault")
        with self.assertRaisesRegex(ValueError, "changed after scanning"):
            quarantine.contain(source, "0" * 64)
        self.assertTrue(source.exists())
