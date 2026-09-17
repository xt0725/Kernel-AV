from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from kernel_av.database import Database
from kernel_av.models import Verdict
from kernel_av.scanner import Scanner


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_known_hash_is_malicious(self) -> None:
        sample = self.root / "sample.bin"
        sample.write_bytes(b"known bad test fixture")
        digest = hashlib.sha256(sample.read_bytes()).hexdigest()
        database = Database(self.root / "db.sqlite")
        database.add_signature(digest, "Test.Family")

        result = Scanner(database).scan_file(sample)

        self.assertIs(result.verdict, Verdict.MALICIOUS)
        self.assertEqual(result.sha256, digest)
        self.assertEqual(result.findings[0].source, "signature")

    def test_powershell_traits_are_reported(self) -> None:
        sample = self.root / "loader.ps1"
        sample.write_text(
            "powershell -ExecutionPolicy Bypass -EncodedCommand " + "A" * 40
            + "; IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('AAAA')))"
        )
        result = Scanner(Database(self.root / "db.sqlite")).scan_file(sample)
        self.assertIs(result.verdict, Verdict.SUSPICIOUS)
        self.assertTrue(any(item.rule == "suspicious-powershell" for item in result.findings))

    def test_clean_file(self) -> None:
        sample = self.root / "notes.txt"
        sample.write_text("ordinary text")
        result = Scanner(Database(self.root / "db.sqlite")).scan_file(sample)
        self.assertIs(result.verdict, Verdict.CLEAN)
