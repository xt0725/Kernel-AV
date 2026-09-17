from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

from .models import ScanResult


SCHEMA = """
CREATE TABLE IF NOT EXISTS signatures (
    sha256 TEXT PRIMARY KEY CHECK(length(sha256) = 64),
    family TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT,
    verdict TEXT NOT NULL,
    details_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantine (
    id TEXT PRIMARY KEY,
    original_path TEXT NOT NULL,
    vault_path TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    quarantined_at TEXT NOT NULL,
    restored_at TEXT
);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def add_signature(self, sha256: str, family: str, source: str = "local") -> None:
        digest = sha256.lower().strip()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("sha256 must contain exactly 64 hexadecimal characters")
        with self.connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO signatures VALUES (?, ?, ?, ?)",
                (digest, family.strip() or "unknown", source, _now()),
            )

    def find_signature(self, sha256: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                "SELECT sha256, family, source FROM signatures WHERE sha256 = ?",
                (sha256.lower(),),
            ).fetchone()

    def log_detection(self, result: ScanResult) -> None:
        if result.verdict.value == "clean":
            return
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO detections(scanned_at, path, sha256, verdict, details_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (_now(), str(result.path), result.sha256, result.verdict.value,
                 json.dumps(result.as_dict(), ensure_ascii=False)),
            )


def _now() -> str:
    return datetime.now(UTC).isoformat()

