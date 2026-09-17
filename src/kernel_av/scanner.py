from __future__ import annotations

import hashlib
from pathlib import Path

from .database import Database
from .heuristics import inspect
from .models import Finding, ScanResult, Verdict
from .yara_engine import YaraEngine


CHUNK_SIZE = 1024 * 1024
SAMPLE_SIZE = 2 * 1024 * 1024


class Scanner:
    def __init__(self, database: Database, yara_engine: YaraEngine | None = None):
        self.database = database
        self.yara_engine = yara_engine

    def scan_file(self, path: Path) -> ScanResult:
        target = path.resolve(strict=False)
        result = ScanResult(path=target)
        try:
            if not target.is_file():
                raise ValueError("path is not a regular file")
            result.size = target.stat().st_size
            digest = hashlib.sha256()
            sample = bytearray()
            with target.open("rb") as handle:
                while chunk := handle.read(CHUNK_SIZE):
                    digest.update(chunk)
                    if len(sample) < SAMPLE_SIZE:
                        sample.extend(chunk[: SAMPLE_SIZE - len(sample)])
            result.sha256 = digest.hexdigest()

            signature = self.database.find_signature(result.sha256)
            if signature:
                result.add(Finding("signature", str(signature["family"]), 100,
                                   f"Known malicious SHA-256 ({signature['source']})"))

            for finding in inspect(target, bytes(sample)):
                result.add(finding)

            if self.yara_engine:
                for finding in self.yara_engine.scan(target):
                    result.add(finding)
        except (OSError, ValueError) as exc:
            result.verdict = Verdict.ERROR
            result.error = str(exc)
        except Exception as exc:
            result.verdict = Verdict.ERROR
            result.error = f"scanner component failed: {exc}"

        self.database.log_detection(result)
        return result

