from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Verdict(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Finding:
    source: str
    rule: str
    severity: int
    description: str


@dataclass(slots=True)
class ScanResult:
    path: Path
    sha256: str | None = None
    size: int | None = None
    verdict: Verdict = Verdict.CLEAN
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        if finding.severity >= 90:
            self.verdict = Verdict.MALICIOUS
        elif finding.severity >= 40 and self.verdict is Verdict.CLEAN:
            self.verdict = Verdict.SUSPICIOUS

    def as_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "size": self.size,
            "verdict": self.verdict.value,
            "findings": [
                {
                    "source": item.source,
                    "rule": item.rule,
                    "severity": item.severity,
                    "description": item.description,
                }
                for item in self.findings
            ],
            "error": self.error,
        }

