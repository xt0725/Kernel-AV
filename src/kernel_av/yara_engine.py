from __future__ import annotations

from pathlib import Path

from .models import Finding


class YaraEngine:
    def __init__(self, rules_dir: Path | None):
        self.rules = None
        self.error: str | None = None
        if rules_dir is None:
            return
        try:
            import yara  # type: ignore[import-not-found]
        except ImportError:
            self.error = "yara-python is not installed; install kernel-av[yara]"
            return

        paths = sorted(rules_dir.glob("*.yar")) + sorted(rules_dir.glob("*.yara"))
        if not paths:
            self.error = f"no YARA rules found in {rules_dir}"
            return
        try:
            self.rules = yara.compile(filepaths={f"rule_{i}": str(path) for i, path in enumerate(paths)})
        except Exception as exc:  # yara exposes multiple version-specific exceptions
            self.error = f"unable to compile YARA rules: {exc}"

    def scan(self, path: Path) -> list[Finding]:
        if self.rules is None:
            return []
        matches = self.rules.match(str(path), timeout=10)
        findings: list[Finding] = []
        for match in matches:
            meta = match.meta or {}
            severity = int(meta.get("severity", 90))
            description = str(meta.get("description", f"YARA rule {match.rule} matched"))
            findings.append(Finding("yara", match.rule, max(0, min(100, severity)), description))
        return findings

