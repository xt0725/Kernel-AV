from __future__ import annotations

import re
import zipfile
from pathlib import Path

from .models import Finding


SCRIPT_EXTENSIONS = {".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".cmd", ".bat"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".com", ".cpl", ".msi"}
OFFICE_EXTENSIONS = {".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".ppsm"}

POWERSHELL_PATTERNS = {
    "encoded-command": re.compile(rb"(?i)(?:-enc(?:odedcommand)?\s+)[A-Za-z0-9+/]{24,}={0,2}"),
    "download-cradle": re.compile(rb"(?i)(invoke-webrequest|downloadstring|invoke-expression|\biex\b)"),
    "memory-loader": re.compile(rb"(?i)(virtualalloc|writeprocessmemory|reflection\.assembly|frombase64string)"),
    "execution-bypass": re.compile(rb"(?i)(executionpolicy\s+bypass|windowstyle\s+hidden)"),
}


def inspect(path: Path, sample: bytes) -> list[Finding]:
    findings: list[Finding] = []
    suffix = path.suffix.lower()
    lower_name = path.name.lower()

    if suffix in SCRIPT_EXTENSIONS:
        findings.append(Finding("heuristic", "script-file", 25, f"Script file ({suffix})"))

    if suffix in EXECUTABLE_EXTENSIONS and _unusual_location(path):
        findings.append(Finding("heuristic", "unusual-executable-location", 45,
                                "Executable located in a user-writable or startup directory"))

    if re.search(r"(?i)\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|com|bat|cmd|js)$", lower_name):
        findings.append(Finding("heuristic", "double-extension", 70,
                                "Filename uses a misleading double extension"))

    if suffix in EXECUTABLE_EXTENSIONS and not sample.startswith((b"MZ", b"\xd0\xcf\x11\xe0")):
        findings.append(Finding("heuristic", "extension-content-mismatch", 55,
                                "Executable extension does not match the file header"))

    if suffix in SCRIPT_EXTENSIONS or b"powershell" in sample.lower():
        matched = [name for name, pattern in POWERSHELL_PATTERNS.items() if pattern.search(sample)]
        if matched:
            severity = min(85, 35 + 15 * len(matched))
            findings.append(Finding("heuristic", "suspicious-powershell", severity,
                                    "Suspicious PowerShell traits: " + ", ".join(matched)))

    if suffix in OFFICE_EXTENSIONS and _contains_vba(path):
        findings.append(Finding("heuristic", "office-macro", 50,
                                "Macro-enabled Office document contains a VBA project"))

    return findings


def _unusual_location(path: Path) -> bool:
    normalized = str(path.resolve(strict=False)).replace("/", "\\").lower()
    markers = ("\\temp\\", "\\tmp\\", "\\downloads\\", "\\startup\\", "\\appdata\\local\\")
    return any(marker in normalized for marker in markers)


def _contains_vba(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            return any(name.lower().endswith("vbaproject.bin") for name in archive.namelist())
    except (OSError, zipfile.BadZipFile):
        return False

