from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Callable

from .behavior import BehaviorAlert


OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}


@dataclass(frozen=True, slots=True)
class ProcessSnapshot:
    pid: int
    ppid: int
    name: str
    executable: str
    command_line: tuple[str, ...]
    parent_name: str = ""


def analyze_process(process: ProcessSnapshot) -> BehaviorAlert | None:
    name = process.name.lower()
    parent = process.parent_name.lower()
    command = " ".join(process.command_line)
    lowered = command.lower()
    score = 0
    reasons: list[str] = []

    if name in {"powershell.exe", "pwsh.exe"}:
        if re.search(r"(?i)(?:-|/)(?:enc|encodedcommand)\b", command):
            score += 55
            reasons.append("encoded PowerShell command")
        if any(token in lowered for token in ("-windowstyle hidden", "-w hidden", "executionpolicy bypass")):
            score += 25
            reasons.append("hidden or bypassed PowerShell")
        if any(token in lowered for token in ("downloadstring", "invoke-webrequest", "frombase64string")):
            score += 25
            reasons.append("PowerShell download or decoding primitive")

    if parent in OFFICE_PROCESSES and name in SCRIPT_HOSTS:
        score += 75
        reasons.append("Office application spawned a script host")

    if name == "mshta.exe" and re.search(r"(?i)https?://", command):
        score += 80
        reasons.append("MSHTA launched remote content")
    if name == "regsvr32.exe" and re.search(r"(?i)(/i:.*https?://|scrobj\.dll)", command):
        score += 85
        reasons.append("Regsvr32 remote scriptlet pattern")
    if name == "rundll32.exe" and "javascript:" in lowered:
        score += 85
        reasons.append("Rundll32 JavaScript execution pattern")

    executable = process.executable.replace("/", "\\").lower()
    if any(marker in executable for marker in ("\\temp\\", "\\downloads\\")):
        score += 35
        reasons.append("process executable in a user-writable transient directory")

    if score < 50:
        return None
    return BehaviorAlert(
        category="suspicious-process",
        severity=min(100, score),
        subject=f"pid={process.pid} {process.name}",
        description="; ".join(reasons),
        evidence={
            "pid": process.pid,
            "ppid": process.ppid,
            "name": process.name,
            "parent_name": process.parent_name,
            "executable": process.executable,
            "command_line": list(process.command_line),
        },
    )


class ProcessMonitor:
    def __init__(self, callback: Callable[[BehaviorAlert], None], poll_seconds: float = 1.0):
        self.callback = callback
        self.poll_seconds = poll_seconds
        self._known: set[tuple[int, float]] = set()
        self._stop = threading.Event()

    def poll_once(self) -> int:
        try:
            import psutil  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("psutil is required for process telemetry") from exc

        emitted = 0
        current: set[tuple[int, float]] = set()
        for process in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time"]):
            try:
                info = process.info
                identity = (int(info["pid"]), float(info["create_time"] or 0))
                current.add(identity)
                if identity in self._known:
                    continue
                parent_name = ""
                try:
                    parent = process.parent()
                    parent_name = parent.name() if parent else ""
                except (psutil.Error, OSError):
                    pass
                snapshot = ProcessSnapshot(
                    pid=identity[0],
                    ppid=int(info["ppid"] or 0),
                    name=str(info["name"] or ""),
                    executable=str(info["exe"] or ""),
                    command_line=tuple(str(item) for item in (info["cmdline"] or ())),
                    parent_name=parent_name,
                )
                alert = analyze_process(snapshot)
                if alert:
                    self.callback(alert)
                    emitted += 1
            except (psutil.Error, OSError, ValueError, TypeError):
                continue
        self._known = current
        return emitted

    def run(self, seconds: float | None = None) -> None:
        deadline = None if seconds is None else monotonic() + seconds
        while not self._stop.is_set() and (deadline is None or monotonic() < deadline):
            self.poll_once()
            self._stop.wait(self.poll_seconds)

    def stop(self) -> None:
        self._stop.set()

