# Kernel-AV

Kernel-AV is an early-stage, Windows-first defensive endpoint scanner. The project favors
explainable detections, least privilege, and testable components over "kernel antivirus"
marketing claims.

## Milestone 1: scanning core

Implemented in this milestone:

- on-demand streaming SHA-256 scans;
- SQLite signature database;
- optional YARA rules with per-rule severity;
- heuristics for scripts, suspicious PowerShell, Office macros, misleading extensions,
  and executables in unusual user-writable locations;
- JSON detection output and durable SQLite detection logging;
- quarantine with random vault names, restrictive permissions, copy verification,
  race detection through an expected hash, and collision-safe restoration;
- unit tests that use harmless fixtures only.

This is **not yet a replacement for Microsoft Defender or another production EDR**. Real-time
monitoring, process telemetry, ransomware scoring, signed updates, a Windows service, service
hardening, and the GUI belong to subsequent milestones.

## Quick start

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[yara]"
python -m unittest discover -s tests

kernel-av scan .\sample.bin --rules .\rules
kernel-av add-signature <sha256> <family> --source local
kernel-av quarantine .\sample.bin --sha256 <sha256>
kernel-av restore <quarantine-id>
```

Exit codes are `0` clean, `10` suspicious, `20` malicious, and `30` scan error. A missing
`yara-python` installation produces an explicit warning while SHA-256 and heuristic scanning
continue to work.

## Delivery roadmap

| Milestone | Scope | Security gate |
| --- | --- | --- |
| 1 — Core | scan, signatures, YARA, heuristics, log, quarantine | unit tests and safe fixtures |
| 2 — Sensor | real-time file events and process telemetry | bounded queues, deduplication, load tests |
| 3 — Behavior | ransomware correlation and response | canary tests, false-positive policy, rollback |
| 4 — Updates | signed manifests and atomic database updates | offline signature verification, anti-rollback |
| 5 — Product | Windows service, authenticated IPC, GUI | ACL review, installer/uninstaller tests |
| 6 — Hardening | tamper resistance and optional driver research | code signing and independent security review |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for trust boundaries and constraints.

## Safety

Use only harmless fixtures such as EICAR in tests. Do not commit malware samples, secrets,
private telemetry, or unsigned signature feeds. Quarantined files remain potentially dangerous;
restore them only when you understand why they were detected.

## License

MIT
