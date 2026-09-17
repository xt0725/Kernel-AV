# Kernel-AV

Kernel-AV is an early-stage, Windows-first defensive endpoint scanner. The project favors
explainable detections, least privilege, and testable components over "kernel antivirus"
marketing claims.

## Milestones 1–2: scanning core and sensors

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
monitoring, process telemetry, and non-destructive ransomware scoring are now available as an
experimental sensor. Signed updates, automatic containment policy, a Windows service, service
hardening, and the GUI belong to subsequent milestones.

Milestone 2 adds:

- recursive OS-backed file create/modify/move events through Watchdog;
- bounded queues, duplicate-event suppression, and full-tree recovery after queue overflow;
- streaming scans for changed files;
- new-process polling with explainable detections for suspicious PowerShell and common
  signed-binary proxy execution patterns;
- a sliding-window ransomware score based on file rate, breadth, rename bursts, repeated
  extensions, and ransom-note names;
- durable behavioral alerts. The sensor reports only; it does not kill processes or delete data.

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
kernel-av watch C:\Users\me\Downloads --rules .\rules
kernel-av processes
```

Exit codes are `0` clean, `10` suspicious, `20` malicious, and `30` scan error. A missing
`yara-python` installation produces an explicit warning while SHA-256 and heuristic scanning
continue to work.

## Delivery roadmap

| Milestone | Scope | Security gate |
| --- | --- | --- |
| 1 — Core ✓ | scan, signatures, YARA, heuristics, log, quarantine | unit tests and safe fixtures |
| 2 — Sensor | real-time file events, process telemetry, ransomware score | bounded queues, deduplication, Windows CI |
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
