# Architecture and trust boundaries

Kernel-AV is designed as separate components so that parsing untrusted files never needs
service-control privileges.

1. **Engine** — deterministic scanning, hashing, signatures, YARA, and heuristics.
2. **Agent** — file-system and process telemetry, rate limiting, and scan scheduling.
3. **Service** — narrow privileged broker for quarantine and protected configuration.
4. **UI/CLI** — unprivileged clients using an authenticated local IPC channel.
5. **Updater** — downloads a signed manifest, verifies it offline, then swaps databases atomically.

The current milestone implements the engine, CLI, audit log, and a local quarantine vault.
It does not claim kernel-level blocking or tamper resistance.

## Non-negotiable controls

- Treat YARA rules, update manifests, file metadata, and paths as untrusted input.
- Never execute or dynamically import a scanned file.
- Parse risky formats in a resource-constrained worker process in a later milestone.
- Require signatures and monotonic versions for remote signature updates.
- Store quarantine objects under random names, remove execute permissions, verify hashes on
  entry and restoration, and never overwrite a restore target.
- Keep the GUI and scanner unable to stop, replace, or reconfigure the protected service.
- Make every detection explainable: source, rule, severity, and timestamp.

## Planned Windows hardening

The production service will use a dedicated service SID, explicit DACLs, restricted IPC,
and SCM recovery settings. Protected Process Light is not promised: Microsoft restricts
anti-malware protected services to properly signed ELAM vendors. Kernel callbacks and
filesystem minifilters are out of scope until the user-mode pipeline is stable and audited.

