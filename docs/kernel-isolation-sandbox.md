# Process isolation sandbox

This repository does not pretend that a PowerShell or Go process is a kernel-level sandbox. On Windows, trustworthy enforcement of file/process isolation requires a signed kernel minifilter driver, or an administrator-managed platform control such as Windows Defender Application Control (WDAC) or AppLocker. Those controls must be deployed by an endpoint administrator and tested against the organisation's application inventory.

`scripts/windows-isolation-readiness.ps1` is a safe, read-only readiness check. It reports whether the endpoint exposes Windows Sandbox, Hyper-V, Application Guard, and VBS signals.

The intended production design is:

1. The DDH endpoint agent collects canary and process telemetry in user mode.
2. WDAC/AppLocker allows only approved binaries in protected folders.
3. A signed minifilter driver (separate Windows-driver project, EV signing, HLK validation, staged rollout) blocks untrusted processes from reading, writing, renaming, or deleting protected paths.
4. The driver sends tamper-resistant events to the DDH agent, which creates incidents and alerts.

Do not ship a kernel driver until it has passed driver signing, crash-dump testing, rollback testing, and a pilot deployment. A faulty driver can make an endpoint unbootable.
