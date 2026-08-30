# Canary Sentinel (offline Windows agent)

Run this script on the Windows endpoint that owns the folder you want to protect. It watches only the paths supplied by the user, plants harmless decoy files, adds a new decoy when a normal file is created, rotates decoy names on a timer, and emits an immediate local buzzer plus an offline JSONL alert when a canary is changed, renamed, or deleted.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
E:\Cyber-Security-Platform\scripts\canary-sentinel.ps1 `
  -WatchPath 'E:\MyProtectedFolder' `
  -RotationMinutes 30
```

Offline alerts are written to `storage\canary-sentinel\alerts.jsonl`.

The agent also maintains `storage\canary-sentinel\canary-inventory.json`, including the original SHA-256 of every active decoy. Alerts are deduplicated for ten seconds by default so that one write operation does not cause a notification storm.

To start monitoring automatically every time the user signs in, install the per-user scheduled task (run once):

```powershell
.\scripts\install-canary-sentinel-task.ps1 -WatchPath 'E:\MyProtectedFolder'
```

Windows directory-change notifications do not reliably report a plain file **read/open** operation. Reliable read-access attribution needs Windows object-access auditing (SACL/audit policy) or a signed kernel minifilter, both of which require administrator deployment. This agent therefore alerts immediately for observable file changes, renames, and deletion; it does not claim reliable read-only detection.

## Endpoint incident response additions

Monitoring is recursive by default, so a selected protected root includes its
subfolders. The decoy notice is customizable while keeping a secure default:

```powershell
.\scripts\canary-sentinel.ps1 `
  -WatchPath 'C:\Users\Analyst\Documents' `
  -IncludeSubdirectories $true `
  -CanaryNotice 'TOP SECRET — Finance investigation file. Unauthorized access is prohibited.'
```

Every canary change creates a timestamped evidence bundle under
`storage\canary-sentinel\evidence`. It contains the alert, endpoint identity,
local IPv4 addresses, a TCP-connection snapshot, process snapshot, SHA-256,
and a small chain-of-custody record. A snapshot is useful for correlation but
does not prove which process changed a file; that requires ETW/audit/minifilter
telemetry.

Network containment is intentionally disabled by default. It isolates the
**victim endpoint**, not an attacker device, and requires an elevated
Administrator PowerShell session. First specify the backend/VPN responder IPs
that must remain reachable, then use:

```powershell
.\scripts\canary-sentinel.ps1 `
  -WatchPath 'C:\Users\Analyst\Documents' `
  -IsolationMode NetworkIsolate `
  -AllowedRemoteAddress '10.10.10.20','10.10.10.21'
```

The isolation helper saves the prior outbound firewall policy before changing
it. Restore networking only after analyst approval:

```powershell
.\scripts\restore-endpoint-network.ps1
```

Generate a review-required complaint/FIR draft from one evidence bundle:

```powershell
$evidenceDirectory = Get-ChildItem .\storage\canary-sentinel\evidence -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
.\scripts\generate-fir-draft.ps1 `
  -EvidenceDirectory $evidenceDirectory `
  -ComplainantName 'Authorized complainant' `
  -OrganizationName 'Example Organization'
```

This produces a local draft with evidence SHA-256 and chain-of-custody. It is
not a police submission: a real FIR submission/status synchronization needs an
authorized police or cybercrime-portal integration and complainant approval.

## Offline police/analyst voice briefing

The offline assistant compares only locally stored evidence bundles, cites the
matching evidence paths/timestamps, and never claims a matching pattern proves
an attacker identity. Create a briefing and read it aloud through the local
Windows voice engine:

```powershell
.\scripts\incident-briefing-assistant.ps1 `
  -EvidenceDirectory $evidenceDirectory `
  -Speak
```

The saved JSON briefing is the proof/reference record an analyst can review
with police before making any allegation or filing.
