# Offline local run

The platform can run without Cloudflare, public URLs, SMTP, or an external AI
service. The laptop must remain powered on because the local API, file monitor,
notification worker, and AI engine run on the laptop.

## Start

From PowerShell:

```powershell
Set-Location E:\Cyber-Security-Platform
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\run-offline.ps1
```

Open the frontend locally at `http://127.0.0.1:5173`. The API is local at
`http://127.0.0.1:8080`.

The launcher starts:

- Go backend and its local PostgreSQL-backed threat/incident pipeline
- React frontend
- Python AI risk engine on port 8091
- Windows desktop notification agent

Use `-SkipAI` when the AI engine is not installed. Use `-SkipDesktopAgent` when
browser notifications and browser audio are sufficient.

## Detection and response flow

Deploy canary files from the Deception section. The backend watches those local
files for `MODIFIED`, `DELETED`, and `RENAMED` events. Each event is recorded as
a file event, evaluated by the local Threat Engine, and can automatically
create or update an incident. The notification worker writes an event into
`backend-go\storage\notification-outbox\local-desktop`.

The desktop agent consumes that outbox, shows a Windows tray balloon, and plays
an audible alert for medium/high/critical notifications. The web UI also polls
the backend and displays the alert in the notification drawer.

This monitor intentionally watches registered canary/protected files, not every
file on the laptop. Watching arbitrary system files would create unsafe noise
and could expose unrelated personal data.

## Offline malware analysis

Malware analysis is available through the Analysis Operations module and the
`/api/v1/malware` API:

- `POST /malware/analyze` creates a malware-analysis job for a local file.
- Files are accepted only under `OPERATIONAL_CONNECTOR_ALLOWED_ROOTS`.
- The connector computes SHA-256 immediately before scanning and rejects a
  supplied hash when it does not match.
- It runs `MALWARE_SCANNER_COMMAND`, or `clamscan` from `PATH` when unset.
  Missing scanners fail closed; they never produce a clean result.
- ClamAV exit code `0` is stored as `CLEAN`, exit code `1` as `INFECTED`, and
  other exit codes fail the job with an error code.
- Results and job events are organization-scoped. `POST /malware/quarantine`
  records a permission-controlled quarantine request; host mutation is not
  performed implicitly by the API.

Example local configuration:

```dotenv
MALWARE_SCANNER_COMMAND=C:\Program Files\ClamAV\clamscan.exe
OPERATIONAL_CONNECTOR_ALLOWED_ROOTS=.\storage\uploads;.\storage\evidence-vault
```

This is static file scanning, not a behavioral sandbox. Ransomware behavior is
detected separately by the canary/file-monitor and pre-encryption pipeline.
Command and memory forensics are separate operational connectors.

## Offline requirements

Before starting, ensure:

1. PostgreSQL is running locally and the backend `.env` points to it.
2. `backend-go\.env` and `ai-engine\.env` exist.
3. The database migrations/seeds have been applied.
4. Frontend dependencies are installed with `npm install` in
   `frontend-react`.
5. The AI engine virtual environment exists if `-SkipAI` is not used.

No `cloudflared` process is required for this mode.
