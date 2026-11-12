# Run Digital Defense Hub locally and on a phone

## First-time setup

```powershell
winget install --id Cloudflare.cloudflared
Set-Location E:\Cyber-Security-Platform\frontend-react
npm install
Set-Location E:\Cyber-Security-Platform\ai-engine
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Ensure `backend-go\.env` and `ai-engine\.env` are configured and PostgreSQL is running.

## One-command temporary public link

```powershell
Set-Location E:\Cyber-Security-Platform
powershell -ExecutionPolicy Bypass -File .\scripts\run-cloudflare.ps1
```

Copy the printed `https://...trycloudflare.com` URL and open it on the phone. The laptop, services, internet connection, and tunnel terminal must remain running.

## Manual terminals

Terminal 1 — migrations and backend:

```powershell
Set-Location E:\Cyber-Security-Platform\backend-go
go run .\cmd\migrate --from 45
go run .\cmd\api
```

Terminal 2 — AI engine:

```powershell
Set-Location E:\Cyber-Security-Platform\ai-engine
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8091
```

Terminal 3 — frontend:

```powershell
Set-Location E:\Cyber-Security-Platform\frontend-react
npm run dev -- --host 127.0.0.1
```

Terminal 4 — temporary Cloudflare tunnel:

```powershell
cloudflared tunnel --url http://127.0.0.1:5173
```

Only the frontend is tunneled. Vite proxies `/api/v1` to the local backend; the backend communicates with the AI engine locally. Do not expose PostgreSQL or the AI port publicly.
