# Digital Defense Hub

This repository contains multiple components for the Digital Defense Hub project.

## Frontend
The frontend application is located in `frontend-react`.

To install dependencies and start the frontend from the repository root:

```powershell
cd E:\Cyber-Security-Platform
npm install
npm run dev
```

Alternatively, run the commands directly inside the frontend folder:

```powershell
cd E:\Cyber-Security-Platform\frontend-react
npm install
npm run dev
```

## Notes
- There is no root-level Node application in this repository.
- `npm run frontend:dev` forwards to `frontend-react` so you can start the frontend from the root.
- If the backend is not running or credentials are unavailable, use the login screen's "Continue in demo mode" button to view the dashboard UI with sample organization data.

## Temporary free deployment

The frontend and API deploy separately. Training datasets, Google Drive archives, local `.env` files, uploads, and trained artifacts must not be committed to GitHub.

1. Deploy `backend-go` as a Go web service on Render. Configure the production environment variables from `backend-go/.env.example` in the Render dashboard. Render supplies `PORT`; the API supports it when `APP_PORT` is not configured.
2. Deploy `frontend-react` on Vercel. Set `VITE_API_BASE_URL` to `https://<your-render-api>.onrender.com/api/v1`, then redeploy the frontend.
3. Set the API CORS allow-list to the deployed Vercel origin before accepting real users.

`frontend-react/.env.production.example` is a safe reference only. Never commit the real `.env.production` or any secret.

## DFIR roadmap
- A defensive DFIR architecture blueprint is documented in [docs/dfir-attribution-module.md](docs/dfir-attribution-module.md).
- The first implementation slice should focus on evidence intake, ransomware behavior scoring, timeline reconstruction, and investigation reporting.
