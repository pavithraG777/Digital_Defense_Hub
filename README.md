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

## DFIR roadmap
- A defensive DFIR architecture blueprint is documented in [docs/dfir-attribution-module.md](docs/dfir-attribution-module.md).
- The first implementation slice should focus on evidence intake, ransomware behavior scoring, timeline reconstruction, and investigation reporting.
