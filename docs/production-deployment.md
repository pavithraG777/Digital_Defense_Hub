# Production hardening and deployment

The API now emits no-store, anti-framing, MIME-sniffing, referrer, permissions, and strict CSP headers. Deploy it behind a TLS-terminating reverse proxy; apply HSTS there only after the public hostname and HTTPS redirect are verified.

Before production release:

1. Set `APP_ENV=production`, use a unique 32+ character JWT secret, and use a 32-byte Base64 `KEY_ENCRYPTION_MASTER_KEY`.
2. Set `DB_SSLMODE=require` (or stronger), use a dedicated least-privileged database user, and back up/restore-test PostgreSQL.
3. Keep `.env`, alert logs, model artifacts, and uploads out of source control. Mount these as restricted persistent volumes.
4. Restrict CORS to the deployed frontend origin; the current localhost origins are development-only.
5. Terminate TLS at a reverse proxy, enforce request-size limits there, enable access logs, and configure health probes for `GET /api/v1/health`.
6. Run the API and AI engine as separate non-administrator service accounts. Do not expose the AI engine directly to the internet.
7. Use staged releases, database migration backups, monitoring, alert-delivery checks, and a rollback procedure.

The Windows endpoint features in this project should run as a standard-user scheduled task unless a separately reviewed WDAC/minifilter deployment requires administrator rights.
