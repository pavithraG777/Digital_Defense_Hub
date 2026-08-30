# Local MinIO Foundation — 2026-08-15

- MinIO API: `http://127.0.0.1:9000`
- MinIO Console: `http://127.0.0.1:9001`
- Server image: `minio/minio:RELEASE.2025-09-07T16-13-09Z`
- Persistent Docker volume: enabled
- Public network exposure: disabled; ports bind to loopback only
- Credentials: generated in ignored `backend-go/.env`
- Deepfake bucket: `deepfake-media`
- Deepfake bucket versioning: enabled
- Evidence bucket: `security-evidence`
- Evidence bucket versioning: enabled
- Evidence Object Lock: enabled
- Default evidence retention: `GOVERNANCE`, 30 days
- Health endpoint: HTTP 200
- Object upload/stat/download/delete round-trip: passed
- Returned object VersionID: verified

Existing deepfake media remains in managed local filesystem storage. This
foundation does not migrate or delete current files; application dual-mode
storage wiring is the next phase.
