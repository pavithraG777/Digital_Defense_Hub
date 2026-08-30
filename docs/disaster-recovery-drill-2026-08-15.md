# Disaster Recovery Drill — 2026-08-15

- Source database: local development database (name intentionally omitted)
- PostgreSQL server: 18.4
- Backup format: PostgreSQL custom archive (`pg_dump -Fc`)
- Backup size: 1,133,072 bytes
- SHA-256 sidecar: created and verified before restore
- Restore target: uniquely named temporary validation database
- Public tables in source: 155
- Public tables after restore: 155
- Total source rows checked: 4,205
- Tables with row-count mismatch: 0
- Restore result: successful
- Cleanup: temporary validation database removed after verification

The backup archive remains under ignored runtime storage at
`storage/dr-backups/`. It is not committed because it may contain sensitive
application data.
