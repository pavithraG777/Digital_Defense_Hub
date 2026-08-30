# Command Sandbox Integration — 2026-08-15

- Docker Desktop: 4.86.0
- Docker Engine: 29.7.2
- Test image: `alpine:3.20`
- Runner authentication: passed
- Artifact SHA-256 verification: passed
- Execution mode: `DOCKER_ISOLATED`
- Isolation profile: `NO_NETWORK_EPHEMERAL_READONLY`
- Container exit code: 0
- Timeout: false
- Evidence artifact mount read-only: confirmed
- Ephemeral `/tmp` write: confirmed
- Outbound network disabled: confirmed
- Temporary service and container cleanup: required after test

The integration test also found and fixed a worker/runner contract mismatch for
`job_id`, `organization_id`, and resource `limits` fields.
