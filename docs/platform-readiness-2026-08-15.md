# Platform Readiness — 2026-08-15

## Local operational

- Event identity, versioning, idempotency, replay and late-event handling
- Transactional outbox, retry, DLQ and poison-event handling
- Tenant isolation and centralized HTTP audit coverage
- Entity graph, correlation, baselines and behavior detections
- Explainable/versioned detections and versioned attack stories
- Static command analysis
- Offline threat-intelligence provider with provenance and expiry
- Recovery approval, dry-run, simulation, rollback and verification workflow
- Evidence hashing, AES-256-GCM encryption and Ed25519 signatures
- Local retention enforcement, custody-chain and integrity verification
- Development secret generation and decrypt-only retired key ring
- PostgreSQL backup, checksum, isolated restore and row verification drill
- Backend tests, vet, runtime security smoke and bounded load smoke
- Official Go vulnerability scan: zero reachable vulnerabilities

## Implemented but runtime prerequisite required

- Dynamic command sandbox service is implemented, but Docker is not installed
  on the audited machine. No host command fallback is allowed.
- The safe recovery runner is implemented as a separate process. The college
  build simulates allowlisted actions and deliberately does not mutate real
  endpoint, credential or network state.

## Optional production/external validation

- Hardware/cloud WORM storage such as S3 Object Lock, Azure immutable Blob or
  MinIO Object Lock
- KMS/HSM-backed encryption and signing keys
- Commercial/live threat-intelligence feeds
- Real endpoint recovery agents
- External penetration testing and full DAST
- Go race detector on a host with CGO and GCC/Clang

## Deferred by project decision

- Deepfake media migration from managed local filesystem to MinIO/object
  storage. PostgreSQL continues to store metadata and analysis results.

This report distinguishes college/offline operational readiness from
enterprise production certification.
