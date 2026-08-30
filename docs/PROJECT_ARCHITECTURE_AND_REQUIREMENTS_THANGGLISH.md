# Cyber Security Platform — Full Architecture & Requirements (Thanglish)

## 1. Project enna?

Idhu multi-tenant **Digital Defense Hub / Cyber Security Platform**. Endpoint telemetry, honey-token ransomware signals, authentication risk, network/IOC events, incidents, deepfake/media forensics, evidence custody, attack correlation, recovery orchestration ellathayum oru platform-la collect, analyse, investigate, respond panna design pannirukkom.

Main runtime flow:

`React UI -> Go REST API -> auth/RBAC/tenant middleware -> domain service/repository -> PostgreSQL`

AI flow:

`Go backend -> authenticated HTTP -> Python FastAPI AI engine -> feature extraction/model runner -> signed/persisted result`

Async security flow:

`Normalized event -> transactional outbox -> worker/retry/DLQ -> entity graph -> correlation/baseline/detection -> attack story/incident -> approved recovery`

## 2. Top-level folders

| Folder | Responsibility | Main connection |
|---|---|---|
| `backend-go/` | Primary REST API, security engines, persistence, workers | PostgreSQL, Python AI engine, isolated external runners |
| `ai-engine/` | FastAPI scoring, deepfake/media analysis, training, DFIR ML | Called by Go backend through service token |
| `frontend-react/` | React/Vite operator console | Calls `/api/v1` APIs and maintains auth navigation |
| `scripts/migrations/seed/` | Ordered PostgreSQL schema and controlled seed scripts | Applied by Go/PowerShell migrator |
| `scripts/` | Deployment, backup/restore, endpoint isolation, readiness automation | Operators, OS, PostgreSQL |
| `docs/` | Architecture, deployment, operational runbooks | Developers/SOC/admin teams |
| `datasets/` | Labeled media training/test samples | AI training pipeline |
| `.github/workflows/` | CI integration and security gates | GitHub PR/push -> tests/vet/race/vulnerability scan |

## 3. Backend architectural layers

Typical full module file responsibilities:

- `routes.go`: URL + HTTP method + permission middleware mapping.
- `handler.go`: request decode/validation, tenant/user context, response mapping.
- `dto.go`: request/response contracts.
- `model.go` / `domain.go`: domain states and entities.
- `service.go`: business rules and workflow transitions.
- `repository.go`: tenant-scoped PostgreSQL queries/transactions.
- `worker.go`: asynchronous queue claim, retry, stale-job recovery.
- `constants.go`: allowlists, statuses, event types.
- `*_test.go`: unit/contract/regression tests.
- `module.go`: small modules-la facade + routes + implementation ஒரே file-la இருக்கலாம்.

Connection rule:

`router.go -> RegisterRoutes -> middleware -> handler -> service -> repository -> database`

Worker rule:

`main.go -> Start(context) -> atomic DB claim/FOR UPDATE SKIP LOCKED -> external/internal processing -> result/audit`

## 4. Core platform modules

### Authentication, identity, access

- `auth`: login, password lifecycle, refresh/session handling, MFA OTP/TOTP, recovery codes, trusted devices and risk signals.
- `middleware`: JWT authentication, tenant context, permission checks, session checks, request ID, CORS and security headers.
- `permission`, `role`, `rolepermission`, `userrole`: RBAC definitions and mappings.
- `user`, `organization`: tenant/user administration and onboarding history.
- `accesscontrol`: consolidated access-control API workspace.

Techniques: bcrypt password hashing, JWT validation, refresh-token rotation, MFA challenge expiry, TOTP, recovery-code hashing, tenant isolation, least privilege, password-change enforcement, device trust.

### HoneyToken and ransomware protection

- `HoneyToken`: canary generation/deployment, protected-file encryption/restoration, trigger collection, incident cases, owner recovery and file integrity.
- `preencryption`: early ransomware behavior signals before large-scale encryption.
- `adaptivedeception`: canary health, fingerprinting, rotation and tamper monitoring.
- `ransomware`: ransomware-focused API facade.

Techniques: deception defense, canary tokens, atomic file operations, AES/key wrapping where configured, hashes, health schedules, rollback-safe rotation, early-warning heuristics.

### AI risk and digital-media forensics

- `airisk`: Go client/service/repository for AI risk scoring.
- `deepfakeforensics`: upload security, analysis jobs, engine client, model deployments, policies, reports, evidence packages, training pipeline and workers.
- `dfir`: forensic feature extraction, deterministic detectors, ML proxy, evidence/report/correlation services.
- `forensics`, `memoryforensics`, `imageanalysis`, `audio`, `face`, `document`, `metadata`: analysis workspaces/facades.

Techniques: asynchronous analysis, SHA-256 asset identity, MIME/size validation, isolated storage path, model versioning, ONNX inference, explainable feature mapping, retry workers, signed forensic evidence.

### Security event foundation

- `securityevents`: normalized versioned events, event identity, idempotency, late/out-of-order handling, replay, transactional outbox, worker retry, DLQ and poison-event handling.
- `securitygraph`: entity-relationship graph API.
- `syncqueue`: offline operation synchronization state.
- `integration`: integration status/facade.

Techniques: UUID identity, schema versions, canonical hashes, unique constraints, transactional outbox, `FOR UPDATE SKIP LOCKED`, bounded retries, DLQ, replay checkpoints.

### Correlation, anomaly and story engines

- `threatcorrelation`: event/entity correlation and versioned rules.
- `baseline`: normal behavior aggregates and anomaly deviation scoring.
- `behavior`: behavior-analysis API facade.
- `attackstory`: versioned attack-story construction and timelines.
- `incidentengine`: incident engine status/operations.

Connection:

`security_events -> security_event_entities -> entity_links -> correlations -> behavior detections -> story versions -> incidents`

Techniques: entity graph, sliding time windows, weighted scoring, baseline statistics, explainable evidence arrays, rule/model versions, immutable story revisions.

### Detection modules

- `credentialabuse`: honey credentials, abnormal failures/success and credential-use findings.
- `privilegeescalation`: suspicious privilege transition/elevation findings.
- `lateralmovement`: source device -> account -> destination device movement paths.
- `commandanalysis`: static PowerShell/CMD/script rules, encoded command decoding, IOC extraction, isolated sandbox queue.
- `endpoint`: endpoint posture/protection events.
- `networksecurity`: network flow/analytics findings.
- `malware`, `persistence`, `dataexfiltration`, `insiderthreat`, `ueba`, `dlp`, `usb`, `vulnerability`, `attacksurface`: specialist detection/workspace APIs.

Techniques: deterministic rules, weighted risk scoring, MITRE-style behavioral patterns, graph paths, explainability, allowlists, sandbox isolation contract, tenant-scoped findings.

### Threat intelligence and attribution

- `threatintel`: manual multi-source IOC scoring plus external provider enrichment queue/worker.
- `intelligence`: intelligence dashboard/mesh facade.
- `attribution`: provider-neutral observations, IOC/ASN/Geo/association investigative leads, provenance, confidence, conflicts and analyst disposition.
- `threathunting`, `threatanalysis`: analyst workflows.

Techniques: IOC normalization, provenance/source reference, freshness/expiry, confidence bounds, conflict penalties, historical tenant evidence, analyst disposition. Attribution output investigative lead மட்டும்; actor identity confirmation அல்ல.

### Evidence Vault

- `evidencevault/module.go`: evidence API route wiring.
- `repository.go`: tenant evidence and custody persistence.
- `manifest.go`: canonical manifest hashing and Ed25519 operations.
- `crypto_api.go`: sign/verify/export verification endpoints and keyring loading.
- `operations.go`: WORM attestation, destruction certificate, integrity health/worker.
- tests: signature, hash-chain and API contracts.

Techniques: SHA-256, encryption metadata, Ed25519 digital signatures, verification-key rotation, immutable/WORM attestation, custody hash chain, export verification, scheduled integrity checks.

### Recovery and resilience

- `recovery/module.go`: plan/dry-run/approval/execute/verify/rollback/emergency-stop APIs.
- `recovery/worker.go`: controlled external runner dispatch, retry and result persistence.
- `recovery/module_test.go`: action allowlist tests.

Techniques: state machine, idempotency, two-person approval, dry-run, action allowlist, external runner isolation, rollback, verification, emergency stop, audit trail.

### Incident/SOC lifecycle modules

`incidentmanagement`, `incidenttriage`, `incidentescalation`, `incidentorchestration`, `incidentremediation`, `incidentresolution`, `incidentclosure`, `incidentreview`, `incidentafteraction`, `incidentlearning`, `incidentreporting`, `incidentanalytics`, `incidentresponse` ஆகியவை SOC lifecycle workspaces/APIs. சில modules compact façade/stub maturity-ல் இருக்கின்றன; core correlation/recovery engine போல எல்லாமே full persistence workflow என்று assume செய்யக்கூடாது.

### Notification and operations

- `notification`: email/SMS/local desktop providers, outbox, templates, retry workers and MFA delivery adapters.
- `health`: liveness, DB readiness and bearer-protected Prometheus metrics.
- `logger`: structured Zap logging.
- `config`: `.env`/Viper configuration validation.
- `database`: UTC PostgreSQL pool configuration.
- `response`: consistent API envelope.

## 5. Python AI engine

- `app/main.py`: FastAPI entrypoint and route registration.
- `config.py`, `security.py`: runtime configuration and service authentication.
- `schemas.py`, `scoring.py`: base risk request/result contracts and scoring.
- `pre_encryption_*`: pre-encryption schema and deterministic scoring.
- `media_forensics_routes.py`: multimodal API routes.
- `media_analysis_service.py`: analysis orchestration.
- `media_forensics_runtime.py`, `media_forensics_probe.py`: runtime/provider capability probing.
- `media_image_*`, `media_video_*`, `media_audio_*`, `media_ocr_analyzer.py`: modality-specific features/analyzers.
- `media_model_runner.py`: model selection/inference execution.
- `training_routes.py`, `training_schemas.py`, `image_training_service.py`: controlled training jobs and artifacts.
- `advanced_forensics.py`, `dfir_ml/`: advanced forensic/ML service.
- `models/`: ONNX/OpenCV inference assets.
- `tests/`: scoring/API/training/forensic regression tests.

## 6. React frontend

- `main.tsx`: React bootstrap.
- `App.tsx`: application routes/session shell.
- `Layout.tsx`: common navigation/layout.
- `api.ts`: Go API request/auth client.
- `auth-navigation.ts`: auth/MFA/password state navigation decisions.
- `modules.ts`: security module catalogue/workspace mapping.
- `records.ts`: client-side response/record helpers.
- Pages: login, MFA, recovery/reset, password change, dashboard, module list and generic module workspace.
- `styles.css`: platform visual design/responsive rules.
- Vite/TypeScript configs: build/type-check configuration.

## 7. Database migrations

- `001–013`: file events, threats, incidents, notifications, AI risk, pre-encryption, deception, media forensics, reports and training foundation.
- `014–021`: artifacts, investigation cases, media policies, MFA, offline sync, intelligence mesh, onboarding and DDH support tables.
- `022`: model-security verification.
- `023`: partial workflow completion schemas.
- `024`: normalized security-event foundation/outbox/DLQ/entities.
- `025`: versioned correlation/entity graph.
- `026`: baseline, behavior detections and attack-story versions.
- `027`: command sandbox jobs.
- `028`: evidence crypto manifests/integrity/WORM/custody.
- `029`: attribution observations/leads.
- `030`: recovery/resilience engine.
- `031`: external threat-intelligence provider jobs/provenance.
- `01–14_seed_*`: reference/initial data. `999_seed_test_user.sql` development-only; production migrator default exclude pannum.

## 8. Functional software requirements used

- FR-Identity: login, MFA, trusted device, session and password lifecycle.
- FR-Tenant: every sensitive record/API organization context-la isolate aaganum.
- FR-Ingestion: endpoint/network/file/auth/IOC events normalized-aa ingest aaganum.
- FR-Detection: credential, privilege, lateral, command, ransomware and anomaly findings generate aaganum.
- FR-Correlation: user/device/process/file/network/IOC/incident relationships correlate aaganum.
- FR-Investigation: story, evidence, attribution, forensics and analyst disposition available aaganum.
- FR-Response: approved dry-run/execute/verify/rollback/emergency-stop lifecycle.
- FR-Offline: disconnected queue and later synchronization.
- FR-Administration: organizations, users, roles, permissions, policies and models manage panna mudiyanum.
- FR-Observability: health/readiness/metrics/audit visibility.

## 9. Non-functional requirements used

- Security: least privilege, tenant isolation, hashing/signatures, secret separation, fail-closed config.
- Reliability: idempotency, retry, DLQ, stale-job reclaim, transactional updates, rollback.
- Integrity: canonical hashes, immutable evidence metadata, checksum-locked migrations.
- Performance: PostgreSQL pool, indexes, async workers, bounded queries/limits.
- Scalability: stateless API, worker queues, external adapters, tenant partition keys.
- Auditability: request IDs, actor/tenant attribution, lifecycle audit events, explainable scores.
- Maintainability: modular packages, DTO/service/repository layering, migrations, tests, CI.
- Portability: Go/Python/React, environment configuration, container-ready external services.
- Recoverability: verified backups, checksum restore, recovery plan state machine.

## 10. Engineering techniques/patterns

- Clean-ish layered architecture: Handler -> Service -> Repository.
- Modular monolith backend with external AI/sandbox/recovery adapters.
- Dependency injection through constructors/router wiring.
- REST APIs with consistent envelopes and validation.
- RBAC middleware and multi-tenancy.
- Transactional outbox and eventual consistency.
- Worker queue with atomic claims and bounded retries.
- Idempotency keys and unique database constraints.
- State machines for incident/recovery/training workflows.
- Strategy/adapter pattern for notification, AI and intelligence providers.
- Cryptographic integrity: SHA-256 + Ed25519.
- Versioning: events, rules/models, attack stories and manifests.
- Explainable scoring rather than opaque risk output alone.
- CI gates: test, vet, race detector, vulnerability scan, migration validation, secret detection.
- Observability: structured logs, request IDs, health/readiness and Prometheus metrics.

## 11. External dependencies needed for full operations

- PostgreSQL.
- Isolated command sandbox service: `COMMAND_SANDBOX_URL/TOKEN`.
- Controlled recovery runner: `RECOVERY_RUNNER_URL/TOKEN`.
- Threat-intelligence provider adapter: `THREAT_INTEL_PROVIDER_URL/TOKEN`.
- Production KMS/HSM/object-lock storage for evidence keys/WORM guarantee.
- Email/SMS providers where enabled.
- Python AI engine/model runtime.
- Prometheus-compatible collector using `METRICS_BEARER_TOKEN`.

Code adapters/queues exist pannalum external service deploy/configure pannama அந்த workflows operational-aa execute aagathu.

## 12. Complete per-file reference

Every inventoried file-oda purpose and connection separate generated appendix-la irukku: [PROJECT_FILE_INVENTORY_THANGGLISH.md](./PROJECT_FILE_INVENTORY_THANGGLISH.md).

Inventory regenerate command:

```powershell
.\scripts\generate-project-file-inventory.ps1
```
