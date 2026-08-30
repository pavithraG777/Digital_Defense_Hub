# Digital Defense Hub — implementation status

This is an evidence-based status report from the current repository, not a
marketing feature list. A capability is labelled **partial** when its data
contract exists but validated source data, a model, or an external provider is
still required.

## Available now

| Area | Status | What is implemented |
| --- | --- | --- |
| Kernel sandbox isolation | Available | Windows isolation-readiness inspection and endpoint network-isolation/restore scripts. |
| Canary and honeytoken | Available | Protected-file, honeytoken, canary, file-event, threat, rotation, fingerprint, local Sentinel, evidence bundle, FIR-draft and offline briefing workflows. |
| Secure evidence intake | Available | Type/signature validation, encrypted-at-rest storage, SHA-256 + SHA-512, content fingerprint, duplicate detection, evidence-package metadata, quarantine and immutable custody events. |
| Deepfake forensic suite | Available / partial | Media intake, image/video/audio/document routing, deepfake, forensic and OCR jobs, frame/temporal evidence, localization, XAI data contract and reports. Accuracy depends on the approved local model. |
| Metadata / video / OCR | Available / partial | Extracted metadata, consistency signals, video frames/temporal findings and OCR results. PRNU/CFA requires camera references. |
| Audio, face, multimodal | Partial | Audio and media routing exist; cross-modal fusion, voice biometrics and face identity correlation require consented reference evidence and approved models. |
| Confidence and explainability | Available | Trust assessment, confidence matrix, detector evidence and human-review flags. |
| Deepfake–ransomware correlation | Partial | Media trust escalation can create incidents; correlation with canary/threat history needs case-level fusion. |
| Governance | Available / partial | Model versioning, approval, rollback, organization assignment, dataset/training jobs, forensic-report approval, organization media policy and investigation cases. |
| Model Security | Available | Tenant-scoped SHA-256 integrity comparison, artifact attestation and validation gates, explainable risk findings, blocked/verified decisions, durable verification history, and posture summary APIs. |

## Capabilities completed at the application-backend boundary

The backend now provides tenant-scoped persisted workflows for adaptive login
risk and device trust, endpoint telemetry and containment, network-flow
analytics and quarantine, credential-abuse risk, privilege-escalation review,
lateral-movement graphing, evidence preservation/custody/legal-hold lifecycle,
attack stories, incident ingestion/training, offline synchronization state
transitions, intelligence read models, and multi-source threat-indicator
enrichment. Endpoint agents, network sensors, and external intelligence feeds
remain deployment integrations rather than hard-coded product claims.

## Capabilities that remain partial

The following areas must not be represented as fully complete until their
production integrations and end-to-end validation are implemented: Autonomous
Response orchestration, Executive Dashboard, and Frontend UX. Advanced
forensics remains model/tool dependent even though its backend case, evidence,
analysis, result, and reporting workflow is implemented.

## MFA implementation boundary

`users.mfa_enabled` is already stored, but login currently issues tokens after
password verification. A real email + phone MFA rollout must add:

1. a hashed, single-use challenge table with expiry, attempts and rate limits;
2. a phone-contact ownership model and an approved SMS provider;
3. SMTP/SMS delivery adapters, without returning OTPs from production APIs;
4. `/auth/login` returning a short-lived `mfa_challenge_id` instead of tokens
   when MFA is enabled; and `/auth/mfa/verify` issuing tokens only after both
   required factors are verified;
5. recovery codes, audit events and session `mfa_verified=true` updates.

The repository has an SMTP notification provider, but no verified user phone
number source or SMS provider. These must be configured before phone MFA can
be honestly enabled.

## Research / innovation modules: start order

1. **Offline Cyber Intelligence Mesh (OCIM):** signed offline threat-package
   import, provenance manifest, version pinning and tenant-scoped rule use.
2. **National Threat DNA Engine:** privacy-preserving indicators and evidence
   fingerprints; never cross-tenant raw evidence sharing.
3. **AI Contradiction Engine:** compare metadata, OCR, model results and human
   assertions; return conflicts, not a fabricated conclusion.
4. **Cross-incident / investigation memory:** case-scoped correlation over
   hashes, approved embeddings and incident indicators.
5. **Replay / story / simulation:** reproducible event timeline from immutable
   custody, job and analyst-review events.

## API contract convention

All successful endpoints use the shared response envelope and authenticated
routes require `Authorization: Bearer <token>`. `GET` requests normally have
no body; list endpoints accept pagination query parameters. Exact runnable
deepfake, canary, report and case request examples are maintained in
`docs/postman-validation.md`.

### Current API groups

| Prefix | Main operations | Required request body / expected result |
| --- | --- | --- |
| `/health` | `GET` | none → service health status. |
| `/auth` | login, refresh, revoke | `POST /login`: `identifier`, `password` → JWT/refresh token; `POST /refresh`: refresh token → rotated token pair; revoke → invalidated refresh token. |
| `/deepfake-forensics/media-assets` | upload, list, inspect, analyze, quarantine/release, trust, reports | upload is multipart `file` plus optional `department_id`, `incident_id`, `metadata`; analysis body selects modes/priority/device → job records; report approval requires an approval note. |
| `/deepfake-forensics/analysis-jobs` | list, inspect, result, cancel, retry | IDs in path; retry/cancel have no body → durable job state. |
| `/deepfake-forensics/organization-policy` | get/update policy | policy body: allowed media types, upload limit, review threshold, suspicious-review policy, retention days → tenant policy. |
| `/deepfake-forensics/models` | list, upload, version, activate, rollback, assign | multipart model upload or JSON assignment/version metadata → governed model state. |
| `/deepfake-forensics/training` | datasets, versions, validation, jobs, approval | dataset/job JSON → registered, validated, approved or cancelled training job. |
| `/canary-files`, `/honeytokens`, `/protected-files` | create, deploy, list, retrieve | JSON configuration/deployment body → organization-scoped decoy/protected-file record. |
| `/file-events`, `/threats`, `/incidents` | record/list events; manage threats/incidents | event or update JSON → immutable event / updated workflow state. |
| `/investigation-cases` | create, list, retrieve, update, link incidents | title/description/priority or incident ID → isolated case workspace. |
| `/notifications` | create/list/read/acknowledge | notification JSON or state patch → delivery/audit state. |
| `/pre-encryption-detections`, `/ai-risk-scores` | list/get/resolve risk signals | no body for reads; resolution/update JSON → reviewed risk state. |
| `/model-security` | integrity summary; list/get/create verifications | expected and observed SHA-256, model identity/version, validation outcome and attestation evidence → durable `VERIFIED` or `BLOCKED` deployment-gate decision. |

For a complete endpoint-by-endpoint route list, the authoritative route files
are `backend-go/internal/router/router.go`, `backend-go/internal/HoneyToken/*routes.go`,
`backend-go/internal/deepfakeforensics/routes.go`,
`backend-go/internal/notification/routes.go`, `backend-go/internal/airisk/routes.go`,
and `backend-go/internal/preencryption/routes.go`.
