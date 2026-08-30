# Enterprise Digital Media Forensics Platform Architecture

## Overview

This document expands the existing Deepfake & Synthetic Media Forensics module into a comprehensive Enterprise Digital Media Forensics Platform.

The platform is split into two main runtime layers:

- `backend-go`: enterprise API, orchestration, DDD domain services, async job orchestration, persistence, evidence storage, workflow management.
- `ai-engine`: Python AI engine for multimodal forensic analysis, model inference, explainability, and report generation.

The platform will remain modular, domain-driven, and extensible for new forensic modalities.

---

## Core Goals

- Provide enterprise-grade media analysis workflows for image, video, audio, document, face, surveillance, email, cloud/mobile, and metadata integrity.
- Keep a clear DDD separation: API/HTTP handlers → application services → domain logic → repositories.
- Support asynchronous analysis with durable job state, retry, and evidence packages.
- Store evidence and explainability metadata in PostgreSQL and secure file storage.
- Expose enterprise APIs for upload, analysis, trust assessment, reports, and investigations.
- Integrate Python AI engine via HTTP/gRPC for model-based detection with confidence, reasoning, and supporting evidence.

---

## Proposed Backend Package Structure

`backend-go/internal/deepfakeforensics`

- `handler.go` — entrypoint HTTP handler orchestration.
- `routes.go` — Gin route registration.
- `dto.go` — API request/response payload definitions.
- `repository.go` — domain repository interface and implementation.
- `service.go` — core application services.
- `query_service.go` — read/query logic for asset, job, report, and timeline views.
- `analysis_service.go` — analysis orchestration and job creation.
- `job_repository.go` — analysis job persistence.
- `worker.go` — analysis worker scheduling and dispatch.
- `engine_client.go` — Python engine client.
- `forensic_report.go` — report generation and approval.
- `trust_service.go` — risk/trust assessment and escalation.
- `model_management.go` — managed model versioning.
- `asset_service.go` — secure media intake and evidence asset management.
- `asset_file_manager.go` — encrypted storage and quarantine handling.
- `evidence_package.go` — chain-of-custody evidence packaging.
- `policy.go` / `policy_handler.go` — organization upload and analysis policy enforcement.
- `constants.go` — shared status, risk, and domain constants.
- `advanced_handler.go` — advanced analysis endpoints.
- `training_*` — model training orchestration and lifecycle.
- `trust_*` — trust scoring and escalation.

### New Domain Subpackages

These can remain in the same package or eventually be split further into subpackages under `deepfakeforensics`.

- `document` — document forensics domain logic.
- `face` — face and identity forensics.
- `image` — image forensics.
- `video` — video forensics.
- `audio` — audio forensics.
- `surveillance` — CCTV and surveillance intelligence.
- `metadata` — metadata & file integrity forensics.
- `synthetic` — synthetic media detection.
- `email` — email & phishing forensics.
- `mobile` / `cloud` — cloud/mobile forensic evidence and timeline.

Each subdomain should define:
- Domain entities and value objects.
- Analysis job types.
- Repository methods and result models.
- Service methods for analysis, query, and reporting.
- Handler endpoints where needed.

---

## Backend API Surface

`/api/v1/deepfake-forensics`

### Asset Management

- `POST /media-assets` — upload media evidence.
- `GET /media-assets` — list assets.
- `GET /media-assets/:media_asset_id` — get asset details.
- `GET /media-assets/:media_asset_id/security-events` — asset event trail.
- `GET /media-assets/:media_asset_id/trust-assessment` — trust score and risk.
- `POST /media-assets/:media_asset_id/analyze` — request analysis.
- `POST /media-assets/:media_asset_id/quarantine` — quarantine suspicious asset.
- `POST /media-assets/:media_asset_id/release` — release quarantined asset.

### Analysis Jobs

- `GET /analysis-jobs` — list analysis jobs.
- `GET /analysis-jobs/:analysis_job_id` — get job details.
- `GET /analysis-jobs/:analysis_job_id/result` — get analysis results.
- `POST /analysis-jobs/:analysis_job_id/cancel` — cancel a job.
- `POST /analysis-jobs/:analysis_job_id/retry` — retry a job.

### Forensic Reports

- `GET /forensic-reports/:report_id` — retrieve report.
- `POST /forensic-reports/:report_id/approve` — approve report.
- `GET /forensic-reports/:report_id/download` — download evidence package.
- `POST /media-assets/:media_asset_id/forensic-reports` — create report from asset or results.

### Model & Policy Management

- `GET /models` — list managed models.
- `GET /models/:model_id` — get model.
- `POST /models` — register model.
- `POST /models/:model_id/assignments` — assign to organization.
- `GET /policy` — view organization policy.
- `PUT /policy` — update organization media policy.

### Extended Forensics Endpoints

- `POST /documents/analyze` — document-specific analysis.
- `POST /faces/analyze` — face/identity analysis.
- `POST /surveillance/track` — surveillance intelligence analysis.
- `POST /email/analyze` — email/phishing analysis.
- `POST /cloud/analyze` — cloud/mobile forensic analysis.

These can be grouped under `/deepfake-forensics` or new subroutes such as `/forensics/document`, `/forensics/face`, etc.

---

## Proposed Domain Model and Job Types

### Document Forensics

- `DocumentForgedDetectionJob`
- `DigitalSignatureVerificationJob`
- `DocumentOCRValidationJob`
- `DocumentTamperDetectionJob`
- `DocumentMetadataAnalysisJob`
- `DocumentHistoryExtractionJob`

### Face & Identity Forensics

- `FaceSwapDetectionJob`
- `FaceMorphingDetectionJob`
- `FaceReenactmentDetectionJob`
- `FaceLivenessDetectionJob`
- `IdentityVerificationJob`
- `FacialLandmarkConsistencyJob`

### Image Forensics

- `CopyMoveForgeryDetectionJob`
- `ImageSplicingDetectionJob`
- `AIImageGenerationDetectionJob`
- `InpaintingDetectionJob`
- `ErrorLevelAnalysisJob`
- `JPEGCompressionAnalysisJob`
- `PRNUNoiseAnalysisJob`
- `ImageMetadataTamperingJob`

### Video Forensics

- `FrameTamperingDetectionJob`
- `FrameDuplicationDetectionJob`
- `FrameDeletionDetectionJob`
- `FrameInterpolationDetectionJob`
- `MotionConsistencyAnalysisJob`
- `CompressionArtifactAnalysisJob`
- `CodecAnalysisJob`
- `AI-VideoGenerationDetectionJob`

### Audio Forensics

- `VoiceCloningDetectionJob`
- `SpeakerVerificationJob`
- `SpeakerIdentificationJob`
- `AudioSplicingDetectionJob`
- `NoiseConsistencyAnalysisJob`
- `VoiceConversionDetectionJob`
- `SyntheticSpeechDetectionJob`

### CCTV & Surveillance Intelligence

- `PersonTrackingJob`
- `MultiCameraTrackingJob`
- `ObjectDetectionJob`
- `VehicleDetectionJob`
- `ALPRJob`
- `IntrusionDetectionJob`
- `LoiteringDetectionJob`
- `CrowdAnalysisJob`

### Metadata & File Integrity

- `EXIFAnalysisJob`
- `GPSValidationJob`
- `TimestampVerificationJob`
- `CameraDeviceMetadataJob`
- `FileHashVerificationJob`
- `FileIntegrityVerificationJob`
- `ChainOfCustodyJob`

### Synthetic Media Detection

- `SyntheticImageDetectionJob`
- `SyntheticVideoDetectionJob`
- `SyntheticAudioDetectionJob`
- `SyntheticDocumentDetectionJob`
- `AIAvatarDetectionJob`

### Email & Phishing Forensics

- `EmailHeaderAnalysisJob`
- `SenderAuthenticationJob`
- `AttachmentAnalysisJob`
- `EmbeddedURLAnalysisJob`
- `PhishingDetectionJob`
- `EmailTimelineReconstructionJob`

### Cloud & Mobile Forensics

- `CloudFileActivityAnalysisJob`
- `VersionHistoryAnalysisJob`
- `FileSharingInvestigationJob`
- `MobileMediaAnalysisJob`
- `DeletedMediaRecoveryJob`
- `TimelineReconstructionJob`

---

## Asynchronous Analysis Architecture

### Go Backend

- `AnalysisWorker` polls pending jobs from PostgreSQL.
- Each job contains `JobType`, `Status`, `Priority`, `ExecutionDevice`, `RequestParameters`, `EvidenceIDs`, and `ExplainabilityMetadata`.
- Worker calls `EngineClient` to dispatch analysis to the Python engine.
- Worker marks job state transitions: `QUEUED`, `PROCESSING`, `FAILED`, `COMPLETED`, `RETRYING`.
- Completed jobs store results in `analysis_results`, `analysis_evidence`, and `explainability` tables.
- Jobs can be retried automatically on transient failures.

### Python AI Engine

- Accepts analysis requests from Go via HTTP/gRPC.
- Executes model pipelines for media modalities.
- Returns structured detection output:
  - `confidence_score`
  - `risk_level`
  - `model_id`
  - `reasoning`
  - `supporting_evidence`
  - `timeline`
  - `recommendations`
- Stores or returns artifact references for explainability visualizations.

### Evidence Packages

- Analysis results include a forensic evidence package with:
  - `artifact_id`
  - `original_media_path`
  - `frame_samples`
  - `extracted_text`
  - `metadata_snapshot`
  - `detection_heatmaps`
  - `audit_trail`

- Evidence packages are accessible through backend report download endpoints.

---

## PostgreSQL Schema Additions

Add tables for enhanced forensic domains: `media_assets`, `analysis_jobs`, `analysis_results`, `analysis_evidence`, `media_trust_assessment`, `forensic_reports`, `document_forensics`, `face_forensics`, `surveillance_insights`, `email_forensics`, `cloud_forensics`, and `media_metadata`.

Each result row should include:

- `id`, `organization_id`, `media_asset_id`, `job_type`, `status`, `priority`, `analysis_started_at`, `analysis_completed_at`
- `confidence_score`, `risk_level`, `model_id`, `model_version`
- `explainability`, `supporting_evidence`, `recommendations`
- `failure_reason` and `retry_count`

Add evidence storage references:

- `evidence_package_id`
- `file_hash_md5`, `file_hash_sha1`, `file_hash_sha256`
- `chain_of_custody_step`, `custody_owner`, `custody_timestamp`

---

## Evidence Storage and Security

- Use secure backend-managed storage under `backend-go/storage/media-analysis`.
- Support encrypted file storage and quarantine of malformed or suspicious uploads.
- Use file name hashing and directory partitioning by organization ID.
- Preserve chain-of-custody metadata for all media artifacts.

---

## Explainability & Reporting

Every analysis result must expose:

- `confidence_score`
- `risk_level`
- `detection_model_id`
- `explainable_reasons`
- `supporting_evidence`
- `forensic_timeline`
- `recommended_actions`

Reports include:
- summary findings
- detection rationale
- evidence references
- recommended remediation actions
- chain-of-custody history
- approval status

---

## Integration with Existing Codebase

### Current module usage

The existing `backend-go/internal/deepfakeforensics` package already provides:

- secure media asset intake
- analysis job orchestration
- trust scoring
- reporting and model management
- external engine client

This architecture should extend the same domains by adding subdomain-specific job types and result models rather than replacing the existing module.

### Recommended incremental expansion

1. Add new analysis job type constants and job dispatch mappings in `analysis_service.go`.
2. Extend `dto.go` with richer request payloads for document, face, surveillance, email, and cloud analysis.
3. Add subdomain result mappers and repository queries for model outputs and explainability.
4. Extend `routes.go` with new endpoints for document, face, email, and cloud forensic operations.
5. Add Python engine endpoints and request/response DTOs in `engine_client.go` / `engine_dto.go`.
6. Add migrations for the new schema.
7. Implement evidence packaging and chain-of-custody support in `evidence_package.go`.
8. Improve `forensic_report.go` with new evidence and recommended action generation.

---

## Python AI Engine Architecture

Create a new Python service under `ai-engine/forensics_engine` or `ai-engine/media_forensics_engine`.

Suggested structure:

- `ai-engine/media_forensics_engine/api.py` — Flask/FastAPI endpoint definitions.
- `ai-engine/media_forensics_engine/pipelines/` — per-domain pipelines.
- `ai-engine/media_forensics_engine/models/` — model wrappers and loading.
- `ai-engine/media_forensics_engine/explainability.py` — human-readable reasoning and evidence extraction.
- `ai-engine/media_forensics_engine/schemas.py` — request/response schemas.
- `ai-engine/media_forensics_engine/tasks.py` — orchestration runners.
- `ai-engine/media_forensics_engine/utils.py` — metadata, hash, and file utilities.

The engine should support:
- document forensics pipelines (PDF parse, OCR, signature verification, layout analysis)
- face forensics pipelines (face swap, morph, liveness, landmark consistency)
- image/video/audio pipelines (forgery, compression, PRNU, splicing, cloning)
- surveillance pipelines (tracking, ALPR, intrusion, crowd behavior)
- email/phishing pipelines (header/URL/attachment analysis)
- metadata integrity pipelines (EXIF/GPS/timestamp validation)
- synthetic detection pipelines (LLM/vision/audio generation detection)

---

## Enterprise Workflows

### Typical analysis workflow

1. User uploads media asset.
2. Backend validates policy and stores asset securely.
3. User requests analysis or policy triggers automatic analysis.
4. Backend creates durable jobs and queues them for worker execution.
5. Worker calls Python engine with the job payload.
6. Python engine returns detection outcomes and explainability metadata.
7. Backend persists results, updates trust assessment, and generates report content.
8. User retrieves results, evidence, and recommended actions.
9. Analyst approves or escalates the report.

### Chain of custody workflow

- Capture upload metadata and hashes.
- Track file movements and evidence processing.
- Store custody handoff events in audit trail tables.
- Include integrity verification and timestamps in reports.

---

## Suggested Implementation Roadmap

1. **Architecture design** — formalize package boundaries, routes, and database schema.
2. **Core platform expansion** — add new analysis job types and job routing.
3. **Evidence storage** — extend secure asset file manager and metadata capture.
4. **Python engine expansion** — add document, face, surveillance, email, and metadata pipelines.
5. **Explainability** — standardize result outputs and evidence packages.
6. **Reporting** — add forensic report templates and approval flows.
7. **Cloud/mobile support** — add mobile/cloud evidence ingestion and timeline analysis.
8. **Enterprise readiness** — add policy, access control, audit logging, and scaling.

---

## Recommended Files to Add

- `docs/enterprise-digital-media-forensics-platform-architecture.md`
- `backend-go/internal/deepfakeforensics/document_*`
- `backend-go/internal/deepfakeforensics/face_*`
- `backend-go/internal/deepfakeforensics/image_*`
- `backend-go/internal/deepfakeforensics/video_*`
- `backend-go/internal/deepfakeforensics/audio_*`
- `backend-go/internal/deepfakeforensics/surveillance_*`
- `backend-go/internal/deepfakeforensics/metadata_*`
- `backend-go/internal/deepfakeforensics/synthetic_*`
- `backend-go/internal/deepfakeforensics/email_*`
- `backend-go/internal/deepfakeforensics/cloud_*`
- `ai-engine/media_forensics_engine/`
- `scripts/migrations/seed/015_deepfake_forensics_enterprise_extensions.sql`
