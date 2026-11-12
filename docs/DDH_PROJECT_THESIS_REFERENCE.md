# Digital Defense Hub (DDH) – Thesis Project Reference

## 1. Project Overview

Digital Defense Hub (DDH) is a multi-tenant cyber security platform designed to detect ransomware behavior, analyze digital-media authenticity, preserve forensic evidence, and support investigation and response workflows. The project combines a Go-based backend, Python AI engine, React front-end, and PostgreSQL data layer to deliver an integrated defensive security platform rather than isolated tools.

The system is built around four major pillars:

- Ransomware and endpoint deception defense
- Digital-media and deepfake forensic analysis
- Evidence custody and investigation workflow
- Security operations and incident response orchestration

This project is implemented as a modular monolith backend with external AI and operational services, allowing security detection, forensics, and response modules to remain independent while sharing a common tenant-safe control plane.

---

## 2. Problem Statement

Modern organizations face two major trust problems:

1. Attackers can encrypt or damage data before traditional security tools detect the threat.
2. Digital media can be manipulated using AI-generated or edited content, causing false trust in evidence or investigation material.

Traditional anti-malware systems usually detect behavior after the damage has already spread. Similarly, media-authentication systems are often isolated from SOC workflows and lack evidence preservation and investigator context.

Digital Defense Hub addresses this gap by integrating:

- honeytoken and canary-based ransomware detection,
- forensic media analysis,
- evidence integrity management,
- incident correlation,
- secure tenant-based investigation workflows.

---

## 3. Project Objectives

The primary objectives of the DDH project are:

- Build a platform for defensive cyber security and digital forensics.
- Detect ransomware-like activity through deceptive canary files and honeytoken deployment.
- Provide strong file integrity validation using hashes and tamper-aware evidence capture.
- Support deepfake and synthetic-media analysis with category-specific model selection.
- Maintain a tenant-scoped, role-based access control system.
- Preserve evidence with integrity metadata and investigation audit trails.
- Provide operational workflows for investigation, recovery, and incident response.

---

## 4. Scope of the System

The platform covers the following areas:

### 4.1 Identity and Access

- User authentication and session management
- MFA and password lifecycle support
- Role-based authorization and tenant isolation
- Organization-level user administration

### 4.2 Honeytoken and Canary Protection

- Canary file generation and deployment
- Honeytoken-based detection logic
- File integrity verification
- Trigger detection for rename, delete, and modification events
- Evidence bundle generation for investigation

### 4.3 Threat Detection and Correlation

- Endpoint telemetry normalization
- Security event ingestion
- Relationship and attack-story correlation
- Risk and anomaly findings
- Incident creation and case handling

### 4.4 Deepfake and Media Forensics

- Image, video, and audio analysis support
- Model-based forensic classification
- Category-aware inference selection
- Evidence and confidence reporting
- Analyst review and investigation support

### 4.5 Evidence Vault and Recovery

- Evidence preservation
- Hash-chain and manifest validation
- WORM and custody design concepts
- Recovery workflows and emergency controls

---

## 5. System Architecture

The repository indicates a layered architecture with the following operational pipeline:

React UI -> Go REST API -> Auth/RBAC/Tenant middleware -> Domain services -> PostgreSQL

And AI workflow:

Go backend -> Authenticated HTTP API -> Python FastAPI AI engine -> Feature extraction/model runner -> Signed result and evidence output

There are also asynchronous security flows:

Normalized event -> transactional outbox -> worker/retry/DLQ -> entity graph -> correlation -> incident -> approved response

### 5.1 Main Components

#### Frontend
- React + Vite + TypeScript
- Operator console for dashboards, investigation modules, authentication, and workflows
- Connected to backend APIs under /api/v1

#### Backend
- Go REST API
- Security engines, repositories, service layer, workers, and middleware
- Multi-tenant resource isolation and RBAC enforcement

#### AI Engine
- Python + FastAPI
- Media analysis, deepfake scoring, feature extraction, training pipelines
- Model runner for ONNX and other inference assets

#### Database
- PostgreSQL
- Storage for users, organizations, incidents, events, evidence, and detection results

#### Security Monitoring
- Canaries and honeytokens deployed in protected directories
- Windows-based sentinel logic that captures file activity and offline JSONL alerts

---

## 6. Core Modules and Functional Areas

### 6.1 Authentication and Access Control

The platform includes authentication, permissions, RBAC, MFA, session lifecycle, and organization-level isolation. Security controls include:

- tenant-aware queries,
- JWT validation,
- refresh-token rotation,
- password lifecycle enforcement,
- MFA challenge expiry,
- least-privilege access design.

### 6.2 HoneyToken and Ransomware Defense

This is a core DDH capability. The system generates canary files and honeytokens in controlled folders. When an attacker or malicious process modifies, renames, or deletes the canary, the system raises an alert and records evidence.

The event flow includes:

1. Create or import a canary file
2. Validate allowed file type and safe deployment path
3. Generate original file hash and metadata
4. Copy to protected directory
5. Monitor for filesystem changes
6. Trigger alert on modification or deletion
7. Save evidence and support incident correlation

### 6.3 Deepfake and Media Forensics

The platform includes media analysis modules for images, video, audio, and forensic artifacts. The design is category-aware and avoids unsafe “single model for all cases” assumptions.

The repository references specialized models such as:

- Whole-image V4 for modern AI-generated images
- Face-swap V2 for face manipulation detection
- Unified V6 as a legacy candidate requiring further validation

This design reflects a forensic approach where model selection depends on media category and evidence quality rather than blind ensemble output.

### 6.4 Security Event and Correlation Pipeline

The project includes normalized security event processing with:

- transactional outbox design,
- worker retry logic,
- dead-letter queue handling,
- entity and relationship graph generation,
- timeline and attack story construction,
- correlation between security events, files, devices, and identities.

### 6.5 Evidence Vault and Integrity

DDH includes evidence-focused design around:

- SHA-256 integrity hashing,
- canonical manifest generation,
- signature and verification support,
- evidence custody metadata,
- WORM-style preservation concepts,
- signed artifact verification.

This enables the platform to maintain an audit-ready chain of custody for incident investigation.

### 6.6 Recovery and Response

The platform supports a recovery and incident response lifecycle with:

- dry-run actions,
- approval states,
- execution verification,
- rollback mechanisms,
- emergency stop controls,
- action allowlists and state transitions.

---

## 7. Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Frontend | React, Vite, TypeScript | Security dashboard and operator console |
| Backend | Go, Gin-style REST APIs | Service layer, RBAC, repositories, workflows |
| Database | PostgreSQL | Multi-tenant storage and security event persistence |
| AI Engine | Python, FastAPI | Model orchestration and media forensic inference |
| Model Runtime | PyTorch, ONNX Runtime | Deepfake and forensic model execution |
| Integrity Layer | SHA-256, Ed25519 concepts | Evidence verification and signing |
| Monitoring | Windows PowerShell / file watchdog logic | Canary detection and offline alerting |
| Storage | PostgreSQL + secure object storage | Assets, jobs, reports, and evidence |

---

## 8. Data and Workflow Design

The project follows a defensive, evidence-first workflow:

### 8.1 Canary Deployment Flow

1. Create or import a canary file
2. Validate tenant, type, path, and file metadata
3. Generate original hash and store deployment state
4. Copy file into protected directory
5. Verify integrity after copy
6. Monitor for modifications, renames, and deletion
7. Trigger alert and generate evidence bundle
8. Correlate results with incidents and response workflows

### 8.2 Media Forensics Flow

1. Media file uploaded for analysis
2. Validate MIME type, size, path, and storage rules
3. Generate integrity and identity records
4. Queue analysis job
5. Select category-appropriate model
6. Run inference and extract forensic features
7. Calculate confidence, risk score, and reasoning
8. Save result and supporting evidence for analyst review

### 8.3 Investigation Flow

1. Detect event or alert
2. Link to entities, endpoints, users, and files
3. Build timeline and investigation story
4. Attach forensic artifacts and evidence manifests
5. Approve or reject response actions
6. Record resolution and final evidence trail

---

## 9. Functional Requirements Covered

The project design explicitly includes the following functional requirements:

- FR-Identity: login, MFA, trusted device, session management
- FR-Tenant: record isolation per organization
- FR-Ingestion: normalized endpoint, network, and file event intake
- FR-Detection: credential abuse, privilege escalation, lateral movement, ransomware, and anomaly detection
- FR-Correlation: entity and attack-story correlation
- FR-Investigation: evidence, forensic output, and analyst comparison
- FR-Response: dry-run, execution, verification, rollback, and emergency stoppage
- FR-Administration: organization, roles, users, policies, and platform settings
- FR-Observability: health checks, metrics, and operational visibility

---

## 10. Non-Functional Requirements Covered

- Security: least privilege, tenant isolation, validation, key separation, fail-closed design
- Reliability: retry logic, idempotency, stale-job recovery, rollback
- Integrity: hashed evidence, signed manifests, immutable evidence design
- Performance: PostgreSQL indexes, async workers, bounded query design
- Scalability: stateless API and external service adapters
- Auditability: request ID tracking, actor attribution, event history
- Maintainability: modular package structure and migration-based database evolution
- Recoverability: backup verification and recovery state machine

---

## 11. Thesis Relevance and Project Significance

Digital Defense Hub is significant because it combines defensive cyber-security, AI-based media forensics, and evidence-driven investigation in a single platform. It helps bridge a gap between:

- endpoint defense,
- cyber incident response,
- deepfake authenticity analysis,
- digital evidence preservation.

This is especially relevant in modern cyber environments where ransomware acts quickly and manipulated media can mislead investigations. The project demonstrates how deception-based detection and forensic intelligence can be combined under a common operational platform.

---

## 12. Potential Research Contributions

This project can support research topics such as:

- honeytoken-based ransomware early warning systems,
- canary file integrity detection in enterprise environments,
- cross-layer event correlation for incident response,
- evidence-first digital forensics workflows,
- category-aware deepfake detection strategies,
- multi-tenant security orchestration in cyber defense platforms.

---

## 13. Important Limitations and Honesty of the Design

The documentation in the repository is precise about the need to distinguish between implemented capabilities and planned or research-level claims. Some important limitations include:

- Read-only file access may not be captured by default watcher designs without SACL or kernel-level auditing.
- Deepfake detection claims must remain evidence-based and category-specific.
- Model decisions should not be treated as certainty without proper validation and threshold control.
- Production evidence guarantees depend on secure key management and WORM-style storage.

This honesty makes the project more suitable for academic and engineering discussion.

---

## 14. Key Project Files and References

These repository files serve as the primary evidence base for the project:

- README.md
- docs/PROJECT_ARCHITECTURE_AND_REQUIREMENTS_THANGGLISH.md
- docs/dfir-attribution-module.md
- docs/enterprise-digital-media-forensics-platform-architecture.md
- docs/DEEPFAKE_ENSEMBLE_COVERAGE_AUDIT.md
- docs/platform-status-and-next-build.md
- backend-go/internal/HoneyToken/
- backend-go/internal/dfir/
- backend-go/internal/deepfakeforensics/
- ai-engine/app/
- frontend-react/

These documents and code folders are the main sources to cite in a thesis or technical report.

---

## 15. Short Thesis Abstract Draft

Digital Defense Hub is a multi-tenant cyber security platform designed to detect ransomware and synthetic-media threats while preserving forensic evidence for investigation. The system combines honeytoken-based canary alerts, tenant-aware security event processing, forensic media analysis, and evidence-guided response workflows. The Go backend provides security orchestration, PostgreSQL persistence, and RBAC controls, while the Python AI engine performs deepfake and media analysis. The platform uses hash-based integrity validation, defensive evidence capture, and correlation logic to support attack investigation and incident response. By integrating deception defense with digital forensics, Digital Defense Hub provides an evidence-first architecture for modern cyber defense scenarios.

---

## 16. Conclusion

Digital Defense Hub is a strong thesis project because it integrates multiple facets of cyber defense into one design: deception-based ransomware detection, AI-driven deepfake analysis, incident correlation, evidence integrity, and multi-tenant security operations. It is technically rich, academically relevant, and closely aligned with contemporary cybersecurity and digital-forensics research.

This project is suitable for a thesis, technical report, or research study when framed carefully around implemented capabilities, model validations, and known operational limitations.
