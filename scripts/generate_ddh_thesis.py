from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "Digital_Defense_Hub_Thesis_Editable.docx"


def shade(cell, fill):
    properties = cell._tc.get_or_add_tcPr()
    element = OxmlElement("w:shd")
    element.set(qn("w:fill"), fill)
    properties.append(element)


def set_cell_text(cell, text, bold=False):
    cell.text = ""
    paragraph = cell.paragraphs[0]
    run = paragraph.add_run(str(text))
    run.bold = bold
    run.font.size = Pt(9)
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER


def add_table(doc, headers, rows):
    result = doc.add_table(rows=1, cols=len(headers))
    result.style = "Table Grid"
    result.alignment = WD_TABLE_ALIGNMENT.CENTER
    for index, header in enumerate(headers):
        set_cell_text(result.rows[0].cells[index], header, True)
        shade(result.rows[0].cells[index], "D9EAF7")
    for row in rows:
        cells = result.add_row().cells
        for index, value in enumerate(row):
            set_cell_text(cells[index], value)
    doc.add_paragraph()


def bullet(doc, text, level=0):
    style = "List Bullet" if level == 0 else "List Bullet 2"
    doc.add_paragraph(text, style=style)


def numbered(doc, text):
    doc.add_paragraph(text, style="List Number")


def diagram(doc, title, lines):
    paragraph = doc.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = paragraph.add_run(title)
    run.bold = True
    run.font.size = Pt(10)
    code = doc.add_paragraph()
    code.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = code.add_run("\n".join(lines))
    run.font.name = "Consolas"
    run.font.size = Pt(8)
    doc.add_paragraph()


def heading(doc, text, level=1):
    doc.add_heading(text, level=level)


def paragraph(doc, text):
    item = doc.add_paragraph(text)
    item.paragraph_format.space_after = Pt(6)
    return item


def add_page_number(section):
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.add_run("Page ")
    field = OxmlElement("w:fldSimple")
    field.set(qn("w:instr"), "PAGE")
    footer._p.append(field)


def build():
    doc = Document()
    section = doc.sections[0]
    section.top_margin = Inches(0.75)
    section.bottom_margin = Inches(0.7)
    section.left_margin = Inches(0.85)
    section.right_margin = Inches(0.75)
    add_page_number(section)

    styles = doc.styles
    styles["Normal"].font.name = "Times New Roman"
    styles["Normal"].font.size = Pt(11)
    for style_name in ("Heading 1", "Heading 2", "Heading 3"):
        styles[style_name].font.name = "Times New Roman"
        styles[style_name].font.bold = True

    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.add_run("DIGITAL DEFENSE HUB\n").bold = True
    title.add_run("HONEYTOKEN-BASED CANARY FILE DEPLOYMENT FOR\n"
                  "RANSOMWARE DETECTION AND DEEPFAKE FORENSIC\n"
                  "AUTHENTICATION SUITE").bold = True
    for run in title.runs:
        run.font.size = Pt(16)
    doc.add_paragraph()
    cover = doc.add_paragraph()
    cover.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cover.add_run("A PROJECT THESIS / TECHNICAL REPORT\n\n").bold = True
    cover.add_run("Submitted in partial fulfillment of the requirements for the degree of\n")
    cover.add_run("BACHELOR OF SCIENCE IN COMPUTER SCIENCE").bold = True
    cover.add_run("\n\nStudent Name: ______________________________\nRegister No.: ______________________________\nGuide: _____________________________________\nDepartment / Institution: ___________________\nAcademic Year: 2026")
    doc.add_page_break()

    heading(doc, "ABSTRACT")
    paragraph(doc, "Digital Defense Hub (DDH) is a multi-tenant defensive cybersecurity platform that combines deception-based ransomware early warning with digital-media forensic authentication. The platform creates or imports controlled canary files and honeytokens, records their original integrity state, deploys them into approved directories, and observes file-system events such as modification, rename, movement, or deletion. Suspicious events are normalized, scored, correlated with entities and incidents, and preserved as evidence. In parallel, the platform accepts image, video, audio, and document evidence, validates media intake, queues analysis jobs, selects an approved category-aware model, and returns confidence-based forensic findings for analyst review. The Go backend provides API, tenant isolation, authorization, workflow, and PostgreSQL persistence. The Python AI engine provides media and machine-learning analysis. SHA-256 hashing, encrypted decoy values, audit trails, asynchronous workers, and model-integrity verification support an evidence-first workflow. The system is designed to report observed evidence and confidence rather than unsupported certainty. Advanced deepfake accuracy remains dependent on the approved model, dataset, threshold, and validation protocol.")
    paragraph(doc, "Keywords: cybersecurity, ransomware detection, honeytoken, canary file, digital forensics, deepfake detection, SHA-256, tenant isolation, evidence integrity, explainable risk scoring")

    heading(doc, "TABLE OF CONTENTS")
    for item in ["1. Introduction", "2. Survey of Technology", "3. Requirements and Analysis", "4. System Design", "5. Implementation and Testing", "6. Results and Discussion", "7. Conclusion and Future Scope", "References", "Appendix A - API and State Tables", "Appendix B - Test Evidence Checklist"]:
        paragraph(doc, item)
    paragraph(doc, "Note: In Microsoft Word, right-click this section and choose Update Field after pagination changes.")

    heading(doc, "LIST OF FIGURES")
    for item in ["Figure 4.1 Overall DDH architecture", "Figure 4.2 Canary deployment and trigger flow", "Figure 4.3 Deepfake forensic analysis flow", "Figure 4.4 Evidence and incident correlation flow", "Figure 5.1 Analysis job state machine", "Figure 6.1 Suggested evaluation dashboard"]:
        paragraph(doc, item)
    heading(doc, "LIST OF TABLES")
    for item in ["Table 3.1 Functional requirements", "Table 3.2 Non-functional requirements", "Table 3.3 Technology stack", "Table 4.1 Core entities", "Table 5.1 Test cases", "Table 6.1 Evaluation metrics"]:
        paragraph(doc, item)

    heading(doc, "CHAPTER 1 - INTRODUCTION")
    heading(doc, "1.1 Background", 2)
    paragraph(doc, "Ransomware can cause operational disruption by encrypting or destroying files before conventional investigation is complete. Deception controls reduce attacker confidence by placing monitored decoy assets in locations that legitimate users and automated business processes should not modify. A canary file is a monitored decoy document; a honeytoken is a decoy value such as a credential, URL, API key, or database record. Interaction with either asset becomes a high-value signal because the asset is intentionally outside the normal business workflow.")
    paragraph(doc, "At the same time, AI-generated and manipulated images, videos, audio, and documents can compromise the reliability of digital evidence. A practical forensic platform must therefore combine media analysis with provenance, integrity, analyst review, and a clear statement of uncertainty.")
    heading(doc, "1.2 Problem Statement", 2)
    paragraph(doc, "Existing security controls and media-forensics tools are often separate. An alert may not carry the original file hash, deployment context, event timeline, model version, or analyst decision required for an investigation. DDH addresses this integration problem through a tenant-safe control plane that connects deception telemetry, forensic analysis, evidence custody, incident correlation, and response workflows.")
    heading(doc, "1.3 Aim and Objectives", 2)
    for item in ["Design a defensive platform for early ransomware detection using canary files and honeytokens.", "Preserve file and media evidence with cryptographic integrity metadata and custody records.", "Provide category-aware forensic analysis for image, video, audio, and document inputs.", "Use explainable, confidence-based risk scoring instead of presenting model output as certainty.", "Enforce tenant isolation, authentication, authorization, and least-privilege access.", "Support asynchronous analysis, retry, stale-job recovery, and investigation workflows."]:
        bullet(doc, item)
    heading(doc, "1.4 Scope and Boundaries", 2)
    paragraph(doc, "The implemented scope includes backend APIs, PostgreSQL persistence, a React operator console, a Python AI service, canary and honeytoken workflows, file-event detection, evidence packaging, media analysis job orchestration, and model-security verification. Kernel-level read auditing, production WORM guarantees, voice biometrics, cross-modal identity correlation, and fully autonomous response remain deployment- or model-dependent and are treated as limitations or future work.")
    heading(doc, "1.5 Significance", 2)
    paragraph(doc, "The project is significant because it joins deception defense and synthetic-media forensics under one evidence-first investigation workflow. This makes it suitable for security operations, digital-forensics research, and organizations that need both early warning and trustworthy evidence handling.")

    heading(doc, "CHAPTER 2 - SURVEY OF TECHNOLOGY")
    heading(doc, "2.1 Existing Approaches", 2)
    add_table(doc, ["Approach", "Strength", "Limitation addressed by DDH"], [["Signature / endpoint antivirus", "Known malware detection", "May miss new behavior and does not preserve a full forensic story"], ["Behavioral ransomware detection", "Detects file-change patterns", "Needs high-value deception signals and evidence correlation"], ["Honeytokens and canaries", "Low-noise unauthorized interaction signal", "Usually isolated from media forensics and case management"], ["Single-model deepfake classifier", "Simple deployment", "Model performance varies by media category and evidence quality"], ["Manual evidence collection", "Human judgment", "Slow, inconsistent, and vulnerable to missing integrity metadata"]])
    heading(doc, "2.2 Proposed Technology", 2)
    paragraph(doc, "DDH uses a modular monolith Go backend with a separate Python AI engine. The backend owns identity, tenant context, workflows, persistence, event normalization, incident correlation, and response state. The AI engine owns media routing, model execution, feature extraction, and confidence reporting. The React frontend exposes operator workflows through authenticated APIs.")
    heading(doc, "2.3 Deep Learning and Forensic Techniques", 2)
    for item in ["Category-aware model routing: image, face manipulation, video temporal analysis, audio, OCR, metadata, and document paths are treated as different evidence types.", "ONNX/PyTorch-compatible model execution: approved model artifacts can be loaded and verified before inference.", "Feature-based forensic analysis: metadata consistency, frame-level or temporal findings, localization, OCR, and explainability evidence support the result.", "Confidence matrix and human review: a score is accompanied by evidence and review status; it is not a legal conclusion.", "Dataset and model governance: model versions, validation, approval, rollback, organization assignment, and SHA-256 integrity checks are part of the platform contract."]:
        bullet(doc, item)
    heading(doc, "2.4 Security and Cryptographic Techniques", 2)
    for item in ["SHA-256 for canary, media, model, and evidence artifact identity.", "SHA-512 and content fingerprints where secure evidence intake requires additional comparison.", "Encrypted-at-rest decoy values and one-time plaintext return for honeytokens.", "JWT authentication, refresh-token rotation, RBAC, tenant-scoped queries, and audit attribution.", "Canonical manifests, evidence bundles, custody events, and signed-artifact verification concepts."]:
        bullet(doc, item)

    heading(doc, "CHAPTER 3 - REQUIREMENTS AND ANALYSIS")
    heading(doc, "3.1 Functional Requirements", 2)
    add_table(doc, ["ID", "Requirement", "Expected behavior"], [["FR-01", "Identity and access", "Authenticate users, validate JWT/session context, enforce role and permission checks."], ["FR-02", "Tenant isolation", "Every organization-owned query and mutation is scoped to the authenticated organization."], ["FR-03", "Honeytoken lifecycle", "Generate, encrypt, store, deploy, expire, trigger, and investigate decoy values."], ["FR-04", "Canary lifecycle", "Create/import, hash, deploy, monitor, trigger, quarantine, and inspect canary files."], ["FR-05", "Event processing", "Normalize file and security events and preserve idempotent event identity."], ["FR-06", "Threat scoring", "Classify canary, honeytoken, ransomware, tampering, integrity, and anomaly signals."], ["FR-07", "Media intake", "Validate file type, size, path, storage, metadata, and analysis request."], ["FR-08", "Forensic analysis", "Queue a job, select a model, run analysis, persist findings, and support analyst review."], ["FR-09", "Evidence custody", "Store hashes, manifests, timestamps, source information, and custody transitions."], ["FR-10", "Investigation", "Link events to incidents, cases, timelines, entities, and reports."]])
    heading(doc, "3.2 Non-Functional Requirements", 2)
    add_table(doc, ["Quality", "Design requirement", "Implementation direction"], [["Security", "Least privilege and fail-closed validation", "Middleware, allowlists, tenant checks, input validation"], ["Integrity", "Detect changes to evidence and models", "SHA-256, manifests, verification history"], ["Reliability", "Recover from worker failure", "Leases, heartbeats, retries, stale-job recovery, DLQ"], ["Auditability", "Explain who/what/when", "Actor IDs, event history, request IDs, custody events"], ["Scalability", "Avoid blocking API requests", "Asynchronous jobs and PostgreSQL worker claims"], ["Maintainability", "Keep domain boundaries clear", "Go package layers: routes, handler, service, repository"]])
    heading(doc, "3.3 Hardware and Software Requirements", 2)
    add_table(doc, ["Layer", "Requirement / technology", "Purpose"], [["Frontend", "React, Vite, TypeScript", "Operator console and authenticated workflows"], ["Backend", "Go REST API", "Security domain services, authorization, persistence"], ["AI service", "Python, FastAPI, PyTorch/ONNX Runtime", "Media analysis and model inference"], ["Database", "PostgreSQL", "Tenant-scoped users, events, jobs, incidents, and evidence"], ["Endpoint", "Windows PowerShell sentinel", "Local canary monitoring and offline alert/evidence bundles"], ["Storage", "Protected local/object storage", "Uploads, model artifacts, reports, and evidence packages"]])
    heading(doc, "3.4 Feasibility Study", 2)
    paragraph(doc, "Technical feasibility is supported by the existing Go, Python, React, PostgreSQL, and Windows tooling. Economic feasibility is improved by using open-source runtimes and asynchronous scale-out rather than requiring specialized hardware for every operator. Operational feasibility depends on approved monitored paths, secure key management, model validation, and trained analysts. Legal feasibility requires authorized monitoring, documented consent, retention policy, and careful language around attribution.")

    heading(doc, "CHAPTER 4 - SYSTEM DESIGN")
    heading(doc, "4.1 Overall Architecture", 2)
    diagram(doc, "Figure 4.1 Overall DDH architecture", ["[React Operator Console]", "          | HTTPS / JWT", "[Go API + Auth/RBAC/Tenant Middleware]", "     |             |                 |", "[PostgreSQL]  [Event/Job Workers]  [Python FastAPI AI Engine]", "     |             |                 |", "[Evidence +     [Correlation +     [Model Router + Feature", " Incidents]       Threats]           Extraction + Inference]", "          \\        |        /", "          [Investigation and Evidence-First Reporting]"])
    paragraph(doc, "The request path is router -> middleware -> handler -> service -> repository -> database. The analysis path is request -> queued job -> leased worker -> model or forensic executor -> result event -> evidence and incident correlation.")
    heading(doc, "4.2 Canary and Honeytoken Design", 2)
    add_table(doc, ["Entity", "Important fields", "Security purpose"], [["Honeytoken", "code, type, encrypted value, value hash, prefix, classification, owner, status", "Detect interaction with a decoy secret without exposing the secret"], ["Canary file", "code, file name/path, original hash, algorithm, size, tracking ID, status", "Detect unauthorized file modification, rename, move, or deletion"], ["File event", "event type, resource, timestamp, actor/device context, payload", "Provide observable detection evidence"], ["Threat", "type, category, severity/risk, status, evidence references", "Prioritize and correlate suspicious behavior"], ["Evidence artifact", "source, SHA-256, size, collection time, custody token", "Preserve verifiable investigation material"]])
    diagram(doc, "Figure 4.2 Canary deployment and trigger flow", ["Create / Import Canary", "        | validate type, path, tenant", "        v", "Generate bytes + SHA-256 + metadata", "        |", "        v", "Deploy to approved protected root", "        | verify copy hash", "        v", "Windows sentinel / file monitor", "        | modified | renamed | moved | deleted", "        v", "Normalize event -> classify threat -> score", "        v", "Evidence bundle -> incident -> investigation case"])
    heading(doc, "4.3 Deepfake Forensic Architecture", 2)
    diagram(doc, "Figure 4.3 Deepfake forensic analysis flow", ["Media upload (image/video/audio/document)", "                 |", "MIME, size, path, tenant and policy validation", "                 |", "SHA-256 asset identity + secure storage", "                 |", "Queued analysis job with model/version", "                 |", "Category router -> image / face / video / audio / OCR", "                 |", "Feature extraction + ONNX/PyTorch inference", "                 |", "confidence + localization + metadata/temporal evidence", "                 |", "human review -> report approval -> incident correlation"])
    heading(doc, "4.4 Threat Scoring Model", 2)
    paragraph(doc, "DDH uses explainable weighted risk scoring. The exact production weight table is configurable and must be reported with an experiment. A thesis-level representation is:")
    paragraph(doc, "R = min(100, B + Wc*C + Wh*H + We*E + Wm*M + Wp*P - Wa*A)")
    paragraph(doc, "where B is the baseline score, C is canary-trigger evidence, H is honeytoken interaction evidence, E is encryption or multiple-file-change evidence, M is a media-forensic risk signal, P is corroborating context, and A is an approved allowlist or benign-context adjustment. Each component must retain an evidence reference and rule/model version.")
    paragraph(doc, "For confidence aggregation across independent signals, a conservative union form is:")
    paragraph(doc, "C_union = 1 - product(1 - c_i), for i = 1..n")
    paragraph(doc, "This formula must not be interpreted as statistical independence unless the experiment validates that assumption. In practice, DDH should show both individual detector confidence and the combined score.")
    heading(doc, "4.5 Evidence Integrity Formulas", 2)
    paragraph(doc, "For a file or artifact x, the integrity digest is H(x) = SHA-256(bytes(x)). A verification decision is:")
    paragraph(doc, "Verified = 1 if H_observed(x) = H_expected(x); otherwise Verified = 0")
    paragraph(doc, "For a canonical evidence manifest containing ordered entries e1..en, the manifest digest can be represented as M = SHA-256(canonicalize(e1 || e2 || ... || en)). A chain-of-custody record should preserve artifact ID, actor, timestamp, action, previous manifest reference, and resulting digest.")
    heading(doc, "4.6 Data Model and Relationships", 2)
    add_table(doc, ["Parent", "Child / relation", "Meaning"], [["Organization", "Users, policies, canaries, honeytokens, incidents, evidence", "Tenant boundary"], ["Canary file", "File events, threats, investigation links", "Decoy detection story"], ["Media asset", "Analysis jobs, results, reports, evidence", "Forensic analysis lifecycle"], ["Analysis job", "Job events, worker lease, result", "Reliable async processing"], ["Incident", "Timeline, entities, evidence, response actions", "Case-level investigation"]])
    heading(doc, "4.7 Security Controls", 2)
    for item in ["JWT authentication and permission middleware protect routes.", "Repository queries carry organization scope to prevent cross-tenant access.", "Honeytoken plaintext is returned once and encrypted material is excluded from general JSON responses.", "Canary deployment is restricted to a configured root and rejects path escape conditions.", "Model artifacts use expected-versus-observed SHA-256 verification and durable verification history.", "Offline sentinel alerts are local JSONL/evidence outputs and are not presented as authoritative process attribution."]:
        bullet(doc, item)

    heading(doc, "CHAPTER 5 - IMPLEMENTATION AND TESTING")
    heading(doc, "5.1 Implementation Modules", 2)
    add_table(doc, ["Module", "Implementation responsibility", "Primary techniques"], [["Authentication/RBAC", "Login, session, role and permission enforcement", "JWT, refresh rotation, tenant context, least privilege"], ["HoneyToken", "Generate, encrypt, store and deploy decoys", "Encrypted values, hashes, lifecycle states"], ["Canary", "Generate/import, hash, deploy and inspect decoy files", "SHA-256, path validation, safe metadata"], ["File monitor", "Capture observable file changes", "Windows notifications, deduplication, JSONL alerting"], ["DFIR", "Normalize signals and preserve investigation evidence", "Weighted rules, timelines, evidence bundles"], ["Deepfake forensics", "Queue and execute media analysis", "Model routing, feature evidence, confidence and review"], ["Operational workers", "Claim and complete analysis jobs", "FOR UPDATE SKIP LOCKED, leases, heartbeats, retries"], ["Frontend", "Operator views for live platform workflows", "React, TypeScript, API response envelopes"]])
    heading(doc, "5.2 Analysis Job State Machine", 2)
    diagram(doc, "Figure 5.1 Analysis job state machine", ["QUEUED -> AWAITING_EXECUTOR -> RUNNING -> COMPLETED", "   |             |               |", "   |             |               +--> FAILED -> RETRY -> QUEUED", "   |             +--> CANCELLED", "   +--> stale lease recovery -> QUEUED", "Every transition writes a job event with actor/worker and timestamp."])
    heading(doc, "5.3 Testing Strategy", 2)
    paragraph(doc, "Testing should combine unit tests for validation and scoring, repository/contract tests for tenant scope, integration tests for API and database workflows, and controlled endpoint tests for the Windows sentinel. Deepfake evaluation must use a held-out dataset and report class balance, threshold, model version, and media category.")
    heading(doc, "5.4 Test Cases", 2)
    add_table(doc, ["ID", "Test case", "Expected result"], [["TC-01", "Create canary with unsupported type", "Request rejected; no database record created"], ["TC-02", "Deploy canary outside configured root", "Deployment rejected with path safety error"], ["TC-03", "Modify deployed canary", "File event and canary/threat signal recorded"], ["TC-04", "Delete deployed canary", "Missing/tampered state and evidence alert recorded"], ["TC-05", "Create honeytoken", "Encrypted value stored; plaintext returned only once"], ["TC-06", "Cross-tenant record request", "Not found or unauthorized; no data disclosure"], ["TC-07", "Upload invalid media MIME or oversized file", "Rejected before analysis job creation"], ["TC-08", "Claim analysis job by two workers", "Only one worker obtains the row lock"], ["TC-09", "Worker lease expires", "Job becomes recoverable and can be retried"], ["TC-10", "Observed model hash differs", "Verification decision is BLOCKED"], ["TC-11", "Evidence hash recomputation", "Matching digest verifies; changed bytes fail"], ["TC-12", "Analyst approves forensic report", "Approval note and audit event are persisted"]])
    heading(doc, "5.5 Ethical and Legal Test Boundaries", 2)
    paragraph(doc, "Testing must occur only on authorized endpoints, paths, accounts, and media. The platform must not claim that a local snapshot proves which process or person caused a file event. Attribution is confidence-based and requires corroborating evidence. Media analysis must use consented or lawfully obtained material and must preserve human review for consequential decisions.")

    heading(doc, "CHAPTER 6 - RESULTS AND DISCUSSION")
    heading(doc, "6.1 Results to Report", 2)
    paragraph(doc, "The repository confirms implemented workflows and data contracts, but an academic results chapter must be populated with measured experiment output rather than invented percentages. The following table is the required measurement plan.")
    add_table(doc, ["Metric", "Formula / definition", "Experiment"], [["Precision", "TP / (TP + FP)", "Canary/file-event alert classification"], ["Recall", "TP / (TP + FN)", "Ransomware-like event detection"], ["F1 score", "2 * Precision * Recall / (Precision + Recall)", "Balanced detection summary"], ["False positive rate", "FP / (FP + TN)", "Benign file activity control set"], ["Detection latency", "alert_timestamp - event_timestamp", "Sentinel and API timestamp logs"], ["Integrity verification rate", "verified_artifacts / total_artifacts", "Evidence/model hash tests"], ["Media accuracy", "correct_predictions / total_samples", "Per-category held-out dataset"], ["AUC / AP", "Threshold-independent ranking metrics", "Only when labels and score outputs exist"]])
    heading(doc, "6.2 Recommended Evaluation Matrix", 2)
    add_table(doc, ["Dimension", "Control", "Treatment", "Output"], [["File activity", "Benign create/modify workload", "Canary modification/rename/delete", "precision, recall, latency"], ["Ransomware behavior", "Low-change workload", "Rapid multi-file change/encryption simulation", "risk score and alert time"], ["Media category", "Authentic samples", "Manipulated/synthetic samples", "per-category confusion matrix"], ["Model integrity", "Matching artifact digest", "Changed artifact digest", "VERIFIED/BLOCKED decision"], ["Tenant security", "Same-tenant request", "Cross-tenant request", "authorization and leakage result"]])
    heading(doc, "6.3 Discussion", 2)
    paragraph(doc, "Canary interaction is a high-value signal because it should have a low benign-activity rate. However, the signal still requires context: deployment mistakes, backup software, administrative testing, or stale decoys can create noise. The best operational result is therefore not a single alert but a correlated story containing the event, original hash, endpoint context, timestamp, related file changes, evidence digest, and analyst disposition.")
    paragraph(doc, "Deepfake detection results must be separated by category. An image model cannot be assumed to perform equally on face swaps, full-image synthesis, video temporal manipulation, audio cloning, or documents. The thesis should publish sample counts, train/validation/test split, model version, threshold, confidence calibration, and error analysis. The platform's design supports this separation, while the final accuracy depends on the approved local models and datasets.")
    heading(doc, "6.4 Current Implementation Status", 2)
    add_table(doc, ["Capability", "Status for thesis wording"], [["Canary and honeytoken backend workflows", "Implemented / available"], ["Evidence intake, SHA-256 and custody metadata", "Implemented / available"], ["Deepfake/media routing and analysis contracts", "Implemented / model-dependent"], ["Model governance and integrity verification", "Implemented at application boundary"], ["Kernel-level read attribution", "Not claimed; requires SACL or minifilter deployment"], ["Fully autonomous response", "Partial / future integration"], ["Production deepfake accuracy", "Must be measured; do not insert an unverified percentage"]])

    heading(doc, "CHAPTER 7 - CONCLUSION AND FUTURE SCOPE")
    heading(doc, "7.1 Conclusion", 2)
    paragraph(doc, "Digital Defense Hub demonstrates an integrated approach to modern cyber defense by connecting deception-based ransomware detection, digital-media forensics, evidence integrity, and investigation workflows. Its main engineering contribution is the shared evidence-first control plane: canary and honeytoken events are not isolated notifications, and media-model findings are not isolated scores. Both are preserved with tenant context, hashes, workflow state, audit history, and analyst review. The system is technically suitable as a thesis when measured claims are kept separate from implemented contracts and future integrations.")
    heading(doc, "7.2 Future Scope", 2)
    for item in ["Add Windows SACL/object-access auditing or a signed minifilter for reliable read attribution.", "Evaluate calibrated deepfake models separately for image synthesis, face swap, video, audio, OCR, and document evidence.", "Add multimodal contradiction analysis between metadata, OCR, model findings, and human assertions.", "Integrate approved WORM/object-lock storage and hardware-backed key management for production custody guarantees.", "Expand replayable incident stories and cross-incident correlation using approved indicators and embeddings.", "Complete response automation with approval gates, rollback, emergency stop, and endpoint isolation verification.", "Publish a reproducible benchmark with dataset manifests, model hashes, thresholds, confusion matrices, and latency distributions."]:
        bullet(doc, item)

    heading(doc, "REFERENCES")
    refs = ["Digital Defense Hub repository documentation: DDH_PROJECT_THESIS_REFERENCE.md.", "Digital Defense Hub, PROJECT_ARCHITECTURE_AND_REQUIREMENTS_THANGGLISH.md.", "Digital Defense Hub, platform-status-and-next-build.md.", "Digital Defense Hub, dfir-attribution-module.md.", "Digital Defense Hub, canary-sentinel.md and scripts/canary-sentinel.ps1.", "Digital Defense Hub backend-go/internal/HoneyToken implementation package.", "Digital Defense Hub backend-go/internal/dfir implementation package.", "Digital Defense Hub deepfakeforensics and AI-engine implementation packages.", "S. B. Kotsiantis, I. Zaharakis, and P. Pintelas, Machine learning: a review of classification and combining techniques, Artificial Intelligence Review, 2006.", "A. Rössler et al., FaceForensics++: Learning to detect manipulated facial images, ICCV, 2019.", "M. Verdoliva, Media forensics and deepfakes: an overview, IEEE Journal of Selected Topics in Signal Processing, 2020.", "NIST, Digital Identity Guidelines and Cybersecurity Framework documentation."]
    for index, ref in enumerate(refs, 1):
        paragraph(doc, f"[{index}] {ref}")

    heading(doc, "APPENDIX A - API AND STATE TABLES")
    add_table(doc, ["API group", "Representative operations", "Security note"], [["/canary-files", "create, import, list, retrieve, deploy, investigation", "Authenticated and permission-protected"], ["/honeytokens", "create, list, retrieve, deploy, trigger review", "Secret value excluded from normal responses"], ["/deepfake-forensics", "media upload, analyze, result, report, model governance", "Tenant policy and review threshold apply"], ["/file-events and /threats", "record/list/update/resolve", "Immutable event history and scoped access"], ["/model-security", "verify, list, posture", "Expected and observed hash comparison"], ["/investigation-cases", "create, link incident, retrieve, update", "Case-scoped evidence access"]])
    add_table(doc, ["State family", "States"], [["Canary", "DRAFT, DEPLOYED, ACTIVE, TRIGGERED, TAMPERED, MISSING, INACTIVE, EXPIRED, ARCHIVED"], ["Honeytoken", "DRAFT, ACTIVE, TRIGGERED, INACTIVE, EXPIRED, REVOKED, ARCHIVED"], ["Analysis job", "QUEUED, AWAITING_EXECUTOR, RUNNING, COMPLETED, FAILED, CANCELLED"], ["Model verification", "VERIFIED, BLOCKED"]])
    heading(doc, "APPENDIX B - TEST EVIDENCE CHECKLIST")
    for item in ["Record environment, OS, dependency versions, model ID, model version, and artifact SHA-256.", "Record dataset manifest, labels, train/validation/test split, and class balance.", "Save raw event timestamp and alert timestamp for latency calculation.", "Save request ID, organization ID, actor/worker ID, and result status for workflow tests.", "Attach evidence bundle path and recomputed digest to each integrity conclusion.", "Document benign control runs and false positives, not only successful detections.", "Record human-review decision and reason for all high-impact forensic outcomes."]:
        bullet(doc, item)

    doc.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    build()