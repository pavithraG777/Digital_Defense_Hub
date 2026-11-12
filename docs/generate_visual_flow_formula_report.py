from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt

from generate_implemented_project_report import add_figure, add_table, heading


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "Digital_Defense_Hub_Visual_Flow_Formula_Report.docx"
DIAGRAMS = ROOT / "report_diagrams"


def paragraph(document, text):
    item = document.add_paragraph(text)
    item.paragraph_format.space_after = Pt(8)


def topic_page(document, title, explanation, diagram, caption, formulas=None, notes=None):
    document.add_page_break()
    heading_item = document.add_heading(title, level=1)
    heading_item.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph(document, explanation)
    if diagram:
        add_figure(document, DIAGRAMS / diagram, caption)
    if formulas:
        heading(document, "Implemented Formula / Rule", 2)
        add_table(document, ["Formula or rule", "Project meaning"], formulas)
    if notes:
        heading(document, "Project Boundary", 2)
        paragraph(document, notes)


def main():
    document = Document()
    section = document.sections[0]
    section.top_margin = Inches(0.7)
    section.bottom_margin = Inches(0.7)
    section.left_margin = Inches(0.8)
    section.right_margin = Inches(0.8)
    document.styles["Normal"].font.name = "Arial"
    document.styles["Normal"].font.size = Pt(10.5)

    title = document.add_heading("DIGITAL DEFENSE HUB", level=1)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle = document.add_paragraph("Project Flow Diagrams and Implemented Formula Report")
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle.runs[0].bold = True
    paragraph(document, "This document uses only DDH flows represented by the repository architecture and only formulas implemented in the source code. A topic without a mathematical calculation is explicitly described as a workflow/control topic; no artificial formula is added.")

    topic_page(
        document,
        "1. Overall Digital Defense Hub Architecture",
        "The project flow begins in the React/Vite/TypeScript operator console. A protected request reaches the Go REST API, where authentication, RBAC and tenant middleware are applied before a domain service and repository persist or retrieve PostgreSQL data. Media and risk-analysis work is sent through authenticated service calls to the Python FastAPI AI engine. Endpoint/file monitoring contributes normalized events that can later be correlated, scored, linked to evidence and shown through dashboards or notifications. This is a layered, multi-component workflow and not a direct browser-to-database design.",
        "architecture.png",
        "Figure 1: Implemented DDH architecture flow",
        notes="No single architecture formula is implemented. The architecture is defined by authenticated request flow, tenant-aware service/repository access and controlled AI/worker integrations.",
    )
    topic_page(
        document,
        "2. Honeytoken and Canary File Protection Flow",
        "The honeytoken/canary flow starts when an authorized workflow creates or imports a decoy resource. The deployment validates the organization context, target path and metadata. A canary file receives a SHA-256 baseline identity before or during protected deployment. Monitoring observes relevant file activity and matches it to registered protected objects. A detected interaction can then become evidence-linked security context for correlation, risk scoring, incident handling and notification. This design uses deception to make an unexpected interaction more meaningful than a normal business-file event.",
        "canary_flow.png",
        "Figure 2: Honeytoken and canary deployment/monitoring flow",
        [("Hbaseline = SHA-256(B)", "B is the byte sequence of the registered/deployed canary or artifact."), ("IntegrityMatch = 1", "Only if Hstored equals Hcurrent; a mismatch indicates bytes changed, not the cause of the change."), ("Deception score = 100", "Pre-encryption scoring assigns this when a canary trigger or honeytoken access is true."), ("Policy floor = 84", "Canary trigger or honeytoken access can elevate the pre-encryption risk score to at least 84.")],
        "Honeytoken deployment itself is a deception workflow, not a machine-learning model. The project does not claim that a touched decoy identifies a specific attacker without analyst evidence.",
    )
    topic_page(
        document,
        "3. Pre-encryption Ransomware Detection Flow",
        "The Python AI engine receives a validated pre-encryption request containing normalized file, entropy, deception, process and threat-context features together with an upstream rule score. It calculates transparent factor contributions, adds a capped correlation bonus, applies the strongest policy floor and mixes the result with the rule score. The returned assessment contains AI score, combined risk score, risk level, classification, threat probability, confidence, detection stage, active factors and recommended actions. The API endpoint requires a service token and a matching X-Request-ID header/body UUID before processing.",
        "risk_flow.png",
        "Figure 3: Implemented pre-encryption ransomware risk flow",
        [("AI score = clamp(Σ(factor score × weight) + correlation bonus)", "Weights: velocity .18, mass modification .16, entropy .18, rename/extension .14, destructive operations .10, deception .12, suspicious process .06, threat context .06."), ("Combined risk = clamp(0.45 × rule score + 0.55 × AI score)", "The highest applicable policy floor overrides a lower calculated result."), ("Threat probability = 100 / (1 + exp(−(score − 50) / 10))", "The project then applies explicit probability floors for strong encryption/deception combinations."), ("Risk levels", "LOW <25; MEDIUM ≥25; HIGH ≥50; CRITICAL ≥75."), ("Classifications", "BENIGN <25; SUSPICIOUS ≥25; LIKELY_RANSOMWARE ≥60; RANSOMWARE ≥85."), ("Policy floors", "96 encryption activity; 90 mass modification + high entropy; 84 deception; 82 ransomware extension + rapid changes; 72 mass modification + rapid changes.")],
        "This is source-implemented deterministic scoring. It is not reported as an opaque trained ransomware classifier, and its outputs remain decision-support evidence for human review.",
    )
    topic_page(
        document,
        "4. Evidence Integrity and Custody Verification Flow",
        "Evidence integrity starts with the artifact’s SHA-256 identity. The evidence vault creates a canonical manifest that includes artifact and storage references, previous-manifest linkage and signing-key information. The manifest is signed through the project’s Ed25519 mechanism. Verification keeps three separate results: the observed object hash must match the manifest hash, the signature must validate against the relevant verification key, and the previous manifest in the chain must exist when one is declared. The system records the verification result rather than reducing these checks to one unexplained status.",
        "evidence_flow.png",
        "Figure 4: Implemented evidence hash, signature and chain verification flow",
        [("Hartifact = SHA-256(B)", "Computes the byte-level identity of the evidence artifact."), ("Object check", "object_hash_verified is true only when observed SHA-256 equals manifest EvidenceSHA256."), ("Signature check", "signature_verified is true only when Ed25519 manifest verification succeeds with the manifest signing key."), ("Chain check", "chain_verified is true when the required previous manifest SHA-256 exists for the same organization."), ("Custody hash", "The custody event hash is SHA-256 of the canonical serialized custody event including previous_event_hash.")],
        "WORM retention is represented by attestation records. A real immutable-storage guarantee still depends on a correctly configured external object-lock provider.",
    )
    topic_page(
        document,
        "5. Deepfake and Media Forensics Flow",
        "The media-analysis service accepts only supported job/media combinations. Before analyzer dispatch it resolves the source safely, checks that the file size equals the requested size and verifies the requested file hash. It then creates an organization/job-scoped workspace and dispatches to image, video, audio, image-forensics, video-forensics, audio-forensics or OCR analysis. The documented approach is category-aware: Whole-image V4 is retained for modern AI-generated whole-image analysis; Face-swap V2 is retained for FaceForensics-style face manipulation. The service returns a structured success or failure response with runtime, warnings, duration and assessment data.",
        "media_flow.png",
        "Figure 5: Implemented media-forensics job flow",
        [("Input integrity condition", "actual_size = request.file_size_bytes and source hash verification must succeed before analysis."), ("Face applicability rule", "When face boxes are available, a face-swap specialist is applicable when face_area / image_area ≥ 0.02."), ("Specialist selection", "The selected applicable result maximizes (verdict severity, deepfake probability)."), ("Disagreement rule", "If applicable specialists contain both positive and negative verdicts, result becomes SUSPICIOUS and confidence is limited to 60."), ("No universal deepfake equation", "The project uses model/analyzer outputs and category-specific routing; it does not implement one report-level classifier formula.")],
        "Unified V6 remains a legacy candidate requiring fresh validation. The report does not claim unverified model architecture, optimizer, loss function or full manipulation-category coverage.",
    )
    topic_page(
        document,
        "6. Authentication, RBAC and Tenant Flow",
        "A user interacts with the React console, but sensitive operations are enforced by the backend. The request passes authentication/session checks, tenant context middleware and required permission checks before handler/service/repository work accesses data. The AI service separately requires a service token for its health, incident-risk and pre-encryption endpoints. For scoring routes it also requires the X-Request-ID header to contain a valid UUID that exactly matches the request-body request_id. These controls make the request traceable and prevent cross-tenant or uncorrelated processing.",
        "architecture.png",
        "Figure 6: Authentication and tenant-protected API flow",
        [("Authorization condition", "Authenticated/session context AND organization context AND required route permission."), ("AI request condition", "Valid service token AND X-Request-ID header present, valid UUID and equal to request-body request_id."), ("No RBAC score formula", "RBAC is implemented as permission/middleware policy, not a numeric calculation.")],
        "UI hiding is not treated as authorization. The database/service path remains organization scoped so a user cannot access another tenant’s protected data merely by changing a client-side identifier.",
    )
    topic_page(
        document,
        "7. Event Correlation, Notification and Controlled Response Flow",
        "The event-processing design is normalized security event to transactional outbox, worker/retry/dead-letter handling, entity relationship/correlation, threat or incident creation, traceable notification and approved response. This supports ransomware, evidence and forensic workflows without silently losing failed asynchronous work. Recovery actions use a controlled lifecycle: plan, dry-run, approval, execution, verification, rollback and emergency stop. The presence of a recovery adapter does not mean the platform performs an action without required configuration, allowlist and approval controls.",
        "architecture.png",
        "Figure 7: DDH event-to-incident and controlled-response relationship",
        [("Incident overall risk", "Σ(factor score × factor weight), subject to source-implemented policy floor."), ("Integrity risk", "0.35 file activity + 0.25 ransomware behavior + 0.20 evidence integrity + 0.15 threat intelligence + 0.05 incident context."), ("Confidentiality risk", "0.30 incident context + 0.25 threat intelligence + 0.20 deception trigger + 0.15 ransomware behavior + 0.10 evidence integrity."), ("Availability risk", "0.35 ransomware behavior + 0.25 file activity + 0.20 threat intelligence + 0.15 response gap + 0.05 incident context."), ("Review condition", "Human review when overall risk ≥75, threat probability ≥75, data-exposure/ransomware suspicion, tampered evidence, or confidence <60.")],
        "Notifications are linked to source workflow states such as honeytoken/canary alert, analysis completion, evidence-verification status, case assignment or report approval. They are not independent proof of a security incident.",
    )
    document.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()
