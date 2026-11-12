from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "Digital_Defense_Hub_Implemented_Project_Report.docx"
ASSETS = ROOT / "report_diagrams"


def font(size=22, bold=False):
    try:
        return ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf", size)
    except OSError:
        return ImageFont.load_default()


def diagram(name, title, lanes):
    ASSETS.mkdir(exist_ok=True)
    width, height = 1600, 250 + 180 * len(lanes)
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, width, 110), fill="#12355B")
    draw.text((55, 35), title, font=font(34, True), fill="white")
    y = 150
    for index, items in enumerate(lanes):
        x = 70
        box_width = (width - 140 - (len(items) - 1) * 50) // len(items)
        for item_index, item in enumerate(items):
            left, top = x, y
            right, bottom = x + box_width, y + 105
            draw.rounded_rectangle((left, top, right, bottom), radius=18, fill="#E7F0FA", outline="#2563A6", width=3)
            words = item.split()
            lines, line = [], ""
            for word in words:
                candidate = f"{line} {word}".strip()
                if draw.textlength(candidate, font=font(22, True)) > box_width - 28:
                    lines.append(line)
                    line = word
                else:
                    line = candidate
            lines.append(line)
            text_height = len(lines) * 28
            text_y = top + (105 - text_height) / 2
            for line in lines:
                text_width = draw.textlength(line, font=font(22, True))
                draw.text((left + (box_width - text_width) / 2, text_y), line, font=font(22, True), fill="#12355B")
                text_y += 28
            if item_index < len(items) - 1:
                arrow_y = top + 52
                draw.line((right + 8, arrow_y, right + 38, arrow_y), fill="#E05D2F", width=5)
                draw.polygon([(right + 38, arrow_y), (right + 25, arrow_y - 9), (right + 25, arrow_y + 9)], fill="#E05D2F")
            x = right + 50
        if index < len(lanes) - 1:
            draw.line((width / 2, y + 112, width / 2, y + 160), fill="#E05D2F", width=5)
            draw.polygon([(width / 2, y + 160), (width / 2 - 9, y + 145), (width / 2 + 9, y + 145)], fill="#E05D2F")
        y += 180
    target = ASSETS / name
    image.save(target)
    return target


def shade(cell, fill):
    properties = cell._tc.get_or_add_tcPr()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:fill"), fill)
    properties.append(shading)


def set_cell_text(cell, text, bold=False):
    cell.text = ""
    paragraph = cell.paragraphs[0]
    run = paragraph.add_run(str(text))
    run.bold = bold
    run.font.size = Pt(9)
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER


def add_table(document, headers, rows):
    table = document.add_table(rows=1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = "Table Grid"
    for cell, text in zip(table.rows[0].cells, headers):
        shade(cell, "12355B")
        set_cell_text(cell, text, True)
        for run in cell.paragraphs[0].runs:
            run.font.color.rgb = RGBColor(255, 255, 255)
    for row in rows:
        cells = table.add_row().cells
        for cell, text in zip(cells, row):
            set_cell_text(cell, text)
    document.add_paragraph()


def add_bullets(document, values):
    for value in values:
        document.add_paragraph(value, style="List Bullet")


def add_figure(document, image, caption):
    paragraph = document.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.add_run().add_picture(str(image), width=Inches(6.5))
    caption_paragraph = document.add_paragraph(caption)
    caption_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    caption_paragraph.runs[0].italic = True


def add_page_number(section):
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    field = OxmlElement("w:fldSimple")
    field.set(qn("w:instr"), "PAGE")
    footer._p.append(field)


def heading(document, text, level=1):
    paragraph = document.add_heading(text, level=level)
    paragraph.paragraph_format.space_before = Pt(12)
    return paragraph


def main():
    architecture = diagram("architecture.png", "Digital Defense Hub Implemented Architecture", [
        ["React Vite TypeScript Console", "Go REST API and RBAC", "PostgreSQL"],
        ["Endpoint File Events", "Event and Evidence Workflows", "Alerts and Dashboards"],
        ["Media Analysis Job", "Python FastAPI AI Engine", "PyTorch or ONNX Runtime"],
    ])
    canary_flow = diagram("canary_flow.png", "Honeytoken and Canary Protection Flow", [
        ["Create or Import Decoy", "Validate Tenant Path and Type", "SHA-256 Baseline"],
        ["Deploy to Protected Folder", "Monitor File Events", "Alert and Evidence Linkage"],
    ])
    risk_flow = diagram("risk_flow.png", "Pre-Encryption Ransomware Risk Scoring Flow", [
        ["Normalized File Features", "Eight Weighted Factors", "Correlation Bonus and Policy Floor"],
        ["AI Score", "45 Percent Rule + 55 Percent AI", "Risk Level and Recommended Action"],
    ])
    media_flow = diagram("media_flow.png", "Deepfake and Media Forensics Flow", [
        ["Validated Upload", "SHA-256 Evidence Identity", "Asynchronous Analysis Job"],
        ["Metadata Frames Audio OCR", "Category-Aware Model Route", "Result Evidence and Analyst Review"],
    ])
    evidence_flow = diagram("evidence_flow.png", "Evidence Integrity and Custody Verification", [
        ["Evidence SHA-256", "Canonical Manifest", "Ed25519 Signature"],
        ["Object Hash Check", "Signature Check", "Manifest Chain Check"],
    ])

    document = Document()
    section = document.sections[0]
    section.top_margin = Inches(0.7)
    section.bottom_margin = Inches(0.7)
    section.left_margin = Inches(0.8)
    section.right_margin = Inches(0.8)
    add_page_number(section)
    styles = document.styles
    styles["Normal"].font.name = "Arial"
    styles["Normal"].font.size = Pt(10.5)
    for style_name in ("Heading 1", "Heading 2", "Heading 3"):
        styles[style_name].font.name = "Arial"
        styles[style_name].font.color.rgb = RGBColor(18, 53, 91)

    title = document.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.add_run("DIGITAL DEFENSE HUB").bold = True
    title.runs[0].font.size = Pt(23)
    subtitle = document.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle.add_run("Honeytoken and Canary File Deployment for Ransomware Detection\nand Deepfake Forensic Authentication Suite").bold = True
    subtitle.runs[0].font.size = Pt(16)
    document.add_paragraph()
    statement = document.add_paragraph("IMPLEMENTED PROJECT REPORT")
    statement.alignment = WD_ALIGN_PARAGRAPH.CENTER
    statement.runs[0].bold = True
    statement.runs[0].font.size = Pt(14)
    document.add_paragraph("Prepared from the supplied project report format and verified against the current Digital Defense Hub source repository. This document intentionally includes only implemented or source-confirmed project details.").alignment = WD_ALIGN_PARAGRAPH.CENTER
    document.add_page_break()

    heading(document, "Abstract")
    document.add_paragraph("Digital Defense Hub is a multi-tenant cyber-security and digital-forensics platform. It combines deception-based ransomware detection, evidence integrity controls, security-event workflows, and media-forensic analysis. The web console uses React, Vite and TypeScript; the core REST service is implemented in Go; PostgreSQL stores tenant-scoped data; and a Python FastAPI AI engine performs scoring and media analysis. Implemented detection inputs include canary and honeytoken interaction, file modification, rename and extension-change activity, entropy-related features, destructive file operations, suspicious processes and existing threat context. Media analysis validates and registers uploaded artifacts, preserves a SHA-256 identity, then routes work through the project’s analysis paths and available model runtime. The report describes only the modules, formulas, techniques and limitations verified in the repository.")

    heading(document, "Contents")
    add_table(document, ["Chapter", "Title"], [
        ["1", "Introduction"], ["2", "Survey of Technologies"], ["3", "Requirements and Analysis"],
        ["4", "System Design"], ["5", "Implementation and Testing"], ["6", "Results and Discussion"],
        ["7", "Conclusion"], ["", "References"],
    ])
    document.add_page_break()

    heading(document, "CHAPTER 1: INTRODUCTION")
    heading(document, "1.1 Background", 2)
    document.add_paragraph("Ransomware can modify, rename, delete or encrypt files at speed. Manipulated images, video and audio can also affect digital investigations. Digital Defense Hub brings these two project areas together: the platform observes suspicious file behaviour using deception resources and preserves or analyses media artifacts within the same tenant-aware investigation environment.")
    heading(document, "1.2 Objectives", 2)
    add_bullets(document, [
        "Deploy and monitor honeytokens and canary files for high-signal ransomware indicators.",
        "Score pre-encryption ransomware behaviour from normalized file and threat features.",
        "Preserve evidence identity, manifest, signature and custody verification information.",
        "Run supported media-forensic analysis through a controlled, category-aware pipeline.",
        "Provide authenticated, role-based and tenant-scoped security workflows.",
    ])
    heading(document, "1.3 Scope", 2)
    document.add_paragraph("The report covers the implemented platform paths: authentication and tenant controls; honeytoken/canary protection; normalized security events; pre-encryption scoring; evidence vault verification; media/deepfake analysis; incident and recovery workflows; dashboards and notifications. A configured external provider or adapter is not claimed as operational unless its service is deployed and configured.")

    heading(document, "CHAPTER 2: SURVEY OF TECHNOLOGIES")
    add_table(document, ["Layer", "Technology confirmed in project", "Use"], [
        ["Frontend", "React, Vite, TypeScript", "Operator console, dashboards and API-driven module workspaces."],
        ["Backend", "Go, Gin-style REST APIs", "Validation, RBAC, tenant context, workflows, repositories and workers."],
        ["Data", "PostgreSQL", "Tenant-scoped application, event, evidence, incident and workflow persistence."],
        ["AI service", "Python, FastAPI", "Risk scoring, media analysis and controlled training routes."],
        ["Model runtime", "PyTorch, ONNX Runtime", "Execution of available media-forensic model assets."],
        ["Integrity", "SHA-256, Ed25519", "Artifact identity, manifest signing, verification and custody records."],
        ["Monitoring", "Windows-oriented watcher/sentinel logic", "Canary/file event observation and local alert buffering where configured."],
    ])
    heading(document, "2.1 Techniques Used", 2)
    add_bullets(document, [
        "Cyber deception using registered honeytokens and canary files.",
        "File-system event normalization and multi-signal ransomware correlation.",
        "Weighted deterministic scoring, correlation bonuses and policy escalation floors.",
        "Category-aware media-forensic routing instead of assuming one universal deepfake model.",
        "SHA-256 hashes, canonical manifests, Ed25519 signatures and custody hash chaining.",
        "JWT authentication, RBAC, tenant isolation, transactional outbox, retries and dead-letter handling.",
    ])

    heading(document, "CHAPTER 3: REQUIREMENTS AND ANALYSIS")
    heading(document, "3.1 Functional Requirements Implemented", 2)
    add_table(document, ["Area", "Implemented requirement"], [
        ["Identity", "Login, MFA-related workflows, session/password lifecycle, JWT validation and RBAC."],
        ["Tenant protection", "Organization-scoped access and tenant-aware data queries."],
        ["Deception", "Honeytoken/canary deployment, integrity baseline, monitoring and trigger linkage."],
        ["Events", "Normalized security-event intake, idempotency, outbox, retry, dead-letter and replay support."],
        ["Forensics", "Media upload validation, SHA-256 identity, metadata, image/video/audio/OCR analysis paths and evidence records."],
        ["Evidence", "Manifest creation, signature verification, object-hash check, chain check and WORM attestation records."],
        ["Response", "Dry-run, approval, execution, verification, rollback and emergency-stop workflow states."],
    ])
    heading(document, "3.2 Non-functional Requirements Implemented", 2)
    add_bullets(document, [
        "Security: least privilege, input validation, tenant isolation and protected API access.",
        "Reliability: idempotency, bounded retries, stale-job recovery and dead-letter handling.",
        "Integrity and auditability: hashes, signatures, custody records, request IDs and actor attribution.",
        "Maintainability: modular backend packages, service/repository separation, migrations and automated tests.",
    ])

    heading(document, "CHAPTER 4: SYSTEM DESIGN")
    heading(document, "4.1 Architecture", 2)
    document.add_paragraph("The normal request path is React console → Go REST API → authentication/RBAC/tenant middleware → domain service/repository → PostgreSQL. Media jobs are sent from the backend to the authenticated Python FastAPI service. Security events can pass through transactional outbox and worker processing before correlation, incident linkage, notification or approved response handling.")
    add_figure(document, architecture, "Figure 4.1: Implemented Digital Defense Hub architecture")
    heading(document, "4.2 Core Modules", 2)
    add_table(document, ["Module", "Implemented design"], [
        ["Honeytoken deployment", "Registers decoy resources in monitored locations with tenant and deployment metadata."],
        ["Canary protection", "Creates/imports a sentinel artifact, records SHA-256 baseline and watches later changes."],
        ["File monitoring", "Normalizes modification, rename, delete, extension, hash and permission-related signals when available."],
        ["Pre-encryption detection", "Calculates deterministic weighted risk from file behaviour, deception, process and threat-context features."],
        ["Media forensics", "Validates media, records identity and performs modality-specific analysis plus category-aware model execution."],
        ["Evidence vault", "Creates signed manifests and verifies object hash, signature and manifest-chain status."],
        ["Security operations", "Correlates events/entities, supports incidents, notifications and controlled recovery workflows."],
    ])
    heading(document, "4.3 Honeytoken and Canary Flow", 2)
    document.add_paragraph("Honeytokens and canary files are deception resources. The file is created or imported, validated against tenant/path/type rules, assigned a baseline identity, deployed to an approved protected location and monitored. A later interaction or change can become an evidence-linked security signal.")
    add_figure(document, canary_flow, "Figure 4.2: Honeytoken and canary protection flow")
    heading(document, "4.4 Pre-encryption Risk Scoring", 2)
    document.add_paragraph("The AI engine implements deterministic pre-encryption scoring. Each non-zero factor contributes factor score × factor weight. The weighted factors are file-change velocity (0.18), mass file modification (0.16), entropy transformation (0.18), rename/extension pattern (0.14), destructive operations (0.10), deception interaction (0.12), suspicious process behaviour (0.06), and existing threat context (0.06).")
    document.add_paragraph("AI score = clamp(sum of factor contributions + correlation bonus). Combined risk score = clamp((rule score × 0.45) + (AI score × 0.55)). The correlation bonus is capped at 30. Policy floors override a lower calculated score: encrypted-file activity 96; mass modification with high-entropy writes 90; canary/honeytoken interaction 84; ransomware extension with rapid file changes 82; mass modification with rapid changes 72.")
    document.add_paragraph("Threat probability = 100 / (1 + exp(−(combined risk score − 50) / 10)). Project rules can raise that probability to at least 98 for confirmed encryption activity, 92 for canary/honeytoken activity, or 94 for high-entropy writes together with mass modification. Risk levels are LOW below 25, MEDIUM from 25, HIGH from 50 and CRITICAL from 75. Classifications are BENIGN below 25, SUSPICIOUS from 25, LIKELY_RANSOMWARE from 60 and RANSOMWARE from 85.")
    add_figure(document, risk_flow, "Figure 4.3: Implemented pre-encryption ransomware scoring flow")
    heading(document, "4.5 Evidence Integrity Formula", 2)
    document.add_paragraph("For each artifact byte sequence B, the platform records H = SHA-256(B). Object integrity is successful only when the observed SHA-256 equals the manifest evidence SHA-256. The evidence verification endpoint separately records object-hash status, Ed25519 manifest-signature status and previous-manifest-chain status. Custody events use SHA-256 of their canonical serialized event representation, including the previous event hash.")
    add_figure(document, evidence_flow, "Figure 4.4: Evidence integrity and custody verification flow")
    heading(document, "4.6 Media Forensics Flow", 2)
    document.add_paragraph("A supported artifact is validated for its allowed media attributes, registered with a SHA-256 identity, and handled as an analysis job. The AI service has image, video, audio and OCR paths with metadata and forensic feature handling. The documented model-selection approach is category-aware: Whole-image V4 is retained for modern AI-generated whole-image analysis and Face-swap V2 for FaceForensics-style face manipulation. Unified V6 is a legacy candidate requiring fresh validation and is not presented as an active universal detector.")
    add_figure(document, media_flow, "Figure 4.5: Implemented deepfake and media-forensics flow")

    heading(document, "CHAPTER 5: IMPLEMENTATION AND TESTING")
    heading(document, "5.1 Implementation Approach", 2)
    document.add_paragraph("The Go backend organizes routes, handlers, service rules, repositories and workers. The React interface calls protected APIs. PostgreSQL persists organizations, events, evidence and cases. The Python FastAPI engine exposes authenticated scoring and media-analysis routes. The repository includes tests for scoring, forensic functions, evidence crypto and backend API/workflow components.")
    heading(document, "5.2 Project-specific Test Cases", 2)
    add_table(document, ["Test ID", "Input / action", "Expected project result"], [
        ["TC-01", "Deploy a canary to an approved path.", "Baseline SHA-256 and deployment metadata are stored."],
        ["TC-02", "Modify or delete a registered canary.", "A high-signal detection/evidence path is available for correlation."],
        ["TC-03", "Submit normalized file-event features.", "The pre-encryption engine returns factor scores, risk level, classification and actions."],
        ["TC-04", "Provide canary/honeytoken interaction.", "Deception factor is set and the policy floor can raise risk to at least 84."],
        ["TC-05", "Upload a supported media artifact.", "Validation and SHA-256 identity occur before analysis processing."],
        ["TC-06", "Verify an evidence manifest with observed hash.", "Object hash, signature and chain verification statuses are recorded."],
        ["TC-07", "Attempt a cross-tenant protected request.", "Tenant/RBAC middleware denies unauthorized access."],
    ])
    heading(document, "5.3 Known Project Boundaries", 2)
    add_bullets(document, [
        "Read-only file access depends on the configured Windows audit source; a basic watcher does not guarantee every read event.",
        "A risk score is a decision-support output, not proof of ransomware by itself; the project keeps evidence and review workflows.",
        "Deepfake results are model/category dependent. Unsupported or unvalidated categories are not claimed as covered.",
        "WORM guarantees require correctly configured external object-lock storage; the repository records WORM attestations but cannot guarantee an unconfigured provider.",
    ])

    heading(document, "CHAPTER 6: RESULTS AND DISCUSSION")
    document.add_paragraph("The implemented design produces traceable outputs instead of an isolated alert. File and deception signals can be normalized, scored and linked to evidence or incident workflows. The pre-encryption result contains factor-level contributions, combined risk, threat probability, confidence, detection stage, classification and recommended actions. Media analysis retains its original artifact identity and routes analysis according to modality and model applicability. Evidence verification exposes separate hash, signature and chain checks so a failed verification can be distinguished from a simple missing result.")
    add_table(document, ["Output", "Project meaning"], [
        ["Canary/honeytoken signal", "A decoy-resource interaction with tenant and evidence context."],
        ["Pre-encryption assessment", "A deterministic risk assessment with explainable factor contributions."],
        ["Media-forensics result", "An analysis job result tied to validated source artifact and model/runtime path."],
        ["Evidence verification", "Object hash, manifest signature and chain verification states."],
        ["Security workflow record", "Correlated event, threat, incident, notification or approved response state."],
    ])

    heading(document, "CHAPTER 7: CONCLUSION")
    heading(document, "7.1 Conclusion", 2)
    document.add_paragraph("Digital Defense Hub integrates ransomware-oriented deception, deterministic pre-encryption scoring, media forensics and evidence integrity under one tenant-aware platform. Its main strength is that detection, forensic output and evidence verification are connected through shared workflows. The report has restricted itself to the current source-confirmed implementation, including exact risk-score weights, thresholds, cryptographic checks and model applicability statements.")
    heading(document, "7.2 Limitations and Future Work", 2)
    document.add_paragraph("Future work must be treated as future work: deploy and configure external provider adapters, validate legacy deepfake candidates on fresh holdout data, improve audit coverage for read-only file access where needed, and conduct deployment-specific capacity and performance testing. These items are not represented as completed features in this report.")

    heading(document, "References")
    add_bullets(document, [
        "Project source: README.md and docs/DDH_PROJECT_THESIS_REFERENCE.md.",
        "Project source: docs/PROJECT_ARCHITECTURE_AND_REQUIREMENTS_THANGGLISH.md.",
        "Project source: ai-engine/app/pre_encryption_scoring.py and ai-engine/app/scoring.py.",
        "Project source: backend-go/internal/evidencevault/.",
        "Project source: docs/DEEPFAKE_ENSEMBLE_COVERAGE_AUDIT.md.",
        "Supplied format reference: project report (1).pdf.",
    ])

    document.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()
