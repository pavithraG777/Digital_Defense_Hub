from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt

from generate_implemented_project_report import add_bullets, add_figure, add_table, heading


ROOT = Path(__file__).resolve().parent
BASE = ROOT / "Digital_Defense_Hub_Implemented_Project_Report.docx"
OUTPUT = ROOT / "Digital_Defense_Hub_Detailed_Implemented_Project_Report.docx"
DIAGRAMS = ROOT / "report_diagrams"


def paragraph(document, value):
    item = document.add_paragraph(value)
    item.paragraph_format.space_after = Pt(7)


def page_title(document, value):
    title = document.add_heading(value, level=1)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER


def module_pages(document, number, name, purpose, inputs, page_one, page_two, flow, techniques, outputs, tests, formula_rows=None, diagram=None):
    document.add_page_break()
    page_title(document, f"DETAILED MODULE {number}: {name} — PAGE 1")
    heading(document, f"{number}.1 Purpose and Project Boundary", 2)
    paragraph(document, purpose)
    heading(document, f"{number}.2 Inputs and Validation", 2)
    add_table(document, ["Input", "Project handling"], inputs)
    heading(document, f"{number}.3 Processing Flow", 2)
    for item in page_one:
        paragraph(document, item)
    add_bullets(document, [f"Step {index + 1}: {item}" for index, item in enumerate(flow)])
    if diagram:
        add_figure(document, diagram, f"Detailed flow for Module {number}: {name}")

    document.add_page_break()
    page_title(document, f"DETAILED MODULE {number}: {name} — PAGE 2")
    heading(document, f"{number}.4 Techniques Used", 2)
    add_bullets(document, techniques)
    heading(document, f"{number}.5 Outputs and Evidence", 2)
    add_table(document, ["Output", "Meaning in this project"], outputs)
    if formula_rows:
        heading(document, f"{number}.6 Implemented Formula / Decision Rules", 2)
        add_table(document, ["Formula or rule", "Meaning"], formula_rows)
    heading(document, f"{number}.7 Testing and Boundaries", 2)
    for item in page_two:
        paragraph(document, item)
    add_table(document, ["Test", "Expected result"], tests)


def main():
    if not BASE.exists():
        raise FileNotFoundError(f"Generate the base report first: {BASE}")
    document = Document(BASE)
    for section in document.sections:
        section.top_margin = Inches(0.7)
        section.bottom_margin = Inches(0.7)

    document.add_page_break()
    page_title(document, "EXPANDED IMPLEMENTED MODULE DOCUMENTATION")
    paragraph(document, "This expanded section is added to the project report so that every core project module has a separate, detailed two-page explanation. The material is written only from the repository implementation and its project documentation. A formula is included only where the source code implements it. Where no formula is implemented, the section states that explicitly instead of adding a theoretical formula.")
    add_table(document, ["Module", "Two-page coverage"], [
        ["1. Honeytoken deployment", "Deployment context, validation, decoy technique, event linkage and output."],
        ["2. Canary file protection", "Baseline hash, integrity verification, monitored changes and evidence."],
        ["3. File monitoring", "Normalization, event attributes, detection inputs and reliable-audit boundary."],
        ["4. Pre-encryption ransomware scoring", "All implemented factor equations, weights, policy floors and thresholds."],
        ["5. Deepfake and media forensics", "Supported job paths, category-aware selection and safe ensemble handling."],
        ["6. Role-based dashboard and tenant control", "JWT/RBAC/tenant authorization and live workspace data flow."],
        ["7. Notification, incident and response flow", "Event-driven records, retries, correlation and controlled recovery states."],
    ])

    module_pages(
        document, "1", "Honeytoken Deployment",
        "The HoneyToken module deploys and registers decoy resources as a deception layer. The project does not use a machine-learning model to deploy a honeytoken. Its protection value comes from the fact that a registered decoy should not normally be accessed during ordinary work. The deployment record gives later file or security events a high-value relationship to a known protected object, tenant and location.",
        [("Organization / tenant", "The request is processed in organization context so one tenant cannot deploy or view another tenant’s decoys."), ("Deployment path", "The workflow validates the deployment target against permitted and safe location rules before use."), ("Decoy metadata", "The resource is registered with deployment state and identifying metadata for later monitoring."), ("User / permission", "The backend route and service workflow apply authenticated, role-based access before a protected action.")],
        [
            "A honeytoken is a controlled decoy resource, not a normal production asset. The system stores enough context to decide that a later interaction is relevant to a security investigation. This avoids treating every normal file action as a high-severity finding.",
            "Deployment is tenant-aware. The tenant identifier, deployment metadata and protected location allow a received security event to be associated with its owner organization. This matches the project’s general rule that sensitive records and queries are organization scoped.",
            "The implementation can link a decoy interaction to threat and incident workflows. The later event is more useful than an anonymous log entry because the platform can retain endpoint, actor/process, path, time and evidence references when they are available.",
            "The deployment technique is intentionally deterministic. It does not claim that the system can prove an attacker identity merely because a honeytoken was touched. The signal is used as evidence and as a high-value input to correlation and scoring.",
        ],
        [
            "There is no independent honeytoken score equation in the deployment module. In the pre-encryption scorer, a confirmed honeytoken access is represented as a deception interaction and can contribute to a risk score and policy escalation.",
            "The deployment itself must remain controlled. A deployment outside approved paths is a validation failure, not an automatic security event. This distinction prevents unsafe or untraceable decoys from entering the monitored inventory.",
        ],
        ["Create or register decoy", "Validate path and tenant context", "Store deployment metadata", "Monitor for interaction", "Link event to evidence, threat or incident"],
        ["Cyber-deception using controlled decoy resources.", "Tenant-scoped deployment and access checks.", "Registered-object matching during event processing.", "Evidence-first linkage of alert context rather than a standalone notification."],
        [("Deployment record", "Identity, tenant, path and lifecycle context for the decoy."), ("Interaction signal", "A high-value event when a monitored decoy is accessed or modified."), ("Linked evidence", "Supporting records that allow an analyst to inspect the relevant event."), ("Correlation input", "A deception feature usable by risk and incident workflows.")],
        [("Deploy to approved directory", "Deployment record is created with organizational context."), ("Deploy to disallowed location", "The unsafe request is rejected before an untracked decoy is created."), ("Receive decoy interaction event", "The event is available for evidence/threat/incident linkage.")],
        [("No standalone ML formula", "Honeytoken deployment is a rule and workflow-based deception control."), ("Deception score = 100", "Pre-encryption scoring sets this when has_canary_trigger or has_honeytoken_access is true."), ("Policy floor = 84", "A canary trigger or honeytoken access can force the pre-encryption score to at least 84.")],
        DIAGRAMS / "canary_flow.png",
    )

    module_pages(
        document, "2", "Canary File Creation and Integrity Protection",
        "The canary module creates or imports a normal-looking sentinel file, registers it, and preserves a baseline identity. It is both a deception technique and an integrity-monitoring technique. An unexpected change becomes a high-value signal because the file was deliberately placed in a protected/monitored context rather than being an ordinary user document.",
        [("Canary source", "A new or imported file becomes a managed protected artifact."), ("Approved path", "The path is validated before deployment to a protected location."), ("File bytes", "The bytes are used to calculate a baseline SHA-256 identity."), ("Deployment metadata", "State, tenant and location are retained for later health and trigger checks.")],
        [
            "Before a deployed canary is relied on as evidence, the project records its baseline hash. This baseline describes the exact byte sequence at registration/deployment time. It does not interpret the content; it gives a repeatable identity check.",
            "After the file is copied or placed into an approved directory, the project can verify that the deployed object matches the expected baseline. A mismatch means the current byte sequence differs from the recorded sequence. The mismatch alone does not state why the change happened; analyst context and associated file events are still needed.",
            "Canary changes may be caused by modification, rename, deletion, extension change or related file activity. The monitoring and pre-encryption paths use this context as a strong deception indicator, while evidence records preserve the event details for investigation.",
            "The canary workflow works with the broader evidence vault pattern. Evidence identity and later verification are kept separate from the decision workflow: first the platform records what was observed; then it correlates, scores and presents actions.",
        ],
        [
            "The project’s direct integrity formula is SHA-256 over the original bytes. It does not use a fabricated file-content classifier to decide whether a canary was changed. SHA-256 comparison only answers whether the observed byte sequence matches the stored baseline.",
            "Canary interaction affects the pre-encryption engine. The scoring code can require human review even when the combined score is below the standard review threshold, because a canary trigger is treated as a special high-value condition.",
        ],
        ["Create or import sentinel file", "Validate metadata and protected path", "Calculate and retain SHA-256 baseline", "Deploy and verify copy", "Monitor and preserve later change evidence"],
        ["Sentinel-file/canary technique.", "SHA-256 baseline identity and comparison.", "Protected-path and tenant validation.", "Evidence linkage for detected changes.", "Correlation with pre-encryption ransomware signals."],
        [("Baseline hash", "Stored SHA-256 value for the original registered/deployed bytes."), ("Health/deployment state", "Tracks whether the protected file is active and available."), ("Change signal", "An event indicating unexpected interaction with the canary."), ("Evidence item", "Artifact/event context retained for verification and investigation.")],
        [("Create and deploy canary", "Baseline hash and deployment state are retained."), ("Verify unchanged file", "Current digest equals stored digest; integrity match succeeds."), ("Alter file and verify", "Current digest differs; integrity mismatch is recorded."), ("Trigger canary in controlled test", "High-value deception context enters the detection workflow.")],
        [("Hbaseline = SHA-256(B)", "B is the registered canary byte sequence."), ("IntegrityMatch = 1", "Only when Hstored equals Hcurrent; otherwise the result is 0."), ("Endpoint isolation condition", "Pre-encryption engine requests isolation when canary trigger is true, independent of score."), ("Human-review condition", "Pre-encryption engine requires review when canary trigger is true.")],
        DIAGRAMS / "canary_flow.png",
    )

    module_pages(
        document, "3", "File Monitoring and Event Normalization",
        "The file-monitoring area receives file-system or audit observations and turns them into normalized security context. The implementation uses the resulting features in detection, correlation and evidence workflows. It does not claim that one isolated rename or one file open proves ransomware. The platform uses event context, registered-object matching and multi-event behaviour signals.",
        [("File event type", "Modification, rename, delete, extension change, hash change, permission change and other supported attributes are normalized."), ("Time and endpoint", "Available timestamp and endpoint information identify where and when activity occurred."), ("Path / file identity", "Used for protected-object matching and evidence linkage."), ("Process / actor context", "Attached when the source provides reliable process or user information."), ("Tenant context", "Prevents cross-organization linking and keeps later findings scoped.")],
        [
            "The normalized security-event foundation uses event identity, schema versions, idempotency controls, outbox processing and retry/dead-letter handling. These techniques help prevent an event pipeline from creating duplicate or silently lost records when work is asynchronous or when a processor fails.",
            "A file event can be linked to entities such as endpoint, account, process, file, network indicator or incident. The correlation layer can then form relationship records, timelines and attack-story versions. This approach preserves the reason a finding exists instead of presenting an unexplained alert.",
            "The pre-encryption scorer consumes aggregated feature values rather than raw unstructured logs. Examples include event rate per minute, number of modified/renamed/deleted files, ratios, high-entropy writes, suspicious process counts, canary/honeytoken flags and existing threat scores.",
            "Read-only access has an explicit boundary. A Windows source may need audit/SACL or kernel-level support to reliably expose every read-only open. The report therefore lists an open/read event only when the deployed event source provides it; it is not guaranteed by a basic watcher.",
        ],
        [
            "The monitoring module has no standalone neural-network equation. Its measurable values become inputs to deterministic pre-encryption and incident risk algorithms. This makes the decision path explainable: a returned risk factor describes which observable activity contributed to the result.",
            "The project uses event processing reliability patterns: a transactional outbox connects data change and later work publication; workers make bounded retries; a dead-letter queue retains poison or repeatedly failing work; and replay/checkpoint handling supports recovery.",
        ],
        ["Capture source event", "Validate and normalize fields", "Apply identity/idempotency rules", "Match tenant and protected objects", "Persist/link/correlate through worker workflow"],
        ["File-system/audit event monitoring.", "Schema-versioned normalization.", "Idempotency and unique identity constraints.", "Transactional outbox, workers, retry and dead-letter queue.", "Entity graph and timeline correlation."],
        [("Normalized event", "A consistent, tenant-scoped representation of file/security activity."), ("Feature aggregates", "Counts, ratios, rates and boolean signals sent to scoring."), ("Entity links", "Relationships among files, devices, identities, processes and incidents."), ("Evidence/correlation record", "Traceable context for later analyst review.")],
        [("Receive duplicate event", "Idempotency/identity handling prevents duplicate processing."), ("Rename ordinary file", "Event is recorded; it is not automatically labelled ransomware."), ("Capture burst and deception event", "Feature values and relationships are available for scoring/correlation."), ("Worker failure", "Retry path is used; repeated failure can be retained in dead-letter handling.")],
        [("Velocity score base", "clamp((event_rate_per_minute / 60) × 100)."), ("Modification score base", "clamp(((modified_event_count + multiple_file_change_event_count) / 20) × 100)."), ("Rename score inputs", "Uses max(rename_ratio, extension_change_ratio) × 100 and count-based values."), ("No single-event declaration", "A normal file rename alone is an event input, not a confirmed ransomware verdict.")],
        DIAGRAMS / "risk_flow.png",
    )

    module_pages(
        document, "4", "Pre-encryption Ransomware Behaviour Detection",
        "This is the project’s implemented deterministic scoring engine for ransomware-oriented pre-encryption behaviour. It is named DDH_PRE_ENCRYPTION_RANSOMWARE_DETECTOR, version 1.0.0, policy version 2026.07. The engine accepts normalized features and a rule score, calculates transparent weighted contributions, applies correlation/policy rules, and returns a risk classification, confidence, threat probability and recommended actions.",
        [("Rule score", "An upstream rule-based score combined at 45 percent in the final score."), ("File activity", "Event rate, modification, rename, extension, deletion, hash and permission measures."), ("Entropy data", "High-entropy write count, average entropy after and entropy delta when available."), ("Deception features", "Canary trigger, honeytoken access and protected-file activity."), ("Process/threat features", "Suspicious process indicators, existing maximum threat score and suspicious-event ratio.")],
        [
            "The engine first calculates individual factor scores, clamps scores to 0–100 and creates contributions. A factor with a zero score is not added as a positive risk factor. This makes the returned explanation show only active contributing factors plus any special escalation factors.",
            "File-change velocity starts with event_rate_per_minute / 60 × 100. Rapid file changes force at least 65; any multiple-file-change count above zero forces at least 80. Mass modification uses the larger of the count-based score and modification ratio; the mass-modification flag forces at least 78.",
            "Entropy transformation starts at zero. High-entropy writes force at least 72 or their event ratio score, whichever is larger. If average entropy after is available it uses average_entropy_after / 8 × 100; if entropy delta is available it uses average_entropy_delta / 2.5 × 100. The largest available result is retained.",
            "Rename/extension behaviour uses the largest of ratio-based, renamed-count and extension-changed-count scores. A ransomware extension forces at least 95. Destructive operations use the largest of deletion, hash-change, permission-change and corresponding ratio measures. These details are source-code rules, not general theoretical estimates.",
        ],
        [
            "The correlation bonus adds independent behaviours but is capped at 30: mass modification plus high entropy adds 16; rapid changes plus extension burst adds 10; rapid rename plus ransomware extension adds 10; suspicious process plus deletion/permission burst adds 8; canary/honeytoken adds 12; confirmed encryption adds 20.",
            "The source implements policy floors as high-priority safety rules. A floor supersedes a lower calculated score. This avoids a dangerous result where a strong explicit encryption or deception signal is hidden by a lower average of other features.",
            "This engine is deterministic and explainable. It is not described as a trained ransomware classifier. The output supports investigation and response; it is not a substitute for human evidence review.",
        ],
        ["Validate normalized request", "Calculate factor scores and contributions", "Add capped correlation bonus", "Apply highest policy floor", "Mix rule and AI scores", "Return classification, actions and review/isolation flags"],
        ["Weighted deterministic feature scoring.", "Score clamping to 0–100.", "Multi-signal correlation bonus.", "Policy escalation floor.", "Logistic threat-probability transformation.", "Risk classification and explainable action selection."],
        [("AI score", "Weighted factor contribution total after bonus/floor processing."), ("Combined risk", "45 percent rule score plus 55 percent AI score, subject to policy floor."), ("Threat probability", "Logistic probability with high-confidence signal floors."), ("Confidence", "Evidence sufficiency indicator from event, file, factor and special-signal data."), ("Actions", "Monitoring, evidence preservation, investigation or isolation recommendations.")],
        [("High entropy + mass modification", "Correlation and policy floor are applied; critical risk can result."), ("Canary/honeytoken flag", "Deception score, review and isolation conditions are activated."), ("Score below 25", "LOW/BENIGN path continues monitoring."), ("Score at least 75", "CRITICAL risk level and endpoint-isolation condition are set."), ("Confirmed encryption", "Detection stage is ENCRYPTION_CONFIRMED and policy floor is 96.")],
        [("AI = clamp(Σ(scorei × weighti) + correlation_bonus)", "Weights: velocity .18, modification .16, entropy .18, rename .14, destructive .10, deception .12, process .06, threat context .06."), ("Combined = clamp(0.45 × Rule + 0.55 × AI)", "The highest policy floor overrides a lower combined score."), ("P = 100 / (1 + exp(−(Score − 50) / 10))", "Threat probability before project-specific floors."), ("Confidence = 40 + min(events/30×20,20) + min(unique_files/20×15,15) + min(factors×3,15) + applicable bonuses", "Confidence is clamped to 20–99; a single weak event can subtract 15."), ("Risk thresholds", "LOW <25; MEDIUM ≥25; HIGH ≥50; CRITICAL ≥75. Classification: BENIGN <25; SUSPICIOUS ≥25; LIKELY_RANSOMWARE ≥60; RANSOMWARE ≥85."), ("Policy floors", "96 encryption activity; 90 mass modification + high entropy; 84 deception interaction; 82 ransomware extension + rapid changes; 72 mass modification + rapid changes.")],
        DIAGRAMS / "risk_flow.png",
    )

    module_pages(
        document, "5", "Deepfake and Digital-media Forensics",
        "The media-forensics component runs validated offline analysis jobs for image, video, audio and OCR-related requests. It verifies the source path, file size and provided file hash before analysis. It prepares a job workspace, dispatches to the matching analyzer, records runtime/warnings and returns deepfake, forensic or OCR assessment data. The project uses category-aware model selection rather than claiming one detector is correct for all media types.",
        [("Job type", "Only supported job/media combinations are accepted: image, video, audio, forensics or OCR paths."), ("Media type", "Validated against the job’s allowed media set before dispatch."), ("Source path and size", "Resolved through the runtime and checked against the request’s expected file size."), ("File hash", "The actual source is hash-verified before processing."), ("Execution request", "Job, organization, model(s), workspace and optional visualization settings direct analysis.")],
        [
            "The service has explicit job mappings. Image deepfake and AI-generated-image detection accept IMAGE; video deepfake accepts VIDEO; audio deepfake accepts AUDIO; image/video/audio forensics follow their matching media type; OCR accepts IMAGE, VIDEO and DOCUMENT. An unsupported mismatch returns a controlled analysis error instead of attempting an invalid model path.",
            "The analyzer creates a per-organization/job workspace and output directories. This prevents loose temporary output from being mixed across analysis jobs. Runtime errors are returned in a structured response with success=false, an error code/message and measured processing duration.",
            "For an image deepfake job, the service can run one model or multiple supplied models. The implementation keeps model component results, their verdicts, probabilities, confidence and thresholds. A face-swap specialist is applied only when the source assessment is face-applicable; this is a category-aware safety condition.",
            "When applicable specialized image models disagree, one reports deepfake/likely-deepfake and another authentic/likely-authentic, the project does not invent a false consensus. It sets the displayed result to SUSPICIOUS, limits confidence to 60 and requires human review in the returned summary.",
        ],
        [
            "Project documentation identifies Whole-image V4 as the specialist retained for modern AI-generated images and Face-swap V2 for FaceForensics-style face manipulation. Unified V6 is retained as a legacy candidate requiring fresh holdout validation. The report does not claim a particular CNN architecture, optimizer or loss because those details are not verified in the required project implementation evidence.",
            "The output is forensic context, not certainty. Metadata, frame extraction, audio analysis, OCR and model results are linked to the submitted artifact identity so an investigator can review the supporting material. Analysis failures return structured failures rather than silently producing a result.",
        ],
        ["Validate job/media compatibility", "Resolve source safely", "Verify size and SHA-256", "Prepare scoped workspace", "Dispatch to image/video/audio/OCR analyzer", "Record result, warnings and duration"],
        ["Authenticated/validated media analysis jobs.", "Size and file-hash verification before inference.", "Per-organization/job workspace isolation.", "Image/video/audio/OCR modality dispatch.", "Category-aware specialist selection.", "Ensemble disagreement downgraded to SUSPICIOUS with human review."],
        [("Analysis response", "Success/failure, duration, runtime and unique warning list."), ("Deepfake assessment", "Model path output with verdict, probability, confidence, signals and feature data."), ("Forensics assessment", "Image/video/audio forensic result for the applicable job."), ("OCR assessment", "Extracted-text analysis result for image, video or document input."), ("Visualization/output files", "Optional job-scoped artifacts generated in the analysis workspace.")],
        [("Image job with VIDEO media", "Compatibility validation rejects the request."), ("Hash mismatch", "Source verification fails before analysis."), ("Image ensemble agreement", "Highest-risk applicable specialist result is selected with component evidence."), ("Image ensemble disagreement", "Result becomes SUSPICIOUS and confidence is capped at 60."), ("Unsupported job type", "Controlled media runtime error is returned.")],
        [("Source integrity condition", "actual_size = request.file_size_bytes and verify_file_hash(source, request.file_hash) must succeed."), ("Face applicability area rule", "A detected face is applicable when face_area / image_area ≥ 0.02, when bounding-box data is available."), ("Ensemble selection", "Select applicable assessment with maximum (severity, deepfake_probability)."), ("Disagreement rule", "Positive verdict plus negative verdict among applicable specialists => SUSPICIOUS, confidence ≤60."), ("No universal deepfake formula", "Source uses analyzer/model output and specialist-routing rules, not one report-level probability equation.")],
        DIAGRAMS / "media_flow.png",
    )

    module_pages(
        document, "6", "Role-based Dashboard, Authentication and Tenant Isolation",
        "The operator interface is implemented with React, Vite and TypeScript and connects to protected backend APIs. It is not a collection of separate applications for each role. Instead, the shared platform applies authentication, JWT/session checks, tenant context and permission middleware before returning the records a user is allowed to access. The dashboard then presents the permitted security, incident, evidence and analysis data.",
        [("User credentials/session", "Authentication workflow establishes the user/session state."), ("JWT and refresh lifecycle", "Middleware validates protected requests and session-related conditions."), ("Organization context", "Every sensitive query and workflow runs in tenant/organization context."), ("Role and permissions", "RBAC maps the authenticated user to permitted module actions."), ("Requested workspace", "The React client requests live records from the matching /api/v1 backend routes.")],
        [
            "The backend request chain is router → middleware → handler → service → repository → database. Middleware is the boundary that applies authentication, tenant context, permission checks, request identifiers, CORS and security headers before a handler performs the requested business action.",
            "The React console contains routes, a session shell, authentication/MFA/password-navigation logic and module workspace mappings. It uses API client helpers to load live data such as threat queues, incident records, notifications, model-verification status and detection queues. A demo mode may display sample organization data when backend access is unavailable, but it is not presented as live tenant data.",
            "RBAC provides role-specific presentation over the same security platform. An authorized analyst, administrator or other assigned role sees only the workspace actions and organization records allowed by backend authorization. Tenant filtering belongs in the backend/repository layer as well as UI navigation; UI hiding alone is not treated as security.",
            "Security-sensitive modules expose permission-guarded routes. For example, evidence manifest creation and verification routes require evidence-vault permissions. The report uses this pattern as the implementation principle instead of inventing a fixed list of role names that is not guaranteed by every deployment’s seeded data.",
        ],
        [
            "There is no mathematical scoring formula for RBAC in the project. Access is a policy and authorization decision: the request must have valid authentication/session context, tenant context and the required permission for the route/action. This is deliberately reported as an authorization workflow, not an AI score.",
            "Tenant isolation is essential to the project’s multi-tenant design. A valid authenticated user in one organization must not be able to read or alter another organization’s evidence, incidents, events, model verifications or protected deployments.",
        ],
        ["User opens console", "Authentication/session navigation", "API request with token", "Backend validates JWT/tenant/permission", "Repository runs organization-scoped operation", "Dashboard renders permitted result"],
        ["React/Vite/TypeScript operator UI.", "JWT authentication and refresh/session lifecycle.", "RBAC permission middleware.", "Organization/tenant-scoped repositories and records.", "Request-ID and audit-friendly service boundaries."],
        [("Permitted dashboard data", "Live tenant-scoped records returned from protected APIs."), ("Authorization failure", "A denied result when authentication, tenant context or permission is missing."), ("Audit context", "Request/actor/tenant metadata for security-sensitive workflow history."), ("Role-specific workspace", "UI presentation and actions available to the authorized user.")],
        [("Valid authorized request", "Matching tenant data and permitted controls are returned."), ("Missing JWT/session", "Protected API request is rejected."), ("Missing permission", "Permission middleware denies the protected action."), ("Cross-tenant identifier", "Repository/service query remains organization scoped and must not expose another tenant’s record.")],
        [("Authorization condition", "Valid authenticated/session context AND organization context AND required route permission."), ("Tenant query condition", "Sensitive data access is scoped by organization identifier rather than an unscoped record lookup."), ("No RBAC score formula", "The implementation uses middleware/policy checks, not a numeric role score.")],
        DIAGRAMS / "architecture.png",
    )

    module_pages(
        document, "7", "Notifications, Incident Correlation and Controlled Response",
        "This project area connects detections to operational action. It includes normalized event processing, entity/event correlation, threat and incident workflows, notifications, and a recovery/resilience lifecycle. The design does not automatically perform destructive actions merely from an alert. Response actions follow controlled states such as dry-run, approval, execution, verification, rollback and emergency stop.",
        [("Security event", "Normalized event with identity, tenant, time and related entities."), ("Detection/assessment", "Pre-encryption, threat, media or evidence output that can be linked to a case."), ("Entity relationships", "Endpoint, user, file, process, evidence and IOC relationships used by correlation."), ("Notification event", "Relevant state change such as a canary alert, analysis completion or evidence verification."), ("Approved response action", "An authorized workflow request for dry-run/execution/verification/rollback.")],
        [
            "The asynchronous event path is normalized event → transactional outbox → worker/retry/dead-letter handling → entity graph/correlation → attack story or incident → approved response. Each stage retains a purpose: the outbox connects database change to later processing; workers process long-running tasks; retries handle transient problems; and the dead-letter path keeps repeatedly failing work visible rather than discarding it.",
            "Correlation links events to entities and produces explainable relationships. A ransomware signal can therefore be examined with its file activity, deception resource, endpoint, process and supporting evidence rather than appearing as a bare severity label. Attack-story versions and timelines preserve investigation sequence over time.",
            "Notifications are event-driven and traceable to their originating tenant/entity. Project documentation identifies honeytoken alerts, canary alerts, deepfake-analysis completion, evidence-verification status, case-assignment alert and report-approval alert. Delivery adapters may differ by configuration, but the notification record preserves workflow linkage.",
            "Recovery uses a state-machine style workflow with dry-run, approval, execution, verification, rollback and emergency stop. The backend uses action allowlists and controlled external-runner adapters. An adapter existing in source code does not mean an external runner is automatically deployed; the report keeps that operational boundary explicit.",
        ],
        [
            "The incident risk scorer is also implemented in the Python engine. Its overall score is the sum of eight weighted factor contributions: ransomware behaviour .20, threat intelligence .18, file activity .14, deception trigger .12, incident context .14, response gap .08, evidence integrity .07 and temporal factor .07. A higher policy floor can replace the base total.",
            "The scorer derives integrity, confidentiality and availability component scores with different explicit weighted combinations. It requests human review at high overall/threat probability, data exposure/ransomware suspicion, tampered evidence, or confidence below 60. These are implementation rules that support analyst work; they are not automatic proof or unapproved remediation.",
        ],
        ["Persist normalized event", "Publish through transactional outbox", "Worker correlation/retry/DLQ", "Create/link threat or incident", "Send traceable notification", "Execute response only through approved lifecycle"],
        ["Transactional outbox and eventual consistency.", "Atomic worker claims, bounded retry and dead-letter queue.", "Entity graph, correlation, timelines and attack-story versioning.", "Event-driven notifications with source linkage.", "Recovery state machine, allowlist, approvals, rollback and emergency stop."],
        [("Correlated threat/incident", "A case record linked to events, entities and evidence."), ("Notification", "A tenant-scoped alert tied to its source state change."), ("Attack-story/timeline", "Ordered investigator context built from linked event data."), ("Recovery run record", "Dry-run/approval/execution/verification/rollback lifecycle state and audit trail."), ("Dead-letter work item", "A retained processing failure that needs operational attention.")],
        [("Transient worker error", "Bounded retry occurs before final failure handling."), ("Repeated processing failure", "Work is retained in dead-letter handling rather than silently lost."), ("Canary alert", "A notification can link the user to its relevant detection/evidence context."), ("Unapproved destructive action", "Recovery workflow must not execute it; approval/allowlist conditions are required."), ("Emergency stop", "A controlled stop state is available in recovery workflow.")],
        [("Incident overall = Σ(factor_score × factor_weight)", "Weights: ransomware .20, threat .18, file .14, deception .12, context .14, response .08, evidence .07, temporal .07; policy floor may supersede."), ("Integrity risk", "0.35 file + 0.25 ransomware + 0.20 evidence + 0.15 threat + 0.05 incident context."), ("Confidentiality risk", "0.30 incident context + 0.25 threat + 0.20 deception + 0.15 ransomware + 0.10 evidence."), ("Availability risk", "0.35 ransomware + 0.25 file + 0.20 threat + 0.15 response gap + 0.05 incident context."), ("Incident review rule", "Human review when overall risk ≥75, threat probability ≥75, data exposure/ransomware suspicion, tampered evidence, or confidence <60.")],
        DIAGRAMS / "architecture.png",
    )

    document.add_page_break()
    page_title(document, "FORMULA INDEX — IMPLEMENTED FORMULAS ONLY")
    add_table(document, ["Area", "Implemented formula / threshold"], [
        ["Canary/evidence identity", "H = SHA-256(B); integrity match only when observed and stored digests are equal."],
        ["Pre-encryption combined score", "0.45 × rule score + 0.55 × AI score, clamped to 0–100 and raised by policy floor where applicable."],
        ["Pre-encryption probability", "100 / (1 + exp(−(score − 50) / 10)), then special project floors may apply."],
        ["Pre-encryption risk levels", "LOW <25; MEDIUM ≥25; HIGH ≥50; CRITICAL ≥75."],
        ["Pre-encryption classifications", "BENIGN <25; SUSPICIOUS ≥25; LIKELY_RANSOMWARE ≥60; RANSOMWARE ≥85."],
        ["Image ensemble selection", "Maximum severity/probability among applicable specialists; positive/negative specialist disagreement becomes SUSPICIOUS."],
        ["Incident overall risk", "Sum of eight factor contributions, subject to the implemented policy floor."],
        ["CIA risk components", "Integrity, confidentiality and availability use separate explicit weighted sums listed in Module 7."],
    ])
    paragraph(document, "Excluded on purpose: a neural-network architecture equation, training optimizer/loss, a universal deepfake threshold, a generic OCR formula and an unsupported ransomware formula. The current repository does not justify presenting those items as implemented project details.")
    document.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()
