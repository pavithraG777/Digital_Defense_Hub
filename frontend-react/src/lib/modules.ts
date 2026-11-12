import type { ApiSource, ModuleDefinition, ScreenDefinition } from "../types";

const live = (id: string, label: string, path: string, detailPath?: string): ApiSource => ({ id, label, path, detailPath });
const connected = (id: string, title: string, description: string, sources: ApiSource[], actions?: ScreenDefinition["actions"]): ScreenDefinition => ({ id, title, description, sources, actions });

const userCreateFields = [
  { name: "username", label: "Username", required: true },
  { name: "official_email", label: "Official email", type: "email" as const, required: true },
  { name: "password", label: "Temporary password", type: "password" as const, required: true },
  { name: "first_name", label: "First name", required: true },
  { name: "last_name", label: "Last name" },
  { name: "display_name", label: "Display name" },
  { name: "designation", label: "Designation" },
  { name: "employee_code", label: "Employee code" },
  { name: "user_type", label: "User type", type: "select" as const, required: true, options: [{ label: "Organization user", value: "ORGANIZATION_USER" }, { label: "Organization admin", value: "ORGANIZATION_ADMIN" }] },
  { name: "role_id", label: "Role ID", required: true, placeholder: "UUID from Role Management" },
];

const analysisJobFields = [
  { name: "target_uri", label: "Approved local/evidence URI", required: true, placeholder: "evidence://asset-id or secured local path" },
  { name: "file_name", label: "File name" },
  { name: "mime_type", label: "MIME type", placeholder: "application/octet-stream" },
  { name: "sha256_hash", label: "SHA-256 (optional)", placeholder: "64 hexadecimal characters" },
  { name: "parameters", label: "Parameters (JSON)", type: "json" as const, placeholder: "{}" },
];

const assessmentFields = [
  { name: "target_type", label: "Target type", required: true },
  { name: "target_id", label: "Target identifier", required: true },
  { name: "profile", label: "Assessment profile", required: true },
  { name: "findings", label: "Findings (JSON array)", type: "json" as const, required: true, placeholder: '[{"code":"CHECK-1","title":"Observed control","severity":"LOW","status":"PASS","evidence":"Verified evidence"}]' },
  { name: "evidence", label: "Supporting evidence (JSON)", type: "json" as const, placeholder: "{}" },
];

export const modules: ModuleDefinition[] = [
  {
    id: "dashboard", title: "Executive Dashboard", icon: "LayoutDashboard", description: "A live, evidence-based overview derived from connected security sources.",
    screens: [
      connected("overview", "Security overview", "Live counts from threats, incidents, protected assets, and notifications.", [live("profile", "Current identity", "/profile"), live("threats", "Threat queue", "/threats"), live("incidents", "Incident queue", "/incidents"), live("notifications", "My notifications", "/my-notifications")]),
      connected("health", "Platform health", "Health checks exposed by the application and AI risk engine.", [live("api", "API health", "/health"), live("risk-engine", "AI risk engine", "/ai-risk/engine/health")]),
    ],
  },
  {
    id: "organizations", title: "Organization Management", icon: "Building2", description: "Tenant onboarding, approval, and organization lifecycle operations.",
    screens: [
      connected("directory", "Organizations", "Review organization registrations and lifecycle status.", [live("organizations", "Organization directory", "/admin/organizations")], [{ label: "Create organization", method: "POST", path: "/admin/organizations", fields: [{ name: "name", label: "Organization name", required: true }, { name: "organization_code", label: "Organization code", required: true }, { name: "official_email", label: "Official email", type: "email" as const, required: true }] }]),
      connected("register", "Register organization", "Create and review organization records through the audited administrator workflow.", [live("organizations", "Organization directory", "/admin/organizations")], [{ label: "Create organization", method: "POST", path: "/admin/organizations", fields: [{ name: "name", label: "Organization name", required: true }, { name: "organization_code", label: "Organization code", required: true }, { name: "official_email", label: "Official email", type: "email" as const, required: true }] }]),
      connected("details", "Organization details", "Review live organization profile, contacts, status, and approval history.", [live("organizations", "Organization directory", "/admin/organizations", "/admin/organizations/:id/history")]),
      connected("settings", "Organization settings", "Review the tenant record and current organization security policy.", [live("organizations", "Organization directory", "/admin/organizations"), live("media-policy", "Media forensic policy", "/deepfake-forensics/organization-policy")]),
      connected("history", "Approval history", "The backend exposes history per organization; select an organization row to inspect its record.", [live("organizations", "Organization directory", "/admin/organizations", "/admin/organizations/:id/history")]),
    ],
  },
  {
    id: "users", title: "User Management", icon: "Users", description: "Manage organization identities and their account lifecycle.",
    screens: [
      connected("directory", "Users", "Live user directory with account status and role context.", [live("users", "User directory", "/admin/users?page=1&limit=50", "/admin/users/:id")], [{ label: "Create user", method: "POST", path: "/admin/users", fields: userCreateFields }]),
      connected("create", "Create user", "Create an organization user through the backend’s audited user workflow.", [live("roles", "Available roles", "/admin/roles")], [{ label: "Create user", method: "POST", path: "/admin/users", fields: userCreateFields }]),
      connected("profile", "User profile", "Open a user from the live directory to inspect their identity and assigned role.", [live("users", "User directory", "/admin/users?page=1&limit=50", "/admin/users/:id")]),
      connected("search", "Search users", "Search and filter the backend user directory by query and account state.", [live("users", "Search results", "/admin/users?page=1&limit=100")]),
    ],
  },
  {
    id: "roles", title: "Role Management", icon: "ShieldCheck", description: "Define access roles and review their security responsibilities.",
    screens: [
      connected("directory", "Roles", "Live roles configured in the backend.", [live("roles", "Role directory", "/admin/roles", "/admin/roles/:id")], [{ label: "Create role", method: "POST", path: "/admin/roles", fields: [{ name: "role_code", label: "Role code", required: true }, { name: "role_name", label: "Role name", required: true }, { name: "description", label: "Description", type: "textarea" as const }] }]),
      connected("permissions", "Role permissions", "Select a role to inspect its real permission assignments.", [live("roles", "Role directory", "/admin/roles", "/admin/roles/:id/permissions")]),
      connected("analytics", "Role analytics", "Compare live roles, users, and permission assignments.", [live("roles", "Roles", "/admin/roles"), live("users", "Users", "/admin/users?page=1&limit=100")]),
      connected("audit", "Role audit logs", "Review immutable administrative activity affecting roles.", [live("audit", "Role audit activity", "/admin/audit-logs?resource_type=ROLE")]),
    ],
  },
  {
    id: "permissions", title: "Permission Management", icon: "KeyRound", description: "Manage granular platform permissions and access controls.",
    screens: [
      connected("directory", "Permissions", "Live permission catalog from the backend.", [live("permissions", "Permission directory", "/admin/permissions", "/admin/permissions/:id")], [{ label: "Create permission", method: "POST", path: "/admin/permissions", fields: [{ name: "permission_code", label: "Permission code", required: true }, { name: "permission_name", label: "Permission name", required: true }, { name: "description", label: "Description", type: "textarea" as const }] }]),
      connected("matrix", "Permission matrix", "Review the live permission catalog beside configured roles.", [live("permissions", "Permissions", "/admin/permissions"), live("roles", "Roles", "/admin/roles")]),
      connected("audit", "Permission audit", "Review immutable permission administration activity.", [live("audit", "Permission audit activity", "/admin/audit-logs?resource_type=PERMISSION")]),
    ],
  },
  {
    id: "user-roles", title: "User Role Assignment", icon: "UserCog", description: "Assign, replace, and review user role entitlements.",
    screens: [
      connected("assignments", "User role assignments", "Choose a user from the live directory to inspect or assign roles.", [live("users", "Users", "/admin/users?page=1&limit=50", "/admin/users/:id/roles")], [{ label: "Assign roles to selected user", method: "POST", path: "/admin/users/:id/roles", fields: [{ name: "role_ids", label: "Role IDs", type: "json", required: true, placeholder: "[\"role-uuid\"]" }] }]),
      connected("bulk", "Bulk role assignment", "Apply one or more roles to multiple users in one authorized operation.", [live("users", "Users", "/admin/users?page=1&limit=100"), live("roles", "Roles", "/admin/roles")], [{ label: "Bulk assign roles", method: "POST", path: "/admin/user-role-assignments/bulk", fields: [{ name: "user_ids", label: "User IDs", type: "json", required: true, placeholder: "[\"user-uuid-1\", \"user-uuid-2\"]" }, { name: "role_ids", label: "Role IDs", type: "json", required: true, placeholder: "[\"role-uuid\"]" }, { name: "expires_at", label: "Optional expiry", type: "datetime-local" }] }]),
      connected("temporary", "Temporary access", "Grant an audited role assignment that expires automatically.", [live("users", "Users", "/admin/users?page=1&limit=100", "/admin/users/:id/roles"), live("roles", "Roles", "/admin/roles")], [{ label: "Grant temporary roles", method: "POST", path: "/admin/users/:id/roles", fields: [{ name: "role_ids", label: "Role IDs", type: "json", required: true, placeholder: "[\"role-uuid\"]" }, { name: "expires_at", label: "Expires at", type: "datetime-local", required: true }] }]),
      connected("approvals", "Assignment approvals", "Request, approve, or reject audited multi-user role assignments.", [live("approvals", "Approval queue", "/admin/role-assignment-approvals")], [{ label: "Request role assignment", method: "POST", path: "/admin/role-assignment-approvals", fields: [{ name: "user_ids", label: "User IDs", type: "json", required: true }, { name: "role_ids", label: "Role IDs", type: "json", required: true }, { name: "expires_at", label: "Optional expiry", type: "datetime-local" }, { name: "reason", label: "Business reason", type: "textarea", required: true }] }, { label: "Decide selected request", method: "POST", path: "/admin/role-assignment-approvals/:id/decision", fields: [{ name: "decision", label: "Decision", type: "select", required: true, options: [{ label: "Approve", value: "APPROVED" }, { label: "Reject", value: "REJECTED" }] }, { name: "note", label: "Decision note", type: "textarea" }] }]),
      connected("analytics", "Assignment analytics", "Analyze live users and role coverage.", [live("users", "Users", "/admin/users?page=1&limit=100"), live("roles", "Roles", "/admin/roles")]),
      connected("audit", "Assignment audit logs", "Review role assignment events.", [live("audit", "Assignment audit", "/admin/audit-logs?resource_type=USER_ROLE")]),
    ],
  },
  {
    id: "role-permissions", title: "Role Permission Assignment", icon: "BadgeCheck", description: "Assign and review permissions held by each role.",
    screens: [
      connected("assignments", "Role permission assignments", "Choose a role from the live directory to inspect assigned permissions.", [live("roles", "Roles", "/admin/roles", "/admin/roles/:id/permissions")]),
      connected("replace", "Replace permissions", "Choose a role and replace its complete permission set in one audited operation.", [live("roles", "Roles", "/admin/roles", "/admin/roles/:id/permissions"), live("permissions", "Permissions", "/admin/permissions")], [{ label: "Replace selected role permissions", method: "PUT", path: "/admin/roles/:id/permissions", fields: [{ name: "permission_ids", label: "Permission IDs (JSON array)", type: "json" as const, required: true, placeholder: "[]" }, { name: "expires_at", label: "Optional expiry (RFC3339)" }] }]),
      connected("audit", "Permission assignment audit", "Review role-permission assignment history.", [live("audit", "Role permission audit", "/admin/audit-logs?resource_type=ROLE_PERMISSION")]),
    ],
  },
  {
    id: "protected-files", title: "Protected File Management", icon: "FileLock2", description: "Register protected assets and restore files through the audited protection workflow.",
    screens: [
      connected("directory", "Protected files", "Organization-scoped protected-file inventory with safe metadata only.", [live("files", "Protected files", "/protected-files", "/protected-files/:id")]),
      connected("details", "Protected file details", "Inspect safe protection state without exposing paths, keys, or hashes.", [live("files", "Protected files", "/protected-files", "/protected-files/:id")]),
      connected("restore", "Restore protected file", "Select an owned protected file and complete the MFA/password restore workflow.", [live("files", "Protected files", "/protected-files", "/protected-files/:id")], [{ label: "Send restore OTP", method: "POST", path: "/protected-files/:id/restore/owner/start" }, { label: "Verify and restore", method: "POST", path: "/protected-files/:id/restore/owner", fields: [{ name: "restore_reason", label: "Restore reason", type: "textarea" as const, required: true }, { name: "mfa_challenge_id", label: "MFA challenge ID", required: true }, { name: "email_code", label: "Email OTP", required: true }, { name: "password", label: "Account password", type: "password" as const, required: true }, { name: "device_id", label: "Approved device ID", required: true }, { name: "download", label: "Download restored file", type: "select" as const, required: true, options: [{ label: "Yes", value: "true" }, { label: "No", value: "false" }] }] }]),
    ],
  },
  {
    id: "encryption", title: "Encryption Key Management", icon: "LockKeyhole", description: "Manage tenant encryption keys without exposing sensitive material.",
    screens: [
      connected("active", "Active encryption key", "View metadata for the active organization encryption key.", [live("active-key", "Active encryption key", "/encryption-keys/active")]),
      connected("rotation", "Key rotation history", "Review complete safe key history and create the next organization key.", [live("keys", "Encryption key history", "/encryption-keys")], [{ label: "Rotate encryption key", method: "POST", path: "/encryption-keys", fields: [{ name: "key_name", label: "New key name", required: true }, { name: "purpose", label: "Rotation purpose", required: true }] }]),
    ],
  },
  {
    id: "honeytokens", title: "Honeytoken Management", icon: "Siren", description: "Create, deploy, validate, and investigate deception honeytokens.",
    screens: [
      connected("directory", "Honeytokens", "Live honeytoken inventory and detection status.", [live("honeytokens", "Honeytoken inventory", "/honeytokens", "/honeytokens/:id")]),
      connected("details", "Honeytoken details", "Select an inventory row to retrieve its backend detail record.", [live("honeytokens", "Honeytoken inventory", "/honeytokens", "/honeytokens/:id")]),
      connected("create", "Create honeytoken", "Create a new deception Honeytoken through the dedicated management workflow.", [live("honeytokens", "Honeytoken inventory", "/honeytokens", "/honeytokens/:id")]),
      connected("deploy", "Deploy honeytoken", "Record the approved logical placement of a selected Honeytoken.", [live("honeytokens", "Honeytoken inventory", "/honeytokens", "/honeytokens/:id")]),
      connected("validate", "Validate honeytoken", "Select a deployed honeytoken and validate an observed value.", [live("honeytokens", "Honeytokens", "/honeytokens", "/honeytokens/:id")], [{ label: "Validate observed value", method: "POST", path: "/honeytokens/:id/validate", fields: [{ name: "observed_value", label: "Observed value", type: "textarea" as const, required: true }] }]),
    ],
  },
  {
    id: "canary-files", title: "Canary File Management", icon: "FileWarning", description: "Generate and deploy canary files for early ransomware detection.",
    screens: [
      connected("directory", "Canary files", "Live canary file inventory and deployment state.", [live("canaries", "Canary inventory", "/canary-files", "/canary-files/:id")]),
      connected("create", "Create canary file", "Generate a decoy or import a secured file copy through the dedicated Canary workflow.", [live("canaries", "Canary inventory", "/canary-files", "/canary-files/:id")]),
      connected("deploy", "Deploy canary", "Copy a staged Canary file into an approved monitored directory.", [live("canaries", "Canary inventory", "/canary-files", "/canary-files/:id")]),
      connected("details", "Canary details", "Inspect safe Canary metadata, deployment state and authoritative Canary event history.", [live("canaries", "Canary inventory", "/canary-files", "/canary-files/:id")]),
    ],
  },
  {
    id: "file-events", title: "File Monitoring", icon: "Activity", description: "Investigate live file-system security events and detailed forensic event records.",
    screens: [
      connected("live", "Live file events", "Real event records emitted by the file monitoring pipeline.", [live("events", "File events", "/file-events", "/file-events/:id")]),
      connected("timeline", "Event timeline", "Use returned file event timestamps to review the live timeline.", [live("events", "File events", "/file-events", "/file-events/:id")]),
      connected("search", "Search events", "Load authoritative events for client-side search and backend-supported filters.", [live("events", "File events", "/file-events", "/file-events/:id")]),
    ],
  },
  {
    id: "threats", title: "Threat Center", icon: "Radar", description: "Prioritize, assign, and track live organization threat records.",
    screens: [
      connected("dashboard", "Threat dashboard", "Live threat records and their severity, status, and assignment data.", [live("threats", "Threat queue", "/threats", "/threats/:id")]),
      connected("directory", "Threat list", "Review active, high-risk, and closed threat records.", [live("threats", "Threat queue", "/threats", "/threats/:id")]),
      connected("details", "Threat details", "Select a live threat to load its complete backend record.", [live("threats", "Threat queue", "/threats", "/threats/:id")]),
    ],
  },
  {
    id: "incidents", title: "Incident Response Center", icon: "ShieldAlert", description: "Coordinate incident lifecycle, evidence, investigation notes, and escalation.",
    screens: [
      connected("dashboard", "Incident dashboard", "Live incident queue with operational status and severity evidence.", [live("incidents", "Incident queue", "/incidents", "/incidents/:id")]),
      connected("directory", "Incident list", "Review and triage the live incident queue.", [live("incidents", "Incident queue", "/incidents", "/incidents/:id")]),
      connected("details", "Incident details", "Select an incident to load its timeline, relationships, and evidence.", [live("incidents", "Incident queue", "/incidents", "/incidents/:id")]),
      connected("metrics", "Response analytics", "Backend-calculated incident snapshots and canonical incident records.", [live("analytics", "Incident analytics", "/incident-analytics"), live("incidents", "Incidents", "/incidents")]),
    ],
  },
  {
    id: "investigations", title: "Investigation Case Management", icon: "FolderSearch2", description: "Create and coordinate investigation cases linked to incidents.",
    screens: [
      connected("dashboard", "Case dashboard", "Live investigation cases and their linked incident records.", [live("cases", "Investigation cases", "/investigation-cases", "/investigation-cases/:id")]),
      connected("directory", "Investigation cases", "Review active and completed investigation cases.", [live("cases", "Investigation cases", "/investigation-cases", "/investigation-cases/:id")]),
      connected("linked-incidents", "Linked incidents", "Select a case to view its backend-linked incidents.", [live("cases", "Investigation cases", "/investigation-cases", "/investigation-cases/:id/incidents")]),
    ],
  },
  {
    id: "ai-risk", title: "AI Risk Engine", icon: "BrainCircuit", description: "View AI-generated incident risk scores and engine availability.",
    screens: [
      connected("dashboard", "AI risk dashboard", "Live AI risk score records and scoring engine health.", [live("scores", "Risk scores", "/ai-risk/scores", "/ai-risk/scores/:id"), live("health", "AI engine health", "/ai-risk/engine/health")]),
      connected("scores", "Risk scores", "Review risk scoring history sourced from the AI risk engine.", [live("scores", "Risk scores", "/ai-risk/scores", "/ai-risk/scores/:id")]),
      connected("health", "AI engine health", "Verify AI risk engine availability and integration health.", [live("health", "AI engine health", "/ai-risk/engine/health")]),
    ],
  },
  {
    id: "model-security", title: "Model Security", icon: "ShieldCheck", description: "Verify model artifacts and review deployment-gate evidence.",
    screens: [
      connected("posture", "Integrity posture", "Tenant-scoped verified and blocked model totals.", [live("integrity", "Integrity posture", "/model-security/integrity")]),
      connected("verifications", "Verification history", "Durable artifact hash, attestation, validation, and risk decisions.", [live("verifications", "Model verifications", "/model-security/verifications", "/model-security/verifications/:id")], [{ label: "Verify model artifact", method: "POST", path: "/model-security/verifications", fields: [{ name: "model_id", label: "Model ID", required: true }, { name: "model_version", label: "Model version", required: true }, { name: "expected_sha256", label: "Expected SHA-256", required: true }, { name: "observed_sha256", label: "Observed SHA-256", required: true }, { name: "attestation_issuer", label: "Attestation issuer", required: true }, { name: "attestation_reference", label: "Attestation reference", required: true }, { name: "validation_passed", label: "Validation result", type: "select" as const, required: true, options: [{ label: "Passed", value: "true" }, { label: "Failed", value: "false" }] }] }]),
    ],
  },
  {
    id: "pre-encryption", title: "Pre-Encryption Detection", icon: "ScanSearch", description: "Review the dedicated behavioural detection queue before files are widely encrypted.",
    screens: [
      connected("dashboard", "Pre-Encryption Detection", "Inspect the authoritative behavioural detections, contributing evidence and engine readiness.", [live("detections", "Detection queue", "/pre-encryption-detections", "/pre-encryption-detections/:id"), live("health", "Detection engine health", "/pre-encryption-detections/engine/health")]),
    ],
  },
  {
    id: "ransomware", title: "Ransomware Detection", icon: "ShieldAlert", description: "Detect encryption behaviour before widespread file loss using rate, entropy, extension, rename, deletion and process-risk signals.",
    screens: [
      connected("dashboard", "Ransomware Scanner", "Choose a folder with explicit permission, scan for ransomware indicators, and review graphical results and organization scan history.", [live("history", "Ransomware scan history", "/ransomware/scans")]),
    ],
  },
  {
    id: "adaptive-deception", title: "Adaptive Deception", icon: "Orbit", description: "Monitor canary health, rotations, and attacker interaction fingerprints.",
    screens: [
      connected("fingerprints", "Interaction fingerprints", "Identify the IP, device, user and process behind access to a monitored canary file.", [live("fingerprints", "Detected actor patterns", "/adaptive-deception/fingerprints", "/adaptive-deception/fingerprints/:id")]),
      connected("health", "Canary integrity health", "Review the latest integrity result for every canary and rerun a check when a file needs attention.", [live("canaries", "Latest canary health results", "/canary-files", "/adaptive-deception/canaries/:id/health")], [{ label: "Check selected canary now", method: "POST", path: "/adaptive-deception/canaries/:id/health-check" }]),
      connected("rotation", "Canary identity rotation", "Renew a selected decoy's identity and review the audit history of previous rotations.", [live("canaries", "Canaries available for rotation", "/canary-files", "/canary-files/:id"), live("history", "Completed and pending rotations", "/adaptive-deception/rotations", "/adaptive-deception/rotations/:id")], [{ label: "Rotate selected canary", method: "POST", path: "/adaptive-deception/canaries/:id/rotate", fields: [{ name: "rotation_reason", label: "Why are you rotating this canary?", required:true, placeholder:"Scheduled refresh, suspected discovery, or compromised identity" }, { name: "rotation_strategy", label: "Rotation strategy", type:"select", required:true, options:[{label:"Generate a new identity and relocate",value:"REGENERATE_AND_RELOCATE"},{label:"Generate a new identity in the same location",value:"REGENERATE_IN_PLACE"}] }, { name: "new_file_name", label: "New file name (optional)", placeholder:"Leave blank to generate automatically" }] }]),
    ],
  },
  {
    id: "deepfake", title: "Deepfake Forensics", icon: "Fingerprint", description: "Secure media intake, forensic analysis, reports, models, and training governance.",
    screens: [
      connected("media", "Media library", "Live forensic media assets and their analysis state.", [live("assets", "Media assets", "/deepfake-forensics/media-assets", "/deepfake-forensics/media-assets/:id")]),
      connected("analysis", "Analysis history", "Browse image, video, audio, and CCTV analysis histories separately.", [live("jobs", "Analysis jobs", "/deepfake-forensics/analysis-jobs", "/deepfake-forensics/analysis-jobs/:id")]),
      connected("policy", "Organization policy", "Review the organization’s media forensic policy.", [live("policy", "Media policy", "/deepfake-forensics/organization-policy")]),
      connected("models", "AI models", "Review deployed forensic model records and versions.", [live("models", "Forensic models", "/deepfake-forensics/models", "/deepfake-forensics/models/:id")]),
      connected("training", "Training", "Review registered training datasets and training jobs.", [live("datasets", "Training datasets", "/deepfake-forensics/training/datasets"), live("training-jobs", "Training jobs", "/deepfake-forensics/training/jobs")]),
      connected("reports", "Forensic reports", "Signed deepfake forensic reports, approvals, integrity hashes, and the complete non-sensitive report record.", [live("reports", "Forensic reports", "/deepfake-forensics/forensic-reports?page=1&page_size=50", "/deepfake-forensics/forensic-reports/:id")]),
    ],
  },
  {
    id: "notifications", title: "Notifications", icon: "BellRing", description: "Read, acknowledge, and manage your security notifications.",
    screens: [
      connected("center", "Notification center", "Live in-app security notifications for the authenticated user.", [live("notifications", "My notifications", "/my-notifications")]),
      connected("history", "Notification history", "Review notification delivery and acknowledgement state.", [live("notifications", "My notifications", "/my-notifications")]),
    ],
  },
  {
    id: "offline-sync", title: "Offline Synchronization", icon: "RefreshCw", description: "Monitor the secure offline synchronization queue.",
    screens: [
      connected("queue", "Synchronization queue", "Live queued, synced, and failed synchronization records.", [live("queue", "Offline sync queue", "/offline-sync/queue")]),
      connected("retry", "Retry queue", "Select a failed synchronization record and return it to the authorized queue.", [live("queue", "Offline sync queue", "/offline-sync/queue")], [{ label: "Retry selected item", method: "POST", path: "/offline-sync/queue/:id/retry" }]),
    ],
  },
  {
    id: "intelligence", title: "Intelligence Center", icon: "Network", description: "Explore connected intelligence correlation, graph, and trust data.",
    screens: [
      connected("dashboard", "Intelligence dashboard", "Live intelligence dashboard data.", [live("dashboard", "Intelligence dashboard", "/intelligence/dashboard")]),
      connected("correlation", "Threat correlation", "Live threat correlation results.", [live("correlation", "Threat correlation", "/intelligence/threat-correlation")]),
      connected("dna", "Threat DNA radar", "Live threat DNA data.", [live("dna", "Threat DNA radar", "/intelligence/threat-dna-radar")]),
      connected("graph", "Knowledge graph", "Live knowledge graph data.", [live("graph", "Knowledge graph", "/intelligence/knowledge-graph")]),
      connected("replay", "Attack replay", "Live attack replay data.", [live("replay", "Attack replay", "/intelligence/attack-replay")]),
      connected("heatmap", "Deepfake heatmap", "Live deepfake heatmap data.", [live("heatmap", "Deepfake heatmap", "/intelligence/deepfake-heatmap")]),
      connected("consensus", "AI consensus", "Live AI consensus data.", [live("consensus", "AI consensus", "/intelligence/ai-consensus")]),
      connected("trust", "Trust evolution", "Live trust evolution data.", [live("trust", "Trust evolution", "/intelligence/trust-evolution")]),
      connected("mesh", "Offline mesh", "Live offline mesh topology.", [live("mesh", "Offline mesh", "/intelligence/offline-mesh")]),
    ],
  },
  {
    id: "audit", title: "Audit Logs", icon: "ScrollText", description: "Trace secured administrative and security activity through immutable audit records.",
    screens: [
      connected("directory", "Audit logs", "Live administrative audit records from the backend.", [live("audit-logs", "Audit logs", "/admin/audit-logs", "/admin/audit-logs/:id")]),
      connected("export", "Export audit logs", "Filter the authoritative audit log before producing a compliance export.", [live("audit", "Audit records", "/admin/audit-logs")]),
    ],
  },
  {
    id: "system", title: "System Administration", icon: "ServerCog", description: "Operational health and service administration for platform administrators.",
    screens: [
      connected("health", "System health", "Live availability, readiness, database and AI risk-engine health data.", [live("api", "API health", "/health"), live("readiness", "Service readiness", "/ready"), live("ai", "AI risk engine", "/ai-risk/engine/health")]),
      connected("workers", "Worker health", "Review security-event queue health and service readiness.", [live("workers", "Security event worker", "/security-events/worker-health"), live("readiness", "Service readiness", "/ready")]),
      connected("statistics", "Organization statistics", "Live organization, user, threat, and incident records for operational totals.", [live("organizations", "Organizations", "/admin/organizations"), live("users", "Users", "/admin/users?page=1&limit=100"), live("threats", "Threats", "/threats"), live("incidents", "Incidents", "/incidents")]),
    ],
  },
  {
    id: "reports", title: "Reports & Analytics", icon: "ChartNoAxesCombined", description: "Generate evidence-backed security and operational reports.",
    screens: [
      connected("threats", "Threat reports", "Build an evidence-backed view from canonical threat records.", [live("threats", "Threat records", "/threats")]),
      connected("incidents", "Incident reports", "Review incident reporting projections and canonical incidents.", [live("reports", "Incident reporting", "/incident-reporting"), live("incidents", "Incidents", "/incidents")]),
      connected("deepfake", "Deepfake reports", "Review signed media forensic reports and their approval state.", [live("reports", "Deepfake forensic reports", "/deepfake-forensics/forensic-reports?page=1&page_size=50", "/deepfake-forensics/forensic-reports/:id")]),
      connected("organization", "Organization reports", "Review tenant, user, audit, and security activity sources.", [live("organizations", "Organizations", "/admin/organizations"), live("audit", "Audit activity", "/admin/audit-activity")]),
    ],
  },
  {
    id: "exposure-operations", title: "Exposure Management", icon: "ScanSearch", description: "Inventory assets, vulnerabilities, attack surface and configuration posture using tenant-scoped records.",
    screens: [
      connected("assets", "Asset inventory", "Organization asset directory from the operational asset service.", [live("assets", "Assets", "/assets", "/assets/:id")]),
      connected("vulnerabilities", "Vulnerability management", "Tracked vulnerabilities and their remediation lifecycle.", [live("vulnerabilities", "Vulnerabilities", "/vulnerabilities", "/vulnerabilities/:id")]),
      connected("attack-surface", "Attack-surface assessments", "Persisted assessment findings and server-calculated risk scores.", [live("surface", "Attack surface", "/attack-surface", "/attack-surface/:id")], [{ label: "Create assessment", method: "POST", path: "/attack-surface/assess", fields: assessmentFields }]),
      connected("configuration", "Configuration assessments", "Configuration posture computed from submitted checks.", [live("configuration", "Configuration posture", "/config-assessment")]),
      connected("cloud-mobile", "Cloud and mobile assessments", "Persisted cloud and mobile security findings.", [live("cloud", "Cloud/mobile assessments", "/cloud", "/cloud/:id")], [{ label: "Create cloud assessment", method: "POST", path: "/cloud/analyze", fields: assessmentFields }]),
    ],
  },
  {
    id: "detection-operations", title: "Detection Operations", icon: "Radar", description: "Investigate alerts, behavior, DLP, UEBA, insider-risk and monitoring records.",
    screens: [
      connected("alerts", "Alert management", "Operational alert records and acknowledgement state.", [live("alerts", "Alerts", "/alert-management", "/alert-management/:id")]),
      connected("behavior", "Behavior analysis", "Observed behavior events and evidence payloads.", [live("behavior", "Behavior events", "/behavior/events")]),
      connected("dlp", "Data loss prevention", "DLP policy violation event records.", [live("dlp", "DLP events", "/dlp/events")]),
      connected("ueba", "UEBA", "User/entity behavior events and high-risk anomalies.", [live("events", "UEBA events", "/ueba/events"), live("anomalies", "UEBA anomalies", "/ueba/anomalies")]),
      connected("insider", "Insider-threat management", "Insider-risk cases and investigation requests.", [live("cases", "Insider-threat cases", "/insider-threat", "/insider-threat/:id"), live("investigations", "Investigation requests", "/insider-threat/investigations")]),
      connected("monitoring", "Security monitoring", "Security-monitoring observations and silence requests.", [live("monitoring", "Monitoring records", "/security-monitoring", "/security-monitoring/:id"), live("silence", "Silence requests", "/security-monitoring/silence-actions")]),
    ],
  },
  {
    id: "governance-operations", title: "Security Governance", icon: "ShieldCheck", description: "Compliance, access control, policy, metadata and removable-media governance.",
    screens: [
      connected("access", "Access-control operations", "Audited grant and revoke records.", [live("access", "Access operations", "/access-control", "/access-control/:id")]),
      connected("compliance", "Compliance audits", "Persisted audit checks and calculated compliance scores.", [live("compliance", "Compliance audits", "/compliance/checks")]),
      connected("policy", "Policy evaluation", "Deterministic policy decisions and rule reasons.", [live("policy", "Policy evaluations", "/policy/evaluations")]),
      connected("metadata", "Metadata validation", "Required, prohibited and expected metadata validation results.", [live("metadata", "Metadata validations", "/metadata", "/metadata/:id")]),
      connected("usb", "USB management", "Observed USB devices, organization policy and block requests.", [live("devices", "USB devices", "/usb/devices"), live("policy", "USB policy", "/usb/policy"), live("actions", "USB actions", "/usb/actions")]),
    ],
  },
  {
    id: "analysis-operations", title: "Analysis Operations", icon: "Microscope", description: "Durable analysis jobs backed by authorized workers; the UI never invents completed scanner results.",
    screens: [
      connected("malware", "Malware analysis", "Malware scan jobs and current execution status.", [live("malware", "Malware jobs", "/malware", "/malware/:id")], [{ label: "Request malware analysis", method: "POST", path: "/malware/analyze", fields: analysisJobFields }]),
      connected("audio", "Audio analysis", "Standalone audio-forensics jobs.", [live("audio", "Audio jobs", "/audio", "/audio/:id")], [{ label: "Request audio analysis", method: "POST", path: "/audio/analyze", fields: analysisJobFields }]),
      connected("documents", "Document analysis", "OCR and document analysis jobs.", [live("documents", "Document jobs", "/documents", "/documents/:id")], [{ label: "Request document analysis", method: "POST", path: "/documents/analyze", fields: analysisJobFields }]),
      connected("email", "Email analysis", "Email security analysis jobs.", [live("email", "Email jobs", "/emails", "/emails/:id")], [{ label: "Request email analysis", method: "POST", path: "/emails/analyze", fields: analysisJobFields }]),
      connected("images", "Generic image analysis", "General image-forensics jobs.", [live("images", "Image jobs", "/images", "/images/:id")], [{ label: "Request image analysis", method: "POST", path: "/images/analyze", fields: analysisJobFields }]),
      connected("faces", "Face analysis", "Face-manipulation analysis jobs.", [live("faces", "Face jobs", "/faces", "/faces/:id")], [{ label: "Request face analysis", method: "POST", path: "/faces/analyze", fields: analysisJobFields }]),
      connected("memory", "Memory forensics", "Memory scan jobs and reports.", [live("memory", "Memory reports", "/memoryforensics/reports", "/memoryforensics/reports/:id")], [{ label: "Request memory scan", method: "POST", path: "/memoryforensics/scan", fields: analysisJobFields }]),
      connected("surveillance", "Surveillance analysis", "Authorized surveillance-analysis jobs and insights.", [live("surveillance", "Surveillance insights", "/surveillance/insights", "/surveillance/insights/:id")], [{ label: "Request surveillance analysis", method: "POST", path: "/surveillance/track", fields: analysisJobFields }]),
      connected("copilot", "Security Copilot", "Persisted incident-summary requests and worker results.", [live("copilot", "Copilot jobs", "/copilot/assist", "/copilot/:id")], [{ label: "Request incident summary", method: "POST", path: "/copilot/summarize", fields: analysisJobFields }]),
    ],
  },
  {
    id: "response-automation", title: "Response Automation", icon: "Workflow", description: "Threat analysis, hunting, response, persistence, integrations and authorized job execution records.",
    screens: [
      connected("analysis", "Threat analysis", "Threat-analysis records and requested actions.", [live("analysis", "Threat analyses", "/threat-analysis", "/threat-analysis/:id"), live("actions", "Analysis actions", "/threat-analysis/actions")]),
      connected("hunting", "Threat hunting", "Threat-hunt records and investigation requests.", [live("hunts", "Threat hunts", "/threat-hunting", "/threat-hunting/:id"), live("actions", "Hunt actions", "/threat-hunting/actions")]),
      connected("response", "Threat response", "Authorized response requests and lifecycle state.", [live("responses", "Threat responses", "/threat-response", "/threat-response/:id"), live("actions", "Response actions", "/threat-response/actions")]),
      connected("persistence", "Persistence discovery", "Persistence assessment findings.", [live("checks", "Persistence checks", "/persistence/checks", "/persistence/checks/:id")], [{ label: "Run persistence assessment", method: "POST", path: "/persistence/discover", fields: assessmentFields }]),
      connected("integrations", "SIEM and ticket integrations", "Outbound requests waiting for an authorized integration executor.", [live("requests", "Integration requests", "/integration/requests")]),
      connected("incident-analytics", "Incident analytics", "Snapshots calculated from canonical incident records.", [live("analytics", "Incident analytics", "/incident-analytics", "/incident-analytics/:id")]),
      connected("incident-lifecycle", "Incident lifecycle views", "Canonical incident records projected for each authorized response stage.", [live("triage", "Triage", "/incident-triage"), live("orchestration", "Orchestration", "/incident-orchestration"), live("remediation", "Remediation", "/incident-remediation"), live("resolution", "Resolution", "/incident-resolution"), live("review", "Review", "/incident-review"), live("closure", "Closure", "/incident-closure"), live("reporting", "Reporting", "/incident-reporting"), live("learning", "Learning", "/incident-learning"), live("after-action", "After action", "/incident-after-action")]),
      connected("operations", "Security operations", "Audited operational action requests and real connector readiness.", [live("health", "Connector readiness", "/security-operations/connectors/health"), live("operations", "Operations", "/security-operations", "/security-operations/:id")]),
    ],
  },
  {
    id: "settings", title: "Settings", icon: "Settings2", description: "Manage personal authentication security and platform preferences.",
    screens: [
      connected("profile", "My profile", "Verify your current authenticated identity directly from the API.", [live("profile", "Authenticated profile", "/profile")]),
      connected("password", "Change password", "Update your password and terminate existing sessions as enforced by the backend.", [], [{ label: "Change password", method: "POST", path: "/change-password", fields: [{ name: "current_password", label: "Current password", type: "password" as const, required: true }, { name: "new_password", label: "New password", type: "password" as const, required: true }, { name: "confirm_password", label: "Confirm new password", type: "password" as const, required: true }] }]),
      connected("mfa", "MFA policy", "Review current MFA state and manage authenticator enrollment from the secured profile workflow.", [live("profile", "Authenticated profile", "/profile")]),
      connected("notifications", "Notification settings", "Review live notification delivery and acknowledgement state.", [live("notifications", "My notifications", "/my-notifications")]),
      connected("appearance", "Theme and language", "Browser-local accessibility preferences are applied without sending personal display choices to the server.", []),
    ],
  },
];

export const getModule = (moduleId?: string) => modules.find((module) => module.id === moduleId);
export const getScreen = (moduleId?: string, screenId?: string) => getModule(moduleId)?.screens.find((screen) => screen.id === screenId);

const modulePermissionMap: Record<string, string[]> = {
  dashboard: [],
  organizations: ["ORGANIZATION_VIEW", "ORGANIZATION_MANAGE"],
  users: ["USER_VIEW", "USER_VIEW_DETAILS"],
  roles: ["ROLE_VIEW"],
  permissions: ["PERMISSION_VIEW", "ROLE_MANAGE_PERMISSIONS"],
  "honeytokens": ["HONEYTOKEN_VIEW"],
  "canary-files": ["CANARY_FILE_VIEW"],
  "file-events": ["FILE_EVENT_VIEW", "CANARY_FILE_VIEW_EVENTS", "HONEYTOKEN_VIEW"],
  threats: ["THREAT_VIEW"],
  incidents: ["INCIDENT_VIEW"],
  investigations: ["INVESTIGATION_VIEW"],
  "ai-risk": ["AI_RISK_VIEW"],
  "pre-encryption": ["PRE_ENCRYPTION_VIEW", "THREAT_VIEW"],
  ransomware: ["THREAT_VIEW", "PRE_ENCRYPTION_VIEW"],
  "adaptive-deception": ["ADAPTIVE_DECEPTION_VIEW", "CANARY_FILE_VIEW"],
  deepfake: ["MEDIA_FORENSIC_VIEW", "AI_ANALYSIS_VIEW"],
  notifications: ["NOTIFICATION_VIEW"],
  "offline-sync": ["SYNC_VIEW"],
  audit: ["AUDIT_LOG_VIEW"],
  system: ["SYSTEM_HEALTH_VIEW"],
  reports: ["REPORT_VIEW"],
  settings: ["PROFILE_VIEW"],
  "exposure-operations": ["ASSET_VIEW", "EXPOSURE_VIEW"],
  "detection-operations": ["ALERT_VIEW", "DETECTION_VIEW"],
  "governance-operations": ["ACCESS_CONTROL_VIEW", "COMPLIANCE_VIEW"],
  "analysis-operations": ["MALWARE_ANALYSIS_VIEW", "ANALYSIS_VIEW"],
  "response-automation": ["THREAT_ANALYSIS_VIEW", "INCIDENT_VIEW"],
};

export function getModuleAccessRequirements(moduleId?: string) {
  if (!moduleId) return [] as string[];
  return modulePermissionMap[moduleId] || [];
}

export function canAccessModule(moduleId: string | undefined, user?: { roles?: string[]; permissions?: string[]; organization_type?:string; user_type?:string } | null) {
  if (!moduleId || !user) return false;
  const isSuperAdmin = (user.roles || []).some((role) => role.toUpperCase() === "SUPER_ADMIN");
  if (isSuperAdmin) return true;
  const isOrganizationAdmin = (user.roles || []).some((role) => {
    const normalized = role.toUpperCase();
    return normalized.includes("ADMIN") || normalized === "MANAGER";
  });
  if (moduleId === "ransomware" && isOrganizationAdmin) return true;
  if(moduleId==="investigations"&&!new Set(["POLICE","FORENSIC_LAB","GOVERNMENT","DEFENCE","CYBERSECURITY_PROVIDER"]).has(String(user.organization_type||"").toUpperCase()))return false;
  const required = getModuleAccessRequirements(moduleId);
  if (!required.length) return true;
  const granted = new Set((user.permissions || []).map((permission) => permission.toUpperCase()));
  return required.some((permission) => granted.has(permission));
}

export const navigationGroups = [
  { label: "Command", modules: ["dashboard", "threats", "incidents", "investigations", "intelligence"] },
  { label: "Defense", modules: ["protected-files", "encryption", "honeytokens", "canary-files", "file-events", "ai-risk", "pre-encryption", "ransomware", "adaptive-deception", "deepfake"] },
  { label: "Identity & Access", modules: ["organizations", "users", "roles", "permissions", "user-roles", "role-permissions"] },
  { label: "Operations", modules: ["notifications", "offline-sync", "audit", "system", "reports", "settings"] },
] as const;
