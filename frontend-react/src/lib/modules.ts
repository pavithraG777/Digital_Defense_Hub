import type { ApiSource, ModuleDefinition, ScreenDefinition } from "../types";

const live = (id: string, label: string, path: string, detailPath?: string): ApiSource => ({ id, label, path, detailPath });
const connected = (id: string, title: string, description: string, sources: ApiSource[], actions?: ScreenDefinition["actions"]): ScreenDefinition => ({ id, title, description, sources, actions });
const planned = (id: string, title: string, description: string, unavailable = "This screen is ready in the navigation, but the current Go backend does not yet expose a matching API."): ScreenDefinition => ({ id, title, description, unavailable });

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
      planned("register", "Register organization", "Submit a new organization application for super-admin approval."),
      planned("details", "Organization details", "Review organization profile, contacts, and tenant configuration."),
      planned("settings", "Organization settings", "Manage organization-level security configuration."),
      connected("history", "Approval history", "The backend exposes history per organization; select an organization row to inspect its record.", [live("organizations", "Organization directory", "/admin/organizations", "/admin/organizations/:id/history")]),
    ],
  },
  {
    id: "users", title: "User Management", icon: "Users", description: "Manage organization identities and their account lifecycle.",
    screens: [
      connected("directory", "Users", "Live user directory with account status and role context.", [live("users", "User directory", "/admin/users?page=1&limit=50", "/admin/users/:id")], [{ label: "Create user", method: "POST", path: "/admin/users", fields: userCreateFields }]),
      connected("create", "Create user", "Create an organization user through the backend’s audited user workflow.", [live("roles", "Available roles", "/admin/roles")], [{ label: "Create user", method: "POST", path: "/admin/users", fields: userCreateFields }]),
      connected("profile", "User profile", "Open a user from the live directory to inspect their identity and assigned role.", [live("users", "User directory", "/admin/users?page=1&limit=50", "/admin/users/:id")]),
      planned("search", "Search users", "Search and filter user accounts across your organization."),
    ],
  },
  {
    id: "roles", title: "Role Management", icon: "ShieldCheck", description: "Define access roles and review their security responsibilities.",
    screens: [
      connected("directory", "Roles", "Live roles configured in the backend.", [live("roles", "Role directory", "/admin/roles", "/admin/roles/:id")], [{ label: "Create role", method: "POST", path: "/admin/roles", fields: [{ name: "role_code", label: "Role code", required: true }, { name: "role_name", label: "Role name", required: true }, { name: "description", label: "Description", type: "textarea" as const }] }]),
      connected("permissions", "Role permissions", "Select a role to inspect its real permission assignments.", [live("roles", "Role directory", "/admin/roles", "/admin/roles/:id/permissions")]),
      planned("analytics", "Role analytics", "Explore role distribution, high-privilege access, and entitlement risk."),
      planned("audit", "Role audit logs", "Review all audited role changes."),
    ],
  },
  {
    id: "permissions", title: "Permission Management", icon: "KeyRound", description: "Manage granular platform permissions and access controls.",
    screens: [
      connected("directory", "Permissions", "Live permission catalog from the backend.", [live("permissions", "Permission directory", "/admin/permissions", "/admin/permissions/:id")], [{ label: "Create permission", method: "POST", path: "/admin/permissions", fields: [{ name: "permission_code", label: "Permission code", required: true }, { name: "permission_name", label: "Permission name", required: true }, { name: "description", label: "Description", type: "textarea" as const }] }]),
      planned("matrix", "Permission matrix", "Review access coverage across roles and protected product areas."),
      planned("audit", "Permission audit", "Review permission change history."),
    ],
  },
  {
    id: "user-roles", title: "User Role Assignment", icon: "UserCog", description: "Assign, replace, and review user role entitlements.",
    screens: [
      connected("assignments", "User role assignments", "Choose a user from the live directory to inspect roles.", [live("users", "Users", "/admin/users?page=1&limit=50", "/admin/users/:id/roles")]),
      planned("bulk", "Bulk role assignment", "Apply an approved role change across multiple organization users."),
      planned("temporary", "Temporary access", "Time-bound and emergency access workflow."),
      planned("approvals", "Assignment approvals", "Approval workflow for sensitive access changes."),
      planned("analytics", "Assignment analytics", "Analyze role assignment coverage and risk."),
      planned("audit", "Assignment audit logs", "Review user role assignment events."),
    ],
  },
  {
    id: "role-permissions", title: "Role Permission Assignment", icon: "BadgeCheck", description: "Assign and review permissions held by each role.",
    screens: [
      connected("assignments", "Role permission assignments", "Choose a role from the live directory to inspect assigned permissions.", [live("roles", "Roles", "/admin/roles", "/admin/roles/:id/permissions")]),
      planned("replace", "Replace permissions", "Replace the permissions associated with a role."),
      planned("audit", "Permission assignment audit", "Review role-permission assignment history."),
    ],
  },
  {
    id: "protected-files", title: "Protected File Management", icon: "FileLock2", description: "Register protected assets and restore files through the audited protection workflow.",
    screens: [
      planned("directory", "Protected files", "The current backend supports registration and per-file retrieval, but does not expose a protected-file list endpoint."),
      planned("details", "Protected file details", "Inspect protection status and restore history for a selected protected asset."),
      planned("restore", "Restore protected file", "Restore a protected file through the backend’s secure recovery flow."),
    ],
  },
  {
    id: "encryption", title: "Encryption Key Management", icon: "LockKeyhole", description: "Manage tenant encryption keys without exposing sensitive material.",
    screens: [
      connected("active", "Active encryption key", "View metadata for the active organization encryption key.", [live("active-key", "Active encryption key", "/encryption-keys/active")]),
      planned("rotation", "Key rotation history", "Review cryptographic key-rotation history."),
    ],
  },
  {
    id: "honeytokens", title: "Honeytoken Management", icon: "Siren", description: "Create, deploy, validate, and investigate deception honeytokens.",
    screens: [
      connected("directory", "Honeytokens", "Live honeytoken inventory and detection status.", [live("honeytokens", "Honeytoken inventory", "/honeytokens", "/honeytokens/:id")]),
      connected("details", "Honeytoken details", "Select an inventory row to retrieve its backend detail record.", [live("honeytokens", "Honeytoken inventory", "/honeytokens", "/honeytokens/:id")]),
      connected("create", "Create honeytoken", "Create a new deception Honeytoken through the dedicated management workflow.", [live("honeytokens", "Honeytoken inventory", "/honeytokens", "/honeytokens/:id")]),
      connected("deploy", "Deploy honeytoken", "Record the approved logical placement of a selected Honeytoken.", [live("honeytokens", "Honeytoken inventory", "/honeytokens", "/honeytokens/:id")]),
      planned("validate", "Validate honeytoken", "Validate a deployed honeytoken against its location."),
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
      planned("search", "Search events", "Search events by asset, file, action, and time range."),
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
      planned("metrics", "Response analytics", "SLA, severity distribution, and response performance analytics."),
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
    id: "pre-encryption", title: "Pre-Encryption Detection", icon: "ScanSearch", description: "Detect suspicious encryption activity before widespread impact.",
    screens: [
      connected("dashboard", "Detection dashboard", "Live detection queue and pre-encryption engine health.", [live("detections", "Detection queue", "/pre-encryption-detections", "/pre-encryption-detections/:id"), live("health", "Detection engine health", "/pre-encryption-detections/engine/health")]),
      connected("directory", "Detection list", "Review all active and historical pre-encryption detections.", [live("detections", "Detection queue", "/pre-encryption-detections", "/pre-encryption-detections/:id")]),
      connected("health", "Engine health", "Verify pre-encryption detection engine availability.", [live("health", "Detection engine health", "/pre-encryption-detections/engine/health")]),
    ],
  },
  {
    id: "adaptive-deception", title: "Adaptive Deception", icon: "Orbit", description: "Monitor canary health, rotations, and attacker interaction fingerprints.",
    screens: [
      connected("fingerprints", "Fingerprints", "Live attacker-interaction fingerprints from canary activity.", [live("fingerprints", "Fingerprint list", "/adaptive-deception/fingerprints", "/adaptive-deception/fingerprints/:id")]),
      planned("health", "Canary health", "Choose a canary file to load its health check and operational details."),
      planned("rotation", "Canary rotation", "Rotate a selected canary and review its rotation history."),
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
      planned("retry", "Retry queue", "Retry failed synchronization records with appropriate authorization."),
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
      planned("export", "Export audit logs", "Create an approved audit export for compliance review."),
    ],
  },
  {
    id: "system", title: "System Administration", icon: "ServerCog", description: "Operational health and service administration for platform administrators.",
    screens: [
      connected("health", "System health", "Live availability, readiness, database and AI risk-engine health data.", [live("api", "API health", "/health"), live("readiness", "Service readiness", "/ready"), live("ai", "AI risk engine", "/ai-risk/engine/health")]),
      planned("workers", "Worker health", "Review worker, service, storage, and database health."),
      planned("statistics", "Organization statistics", "Review organization and user statistics."),
    ],
  },
  {
    id: "reports", title: "Reports & Analytics", icon: "ChartNoAxesCombined", description: "Generate evidence-backed security and operational reports.",
    screens: [
      planned("threats", "Threat reports", "Generate a threat operations report."),
      planned("incidents", "Incident reports", "Generate an incident response report."),
      planned("deepfake", "Deepfake reports", "Generate a deepfake forensic report."),
      planned("organization", "Organization reports", "Generate organization security and activity reports."),
    ],
  },
  {
    id: "settings", title: "Settings", icon: "Settings2", description: "Manage personal authentication security and platform preferences.",
    screens: [
      connected("profile", "My profile", "Verify your current authenticated identity directly from the API.", [live("profile", "Authenticated profile", "/profile")]),
      connected("password", "Change password", "Update your password and terminate existing sessions as enforced by the backend.", [], [{ label: "Change password", method: "POST", path: "/change-password", fields: [{ name: "current_password", label: "Current password", type: "password" as const, required: true }, { name: "new_password", label: "New password", type: "password" as const, required: true }, { name: "confirm_password", label: "Confirm new password", type: "password" as const, required: true }] }]),
      planned("mfa", "MFA policy", "Manage organization MFA and trusted-device policy."),
      planned("notifications", "Notification settings", "Manage security notification preferences."),
      planned("appearance", "Theme and language", "Manage visual theme and language preference."),
    ],
  },
];

export const getModule = (moduleId?: string) => modules.find((module) => module.id === moduleId);
export const getScreen = (moduleId?: string, screenId?: string) => getModule(moduleId)?.screens.find((screen) => screen.id === screenId);

export const navigationGroups = [
  { label: "Command", modules: ["dashboard", "threats", "incidents", "investigations", "intelligence"] },
  { label: "Defense", modules: ["protected-files", "encryption", "honeytokens", "canary-files", "file-events", "ai-risk", "pre-encryption", "adaptive-deception", "deepfake"] },
  { label: "Identity & Access", modules: ["organizations", "users", "roles", "permissions", "user-roles", "role-permissions"] },
  { label: "Operations", modules: ["notifications", "offline-sync", "audit", "system", "reports", "settings"] },
] as const;
