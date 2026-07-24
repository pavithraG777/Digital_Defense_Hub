package honeytoken

// Protected file types.
const (
	FileTypeOriginal   = "ORIGINAL"
	FileTypeHoneytoken = "HONEYTOKEN"
	FileTypeCanary     = "CANARY"
)

// Protected file categories.
const (
	FileCategoryCredentials = "CREDENTIALS"
	FileCategoryFinancial   = "FINANCIAL"
	FileCategoryEmployee    = "EMPLOYEE"
	FileCategoryCustomer    = "CUSTOMER"
	FileCategoryMedical     = "MEDICAL"
	FileCategoryLegal       = "LEGAL"
	FileCategorySourceCode  = "SOURCE_CODE"
	FileCategoryContract    = "CONTRACT"
	FileCategoryEvidence    = "EVIDENCE"
	FileCategoryOther       = "OTHER"
)

// File sensitivity levels.
const (
	SensitivityPublic       = "PUBLIC"
	SensitivityInternal     = "INTERNAL"
	SensitivityConfidential = "CONFIDENTIAL"
	SensitivityRestricted   = "RESTRICTED"
	SensitivityCritical     = "CRITICAL"
)

// Protected file processing statuses.
const (
	FileStatusPending    = "PENDING"
	FileStatusProcessing = "PROCESSING"
	FileStatusProtected  = "PROTECTED"
	FileStatusFailed     = "FAILED"
	FileStatusArchived   = "ARCHIVED"
)

// Deployment statuses.
const (
	DeploymentStatusPending  = "PENDING"
	DeploymentStatusDeployed = "DEPLOYED"
	DeploymentStatusFailed   = "FAILED"
	DeploymentStatusRemoved  = "REMOVED"
)

// Honeytoken types supported by the honeytokens table.
const (
	HoneytokenTypeUsername        = "USERNAME"
	HoneytokenTypePassword        = "PASSWORD"
	HoneytokenTypeEmailAddress    = "EMAIL_ADDRESS"
	HoneytokenTypeAPIKey          = "API_KEY"
	HoneytokenTypeAccessToken     = "ACCESS_TOKEN"
	HoneytokenTypeDatabaseRecord  = "DATABASE_RECORD"
	HoneytokenTypeCloudCredential = "CLOUD_CREDENTIAL"
	HoneytokenTypeSSHKey          = "SSH_KEY"
	HoneytokenTypeDocumentData    = "DOCUMENT_DATA"
	HoneytokenTypeURL             = "URL"
	HoneytokenTypeCustom          = "CUSTOM"
)

// Honeytoken lifecycle statuses supported by the honeytokens table.
const (
	HoneytokenStatusDraft     = "DRAFT"
	HoneytokenStatusActive    = "ACTIVE"
	HoneytokenStatusTriggered = "TRIGGERED"
	HoneytokenStatusInactive  = "INACTIVE"
	HoneytokenStatusExpired   = "EXPIRED"
	HoneytokenStatusRevoked   = "REVOKED"
	HoneytokenStatusArchived  = "ARCHIVED"
)

// Canary file types.
const (
	CanaryTypeDocument       = "DOCUMENT"
	CanaryTypeSpreadsheet    = "SPREADSHEET"
	CanaryTypePDF            = "PDF"
	CanaryTypeImage          = "IMAGE"
	CanaryTypeArchive        = "ARCHIVE"
	CanaryTypeDatabaseBackup = "DATABASE_BACKUP"
	CanaryTypeConfiguration  = "CONFIGURATION"
	CanaryTypeSourceCode     = "SOURCE_CODE"
	CanaryTypeCredentialFile = "CREDENTIAL_FILE"
	CanaryTypeCustom         = "CUSTOM"
)

// Canary file statuses.
const (
	CanaryStatusDraft     = "DRAFT"
	CanaryStatusDeployed  = "DEPLOYED"
	CanaryStatusActive    = "ACTIVE"
	CanaryStatusTriggered = "TRIGGERED"
	CanaryStatusTampered  = "TAMPERED"
	CanaryStatusMissing   = "MISSING"
	CanaryStatusInactive  = "INACTIVE"
	CanaryStatusExpired   = "EXPIRED"
	CanaryStatusArchived  = "ARCHIVED"
)

// Canary file hash algorithms.
const (
	CanaryHashAlgorithmSHA256 = "SHA256"
	CanaryHashAlgorithmSHA384 = "SHA384"
	CanaryHashAlgorithmSHA512 = "SHA512"
)

// File monitoring event types.
const (
	EventTypeCreated             = "CREATED"
	EventTypeOpened              = "OPENED"
	EventTypeRead                = "READ"
	EventTypeCopied              = "COPIED"
	EventTypeMoved               = "MOVED"
	EventTypeRenamed             = "RENAMED"
	EventTypeModified            = "MODIFIED"
	EventTypeEncrypted           = "ENCRYPTED"
	EventTypeDeleted             = "DELETED"
	EventTypeExtensionChanged    = "EXTENSION_CHANGED"
	EventTypePermissionChanged   = "PERMISSION_CHANGED"
	EventTypeHashChanged         = "HASH_CHANGED"
	EventTypeMultipleFileChanges = "MULTIPLE_FILE_CHANGES"
	EventTypeCustom              = "CUSTOM"
)

// File event source resource types.
const (
	FileEventSourceProtectedFile = "PROTECTED_FILE"
	FileEventSourceHoneytoken    = "HONEYTOKEN"
	FileEventSourceCanaryFile    = "CANARY_FILE"
	FileEventSourceUnmanagedFile = "UNMANAGED_FILE"
)

// File event collectors.
const (
	FileEventCollectorWindowsWatcher = "WINDOWS_WATCHER"
	FileEventCollectorLinuxInotify   = "LINUX_INOTIFY"
	FileEventCollectorMacOSFSEvents  = "MACOS_FSEVENTS"
	FileEventCollectorAPI            = "API"
	FileEventCollectorAgent          = "AGENT"
	FileEventCollectorManual         = "MANUAL"
	FileEventCollectorSystem         = "SYSTEM"
)

// File event detection methods.
const (
	DetectionMethodRuleBased      = "RULE_BASED"
	DetectionMethodSignatureBased = "SIGNATURE_BASED"
	DetectionMethodBehaviourBased = "BEHAVIOUR_BASED"
	DetectionMethodAIBased        = "AI_BASED"
	DetectionMethodHybrid         = "HYBRID"
)

// File event processing statuses.
const (
	FileEventStatusReceived   = "RECEIVED"
	FileEventStatusQueued     = "QUEUED"
	FileEventStatusProcessing = "PROCESSING"
	FileEventStatusProcessed  = "PROCESSED"
	FileEventStatusFailed     = "FAILED"
	FileEventStatusIgnored    = "IGNORED"
)

// Threat levels.
const (
	ThreatLevelLow      = "LOW"
	ThreatLevelMedium   = "MEDIUM"
	ThreatLevelHigh     = "HIGH"
	ThreatLevelCritical = "CRITICAL"
)

// Incident statuses represent the complete incident-response lifecycle.
const (
	IncidentStatusOpen          = "OPEN"
	IncidentStatusAssigned      = "ASSIGNED"
	IncidentStatusInvestigating = "INVESTIGATING"
	IncidentStatusContained     = "CONTAINED"
	IncidentStatusEradicated    = "ERADICATED"
	IncidentStatusRecovering    = "RECOVERING"
	IncidentStatusResolved      = "RESOLVED"
	IncidentStatusClosed        = "CLOSED"
	IncidentStatusReopened      = "REOPENED"
	IncidentStatusCancelled     = "CANCELLED"
)

// Incident categories classify the primary security problem.
const (
	IncidentCategoryUnauthorizedAccess = "UNAUTHORIZED_ACCESS"
	IncidentCategoryHoneytokenTrigger  = "HONEYTOKEN_TRIGGER"
	IncidentCategoryCanaryFileTrigger  = "CANARY_FILE_TRIGGER"
	IncidentCategoryRansomware         = "RANSOMWARE"
	IncidentCategoryMalware            = "MALWARE"
	IncidentCategoryPhishing           = "PHISHING"
	IncidentCategoryDataBreach         = "DATA_BREACH"
	IncidentCategoryInsiderThreat      = "INSIDER_THREAT"
	IncidentCategoryAccountCompromise  = "ACCOUNT_COMPROMISE"
	IncidentCategoryAPIAttack          = "API_ATTACK"
	IncidentCategoryDeepfake           = "DEEPFAKE"
	IncidentCategoryDigitalEvidence    = "DIGITAL_EVIDENCE"
	IncidentCategoryPolicyViolation    = "POLICY_VIOLATION"
	IncidentCategorySystemAnomaly      = "SYSTEM_ANOMALY"
	IncidentCategoryOther              = "OTHER"
)

// Incident priorities represent the required response urgency.
const (
	IncidentPriorityLow    = "LOW"
	IncidentPriorityMedium = "MEDIUM"
	IncidentPriorityHigh   = "HIGH"
	IncidentPriorityUrgent = "URGENT"
)

// Incident detection sources identify how an incident was discovered.
const (
	IncidentDetectionSourceSecurityAlert  = "SECURITY_ALERT"
	IncidentDetectionSourceHoneytoken     = "HONEYTOKEN"
	IncidentDetectionSourceCanaryFile     = "CANARY_FILE"
	IncidentDetectionSourceFileMonitoring = "FILE_MONITORING"
	IncidentDetectionSourceAIAnalysis     = "AI_ANALYSIS"
	IncidentDetectionSourceUserReport     = "USER_REPORT"
	IncidentDetectionSourceAdminReport    = "ADMIN_REPORT"
	IncidentDetectionSourceSystem         = "SYSTEM"
	IncidentDetectionSourceExternalReport = "EXTERNAL_REPORT"
	IncidentDetectionSourceOther          = "OTHER"
)

// Incident defaults and identifiers.
const (
	IncidentNumberPrefix    = "DDH-INC"
	DefaultIncidentSeverity = ThreatLevelMedium
	DefaultIncidentPriority = IncidentPriorityMedium
	DefaultIncidentStatus   = IncidentStatusOpen
)

// Threat score values.
const (
	ThreatScoreHoneytokenOpened = 30
	ThreatScoreCanaryModified   = 30
	ThreatScoreMassFileChange   = 25
	ThreatScoreExtensionChange  = 20
	ThreatScoreFileDeletion     = 15
	ThreatScorePermissionChange = 10
)

// Threat score thresholds.
const (
	ThreatScoreMediumThreshold   = 30
	ThreatScoreHighThreshold     = 60
	ThreatScoreCriticalThreshold = 80
)

// Protected package configuration.
const (
	ProtectedPackageExtension = ".ddh"
	MetadataFileExtension     = ".xml"
	HashAlgorithmSHA256       = "SHA-256"
	EncryptionAlgorithmAES256 = "AES-256-GCM"
)

// Threat types identify the security behaviour detected by the threat engine.
const (
	ThreatTypeHoneytokenAccess     = "HONEYTOKEN_ACCESS"
	ThreatTypeCanaryTriggered      = "CANARY_TRIGGERED"
	ThreatTypeFileTampering        = "FILE_TAMPERING"
	ThreatTypeMassFileModification = "MASS_FILE_MODIFICATION"
	ThreatTypeMassFileRename       = "MASS_FILE_RENAME"
	ThreatTypeMassFileDeletion     = "MASS_FILE_DELETION"
	ThreatTypeRansomwareActivity   = "RANSOMWARE_ACTIVITY"
	ThreatTypeUnauthorizedAccess   = "UNAUTHORIZED_ACCESS"
	ThreatTypeSuspiciousProcess    = "SUSPICIOUS_PROCESS"
	ThreatTypeHashMismatch         = "HASH_MISMATCH"
	ThreatTypePermissionAbuse      = "PERMISSION_ABUSE"
	ThreatTypeCustom               = "CUSTOM"
)

// Threat categories group related threat behaviours.
const (
	ThreatCategoryDeception        = "DECEPTION"
	ThreatCategoryRansomware       = "RANSOMWARE"
	ThreatCategoryIntegrity        = "INTEGRITY"
	ThreatCategoryAccessControl    = "ACCESS_CONTROL"
	ThreatCategoryMalware          = "MALWARE"
	ThreatCategoryBehaviourAnomaly = "BEHAVIOURAL_ANOMALY"
	ThreatCategoryUnknown          = "UNKNOWN"
)

// Threat classifications represent the investigation conclusion.
const (
	ThreatClassificationUnknown         = "UNKNOWN"
	ThreatClassificationLikelyBenign    = "LIKELY_BENIGN"
	ThreatClassificationSuspicious      = "SUSPICIOUS"
	ThreatClassificationLikelyMalicious = "LIKELY_MALICIOUS"
	ThreatClassificationMalicious       = "MALICIOUS"
)

// Threat statuses represent the threat investigation lifecycle.
const (
	ThreatStatusDetected      = "DETECTED"
	ThreatStatusAnalyzing     = "ANALYZING"
	ThreatStatusConfirmed     = "CONFIRMED"
	ThreatStatusFalsePositive = "FALSE_POSITIVE"
	ThreatStatusMitigated     = "MITIGATED"
	ThreatStatusEscalated     = "ESCALATED"
	ThreatStatusResolved      = "RESOLVED"
	ThreatStatusArchived      = "ARCHIVED"
)

// Threat-file-event relations describe how an event supports a threat.
const (
	ThreatEventRelationPrimary    = "PRIMARY"
	ThreatEventRelationSupporting = "SUPPORTING"
	ThreatEventRelationCorrelated = "CORRELATED"
	ThreatEventRelationEvidence   = "EVIDENCE"
)
