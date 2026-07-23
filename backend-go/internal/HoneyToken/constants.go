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
	EventTypeCreated           = "CREATED"
	EventTypeOpened            = "OPENED"
	EventTypeRead              = "READ"
	EventTypeModified          = "MODIFIED"
	EventTypeRenamed           = "RENAMED"
	EventTypeDeleted           = "DELETED"
	EventTypeMoved             = "MOVED"
	EventTypeExtensionChanged  = "EXTENSION_CHANGED"
	EventTypePermissionChanged = "PERMISSION_CHANGED"
)

// Threat levels.
const (
	ThreatLevelLow      = "LOW"
	ThreatLevelMedium   = "MEDIUM"
	ThreatLevelHigh     = "HIGH"
	ThreatLevelCritical = "CRITICAL"
)

// Incident statuses.
const (
	IncidentStatusOpen          = "OPEN"
	IncidentStatusInvestigating = "INVESTIGATING"
	IncidentStatusContained     = "CONTAINED"
	IncidentStatusResolved      = "RESOLVED"
	IncidentStatusClosed        = "CLOSED"
	IncidentStatusFalsePositive = "FALSE_POSITIVE"
)

// Incident types.
const (
	IncidentTypeHoneytokenAccess = "HONEYTOKEN_ACCESS"
	IncidentTypeCanaryTriggered  = "CANARY_TRIGGERED"
	IncidentTypeMassModification = "MASS_FILE_MODIFICATION"
	IncidentTypeMassRename       = "MASS_FILE_RENAME"
	IncidentTypeMassDeletion     = "MASS_FILE_DELETION"
	IncidentTypeRansomware       = "RANSOMWARE_ACTIVITY"
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
