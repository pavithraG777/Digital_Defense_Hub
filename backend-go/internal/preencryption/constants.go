package preencryption

import (
	"math"
	"strings"
)

const (
	RiskLevelLow      = "LOW"
	RiskLevelMedium   = "MEDIUM"
	RiskLevelHigh     = "HIGH"
	RiskLevelCritical = "CRITICAL"
)

const (
	ClassificationBenign           = "BENIGN"
	ClassificationSuspicious       = "SUSPICIOUS"
	ClassificationLikelyRansomware = "LIKELY_RANSOMWARE"
	ClassificationRansomware       = "RANSOMWARE"
)

const (
	DetectionStagePreEncryption       = "PRE_ENCRYPTION"
	DetectionStageEncryptionSuspected = "ENCRYPTION_SUSPECTED"
	DetectionStageEncryptionConfirmed = "ENCRYPTION_CONFIRMED"
)

const (
	DetectionMethodRuleBased = "RULE_BASED"
	DetectionMethodAIBased   = "AI_BASED"
	DetectionMethodHybrid    = "HYBRID"
)

const (
	DetectionStatusOpen          = "OPEN"
	DetectionStatusInvestigating = "INVESTIGATING"
	DetectionStatusConfirmed     = "CONFIRMED"
	DetectionStatusFalsePositive = "FALSE_POSITIVE"
	DetectionStatusMitigated     = "MITIGATED"
	DetectionStatusArchived      = "ARCHIVED"
)

const (
	ActionStatusPending     = "PENDING"
	ActionStatusNotRequired = "NOT_REQUIRED"
	ActionStatusRequested   = "REQUESTED"
	ActionStatusCompleted   = "COMPLETED"
	ActionStatusFailed      = "FAILED"
)

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

const (
	SourceTypeProtectedFile = "PROTECTED_FILE"
	SourceTypeHoneytoken    = "HONEYTOKEN"
	SourceTypeCanaryFile    = "CANARY_FILE"
	SourceTypeUnmanagedFile = "UNMANAGED_FILE"
)

const (
	SignalMassFileModification  = "MASS_FILE_MODIFICATION"
	SignalRapidFileChanges      = "RAPID_FILE_CHANGES"
	SignalRapidRename           = "RAPID_RENAME"
	SignalExtensionChangeBurst  = "EXTENSION_CHANGE_BURST"
	SignalHashChangeBurst       = "HASH_CHANGE_BURST"
	SignalFileDeletionBurst     = "FILE_DELETION_BURST"
	SignalPermissionChangeBurst = "PERMISSION_CHANGE_BURST"
	SignalHighEntropyWrite      = "HIGH_ENTROPY_WRITE"
	SignalCanaryTrigger         = "CANARY_TRIGGER"
	SignalHoneytokenAccess      = "HONEYTOKEN_ACCESS"
	SignalProtectedFileActivity = "PROTECTED_FILE_ACTIVITY"
	SignalEncryptionActivity    = "ENCRYPTION_ACTIVITY"
	SignalSuspiciousProcess     = "SUSPICIOUS_PROCESS"
	SignalHighEventRate         = "HIGH_EVENT_RATE"
)

const (
	MinimumScore = 0.0
	MaximumScore = 100.0

	MediumRiskThreshold   = 25.0
	HighRiskThreshold     = 50.0
	CriticalRiskThreshold = 75.0
)

func NormalizeConstant(
	value string,
) string {
	return strings.ToUpper(
		strings.TrimSpace(value),
	)
}

func IsValidScore(
	value float64,
) bool {
	return !math.IsNaN(value) &&
		!math.IsInf(value, 0) &&
		value >= MinimumScore &&
		value <= MaximumScore
}

func RiskLevelFromScore(
	score float64,
) (string, bool) {
	if !IsValidScore(score) {
		return "", false
	}

	switch {
	case score >= CriticalRiskThreshold:
		return RiskLevelCritical, true

	case score >= HighRiskThreshold:
		return RiskLevelHigh, true

	case score >= MediumRiskThreshold:
		return RiskLevelMedium, true

	default:
		return RiskLevelLow, true
	}
}

func IsSupportedRiskLevel(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case RiskLevelLow,
		RiskLevelMedium,
		RiskLevelHigh,
		RiskLevelCritical:
		return true

	default:
		return false
	}
}

func IsSupportedClassification(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case ClassificationBenign,
		ClassificationSuspicious,
		ClassificationLikelyRansomware,
		ClassificationRansomware:
		return true

	default:
		return false
	}
}

func IsSupportedDetectionStage(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case DetectionStagePreEncryption,
		DetectionStageEncryptionSuspected,
		DetectionStageEncryptionConfirmed:
		return true

	default:
		return false
	}
}

func IsSupportedDetectionMethod(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case DetectionMethodRuleBased,
		DetectionMethodAIBased,
		DetectionMethodHybrid:
		return true

	default:
		return false
	}
}

func IsSupportedDetectionStatus(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case DetectionStatusOpen,
		DetectionStatusInvestigating,
		DetectionStatusConfirmed,
		DetectionStatusFalsePositive,
		DetectionStatusMitigated,
		DetectionStatusArchived:
		return true

	default:
		return false
	}
}

func IsSupportedActionStatus(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case ActionStatusPending,
		ActionStatusNotRequired,
		ActionStatusRequested,
		ActionStatusCompleted,
		ActionStatusFailed:
		return true

	default:
		return false
	}
}

func IsPreEncryptionRelevantEventType(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case EventTypeCreated,
		EventTypeCopied,
		EventTypeMoved,
		EventTypeRenamed,
		EventTypeModified,
		EventTypeEncrypted,
		EventTypeDeleted,
		EventTypeExtensionChanged,
		EventTypePermissionChanged,
		EventTypeHashChanged,
		EventTypeMultipleFileChanges:
		return true

	default:
		return false
	}
}

func IsFileChangeEventType(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case EventTypeCreated,
		EventTypeCopied,
		EventTypeMoved,
		EventTypeRenamed,
		EventTypeModified,
		EventTypeEncrypted,
		EventTypeDeleted,
		EventTypeExtensionChanged,
		EventTypePermissionChanged,
		EventTypeHashChanged,
		EventTypeMultipleFileChanges:
		return true

	default:
		return false
	}
}

func IsDeceptionSourceType(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case SourceTypeHoneytoken,
		SourceTypeCanaryFile:
		return true

	default:
		return false
	}
}

func IsSupportedSignalType(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case SignalMassFileModification,
		SignalRapidFileChanges,
		SignalRapidRename,
		SignalExtensionChangeBurst,
		SignalHashChangeBurst,
		SignalFileDeletionBurst,
		SignalPermissionChangeBurst,
		SignalHighEntropyWrite,
		SignalCanaryTrigger,
		SignalHoneytokenAccess,
		SignalProtectedFileActivity,
		SignalEncryptionActivity,
		SignalSuspiciousProcess,
		SignalHighEventRate:
		return true

	default:
		return false
	}
}
