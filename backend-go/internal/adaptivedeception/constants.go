package adaptivedeception

import (
	"math"
	"strings"
)

const (
	HealthCheckTypeStartup      = "STARTUP"
	HealthCheckTypeScheduled    = "SCHEDULED"
	HealthCheckTypeManual       = "MANUAL"
	HealthCheckTypePostTrigger  = "POST_TRIGGER"
	HealthCheckTypePostRotation = "POST_ROTATION"
	HealthCheckTypeRecovery     = "RECOVERY"
)

const (
	CanaryHealthStatusHealthy  = "HEALTHY"
	CanaryHealthStatusDegraded = "DEGRADED"
	CanaryHealthStatusTampered = "TAMPERED"
	CanaryHealthStatusMissing  = "MISSING"
	CanaryHealthStatusExpired  = "EXPIRED"
	CanaryHealthStatusError    = "ERROR"
	CanaryHealthStatusUnknown  = "UNKNOWN"
)

const (
	HashAlgorithmSHA256 = "SHA256"
	HashAlgorithmSHA384 = "SHA384"
	HashAlgorithmSHA512 = "SHA512"
)

const (
	RotationReasonScheduled      = "SCHEDULED"
	RotationReasonManual         = "MANUAL"
	RotationReasonTriggered      = "TRIGGERED"
	RotationReasonTampered       = "TAMPERED"
	RotationReasonMissing        = "MISSING"
	RotationReasonExpired        = "EXPIRED"
	RotationReasonPolicyChanged  = "POLICY_CHANGED"
	RotationReasonHealthDegraded = "HEALTH_DEGRADED"
)

const (
	RotationStrategyRename                = "RENAME"
	RotationStrategyRelocate              = "RELOCATE"
	RotationStrategyRegenerate            = "REGENERATE"
	RotationStrategyRedeploy              = "REDEPLOY"
	RotationStrategyRegenerateAndRelocate = "REGENERATE_AND_RELOCATE"
)

const (
	RotationStatusPending    = "PENDING"
	RotationStatusProcessing = "PROCESSING"
	RotationStatusCompleted  = "COMPLETED"
	RotationStatusFailed     = "FAILED"
	RotationStatusCancelled  = "CANCELLED"
)

const (
	MinimumScore = 0.0
	MaximumScore = 100.0
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

func IsSupportedHealthCheckType(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case HealthCheckTypeStartup,
		HealthCheckTypeScheduled,
		HealthCheckTypeManual,
		HealthCheckTypePostTrigger,
		HealthCheckTypePostRotation,
		HealthCheckTypeRecovery:
		return true

	default:
		return false
	}
}

func IsSupportedCanaryHealthStatus(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case CanaryHealthStatusHealthy,
		CanaryHealthStatusDegraded,
		CanaryHealthStatusTampered,
		CanaryHealthStatusMissing,
		CanaryHealthStatusExpired,
		CanaryHealthStatusError,
		CanaryHealthStatusUnknown:
		return true

	default:
		return false
	}
}

func IsSupportedHashAlgorithm(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case HashAlgorithmSHA256,
		HashAlgorithmSHA384,
		HashAlgorithmSHA512:
		return true

	default:
		return false
	}
}

func IsSupportedRotationReason(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case RotationReasonScheduled,
		RotationReasonManual,
		RotationReasonTriggered,
		RotationReasonTampered,
		RotationReasonMissing,
		RotationReasonExpired,
		RotationReasonPolicyChanged,
		RotationReasonHealthDegraded:
		return true

	default:
		return false
	}
}

func IsSupportedRotationStrategy(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case RotationStrategyRename,
		RotationStrategyRelocate,
		RotationStrategyRegenerate,
		RotationStrategyRedeploy,
		RotationStrategyRegenerateAndRelocate:
		return true

	default:
		return false
	}
}

func IsSupportedRotationStatus(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case RotationStatusPending,
		RotationStatusProcessing,
		RotationStatusCompleted,
		RotationStatusFailed,
		RotationStatusCancelled:
		return true

	default:
		return false
	}
}

func IsTerminalRotationStatus(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case RotationStatusCompleted,
		RotationStatusFailed,
		RotationStatusCancelled:
		return true

	default:
		return false
	}
}
