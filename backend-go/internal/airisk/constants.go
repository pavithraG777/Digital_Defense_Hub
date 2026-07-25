package airisk

import "math"

const (
	RiskSubjectTypeIncident      = "INCIDENT"
	RiskSubjectTypeSecurityAlert = "SECURITY_ALERT"
	RiskSubjectTypeEvidence      = "EVIDENCE"
	RiskSubjectTypeEvidenceFile  = "EVIDENCE_FILE"
	RiskSubjectTypeUser          = "USER"
	RiskSubjectTypeDevice        = "DEVICE"
	RiskSubjectTypeAnalysisJob   = "AI_ANALYSIS_JOB"
)

const (
	RiskLevelLow      = "LOW"
	RiskLevelMedium   = "MEDIUM"
	RiskLevelHigh     = "HIGH"
	RiskLevelCritical = "CRITICAL"
)

const (
	RiskStatusActive     = "ACTIVE"
	RiskStatusReviewed   = "REVIEWED"
	RiskStatusOverridden = "OVERRIDDEN"
	RiskStatusExpired    = "EXPIRED"
	RiskStatusArchived   = "ARCHIVED"
)

const (
	MinimumRiskScore = 0.0
	MaximumRiskScore = 100.0

	MediumRiskThreshold   = 25.0
	HighRiskThreshold     = 50.0
	CriticalRiskThreshold = 75.0
)

func IsSupportedRiskSubjectType(value string) bool {
	switch value {
	case RiskSubjectTypeIncident,
		RiskSubjectTypeSecurityAlert,
		RiskSubjectTypeEvidence,
		RiskSubjectTypeEvidenceFile,
		RiskSubjectTypeUser,
		RiskSubjectTypeDevice,
		RiskSubjectTypeAnalysisJob:
		return true

	default:
		return false
	}
}

func IsSupportedRiskLevel(value string) bool {
	switch value {
	case RiskLevelLow,
		RiskLevelMedium,
		RiskLevelHigh,
		RiskLevelCritical:
		return true

	default:
		return false
	}
}

func IsSupportedRiskStatus(value string) bool {
	switch value {
	case RiskStatusActive,
		RiskStatusReviewed,
		RiskStatusOverridden,
		RiskStatusExpired,
		RiskStatusArchived:
		return true

	default:
		return false
	}
}

func IsValidRiskScore(value float64) bool {
	return !math.IsNaN(value) &&
		!math.IsInf(value, 0) &&
		value >= MinimumRiskScore &&
		value <= MaximumRiskScore
}

func RiskLevelFromScore(
	score float64,
) (string, bool) {
	if !IsValidRiskScore(score) {
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
