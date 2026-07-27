package deepfakeforensics

import (
	"errors"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrMediaTrustAssessmentNotFound = errors.New(
	"media trust assessment not found",
)

var ErrInsufficientMediaTrustEvidence = errors.New(
	"insufficient media evidence for trust assessment",
)

func calculateMediaTrustAssessment(
	snapshot trustAnalysisSnapshot,
	now time.Time,
) (*MediaTrustAssessment, error) {
	if snapshot.Asset.ID == uuid.Nil ||
		snapshot.Asset.OrganizationID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	weightedTrust := 0.0
	weightedConfidence := 0.0
	totalWeight := 0.0
	componentScores := map[string]any{}
	signals := make([]map[string]any, 0, 6)
	warnings := make([]string, 0, 6)

	trainedModelUsed := snapshot.DeepfakeTrained

	if snapshot.DeepfakeResult != nil {
		deepfakeTrust := trustFromDeepfake(snapshot)
		deepfakeConfidence := normalizedScore(
			valueOrDefault(snapshot.DeepfakeConfidence, 50),
		)
		const deepfakeWeight = 0.60

		weightedTrust += deepfakeTrust * deepfakeWeight
		weightedConfidence += deepfakeConfidence * deepfakeWeight
		totalWeight += deepfakeWeight

		componentScores["deepfake"] = map[string]any{
			"trust_score":        deepfakeTrust,
			"confidence_score":   deepfakeConfidence,
			"result":             NormalizeConstant(*snapshot.DeepfakeResult),
			"runtime":            stringValue(snapshot.DeepfakeRuntime),
			"trained_model_used": snapshot.DeepfakeTrained,
			"weight":             deepfakeWeight,
		}
		signals = append(signals, map[string]any{
			"code":             "DEEPFAKE_ASSESSMENT",
			"result":           NormalizeConstant(*snapshot.DeepfakeResult),
			"trust_score":      deepfakeTrust,
			"confidence_score": deepfakeConfidence,
		})
		warnings = appendUniqueStrings(
			warnings,
			snapshot.DeepfakeWarnings...,
		)
	}

	if snapshot.ForensicResult != nil {
		forensicTrust := trustFromForensics(
			*snapshot.ForensicResult,
		)
		forensicConfidence := normalizedScore(
			valueOrDefault(snapshot.ForensicConfidence, 50),
		)
		const forensicWeight = 0.35

		weightedTrust += forensicTrust * forensicWeight
		weightedConfidence += forensicConfidence * forensicWeight
		totalWeight += forensicWeight

		componentScores["forensics"] = map[string]any{
			"trust_score":      forensicTrust,
			"confidence_score": forensicConfidence,
			"result":           NormalizeConstant(*snapshot.ForensicResult),
			"runtime":          stringValue(snapshot.ForensicRuntime),
			"weight":           forensicWeight,
		}
		signals = append(signals, map[string]any{
			"code":             "CLASSICAL_FORENSICS",
			"result":           NormalizeConstant(*snapshot.ForensicResult),
			"trust_score":      forensicTrust,
			"confidence_score": forensicConfidence,
		})
		warnings = appendUniqueStrings(
			warnings,
			snapshot.ForensicWarnings...,
		)
	}

	if totalWeight == 0 {
		return nil, ErrInsufficientMediaTrustEvidence
	}

	// A completed engine job verifies the immutable upload hash before
	// analysis. This small integrity component prevents metadata-only
	// conclusions from dominating the authenticity decision.
	const integrityWeight = 0.05
	integrityTrust := 100.0
	if strings.TrimSpace(snapshot.Asset.FileHash) == "" {
		integrityTrust = 0
		warnings = appendUniqueStrings(
			warnings,
			"Source media hash is unavailable.",
		)
	}
	weightedTrust += integrityTrust * integrityWeight
	weightedConfidence += 100 * integrityWeight
	totalWeight += integrityWeight
	componentScores["source_integrity"] = map[string]any{
		"trust_score":      integrityTrust,
		"confidence_score": 100.0,
		"hash_algorithm":   snapshot.Asset.HashAlgorithm,
		"weight":           integrityWeight,
	}

	if snapshot.OCRResult != nil {
		componentScores["ocr"] = map[string]any{
			"result": NormalizeConstant(*snapshot.OCRResult),
			"confidence_score": normalizedScore(
				valueOrDefault(snapshot.OCRConfidence, 0),
			),
			"requires_manual_review":     snapshot.OCRRequiresManualReview,
			"affects_authenticity_score": false,
		}
	}

	trustScore := roundedTrustScore(
		weightedTrust / totalWeight,
	)
	confidenceScore := roundedTrustScore(
		weightedConfidence / totalWeight,
	)
	riskScore := roundedTrustScore(100 - trustScore)

	verdict := trustVerdict(
		trustScore,
		confidenceScore,
	)
	classification := trustClassification(verdict)
	riskLevel := trustRiskLevel(riskScore)

	if !trainedModelUsed {
		warnings = appendUniqueStrings(
			warnings,
			"No verified trained deepfake model contributed to the combined verdict.",
		)
		if confidenceScore > 70 {
			confidenceScore = 70
		}
	}

	requiresHumanReview :=
		!trainedModelUsed ||
			riskLevel == TrustRiskHigh ||
			riskLevel == TrustRiskCritical ||
			verdict == TrustVerdictSuspicious ||
			verdict == TrustVerdictLikelyManipulated ||
			verdict == TrustVerdictManipulated ||
			verdict == TrustVerdictInconclusive ||
			snapshot.OCRRequiresManualReview

	escalationStatus := TrustEscalationNone
	if riskLevel == TrustRiskHigh ||
		riskLevel == TrustRiskCritical {
		escalationStatus = TrustEscalationPending
	}

	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	return &MediaTrustAssessment{
		ID:             uuid.New(),
		OrganizationID: snapshot.Asset.OrganizationID,
		MediaAssetID:   snapshot.Asset.ID,

		TrustScore:      trustScore,
		RiskScore:       riskScore,
		ConfidenceScore: confidenceScore,

		Verdict:        verdict,
		Classification: classification,
		RiskLevel:      riskLevel,

		TrainedModelUsed:    trainedModelUsed,
		RequiresHumanReview: requiresHumanReview,
		Finalized:           snapshot.AllJobsTerminal,

		ComponentScores: componentScores,
		Signals:         signals,
		Warnings:        warnings,

		CompletedJobCount:   snapshot.CompletedJobCount,
		TerminalJobCount:    snapshot.TerminalJobCount,
		LatestAnalysisJobID: snapshot.LatestJobID,

		EscalationStatus: escalationStatus,

		EvaluatedAt: now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func trustFromDeepfake(
	snapshot trustAnalysisSnapshot,
) float64 {
	trust := 50.0
	switch {
	case snapshot.AuthenticityProbability != nil:
		trust = *snapshot.AuthenticityProbability
	case snapshot.DeepfakeProbability != nil:
		trust = 100 - *snapshot.DeepfakeProbability
	}

	switch NormalizeConstant(
		stringValue(snapshot.DeepfakeResult),
	) {
	case DetectionResultAuthentic:
		trust = math.Max(trust, 80)
	case DetectionResultLikelyAuthentic:
		trust = math.Max(trust, 65)
	case DetectionResultSuspicious:
		trust = math.Min(trust, 50)
	case DetectionResultLikelyDeepfake:
		trust = math.Min(trust, 25)
	case DetectionResultDeepfake:
		trust = math.Min(trust, 10)
	case DetectionResultInconclusive,
		DetectionResultError:
		trust = 50
	}

	return roundedTrustScore(trust)
}

func trustFromForensics(result string) float64 {
	switch NormalizeConstant(result) {
	case ForensicResultAuthentic:
		return 90
	case ForensicResultSuspicious:
		return 45
	case ForensicResultManipulated:
		return 10
	case ForensicResultCorrupted:
		return 25
	default:
		return 50
	}
}

func trustVerdict(
	trustScore float64,
	confidenceScore float64,
) string {
	if confidenceScore < 35 {
		return TrustVerdictInconclusive
	}

	switch {
	case trustScore >= 80:
		return TrustVerdictAuthentic
	case trustScore >= 65:
		return TrustVerdictLikelyAuthentic
	case trustScore >= 45:
		return TrustVerdictSuspicious
	case trustScore >= 25:
		return TrustVerdictLikelyManipulated
	default:
		return TrustVerdictManipulated
	}
}

func trustClassification(verdict string) string {
	switch verdict {
	case TrustVerdictAuthentic,
		TrustVerdictLikelyAuthentic:
		return TrustClassificationAuthentic
	case TrustVerdictSuspicious:
		return TrustClassificationSuspicious
	case TrustVerdictLikelyManipulated,
		TrustVerdictManipulated:
		return TrustClassificationManipulated
	default:
		return TrustClassificationInconclusive
	}
}

func trustRiskLevel(riskScore float64) string {
	switch {
	case riskScore >= 75:
		return TrustRiskCritical
	case riskScore >= 50:
		return TrustRiskHigh
	case riskScore >= 25:
		return TrustRiskMedium
	default:
		return TrustRiskLow
	}
}

func normalizedScore(value float64) float64 {
	return math.Max(0, math.Min(100, value))
}

func roundedTrustScore(value float64) float64 {
	return math.Round(normalizedScore(value)*100) / 100
}

func valueOrDefault(value *float64, fallback float64) float64 {
	if value == nil {
		return fallback
	}

	return *value
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}

	return strings.TrimSpace(*value)
}

func appendUniqueStrings(
	target []string,
	values ...string,
) []string {
	seen := make(map[string]struct{}, len(target)+len(values))
	for _, item := range target {
		normalized := strings.TrimSpace(item)
		if normalized != "" {
			seen[normalized] = struct{}{}
		}
	}

	for _, item := range values {
		normalized := strings.TrimSpace(item)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}

		seen[normalized] = struct{}{}
		target = append(target, normalized)
	}

	return target
}
