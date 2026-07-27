package deepfakeforensics

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCalculateMediaTrustAssessmentAuthenticFallback(
	t *testing.T,
) {
	deepfakeResult := DetectionResultAuthentic
	authenticity := 70.0
	deepfakeConfidence := 65.0
	deepfakeRuntime := "HEURISTIC_FALLBACK"
	forensicResult := ForensicResultAuthentic
	forensicConfidence := 73.5
	forensicRuntime := "OPENCV"

	assessment, err := calculateMediaTrustAssessment(
		trustAnalysisSnapshot{
			Asset: MediaAnalysisAsset{
				ID:             uuid.New(),
				OrganizationID: uuid.New(),
				FileHash:       strings.Repeat("a", 64),
				HashAlgorithm:  "SHA256",
			},
			DeepfakeResult:          &deepfakeResult,
			AuthenticityProbability: &authenticity,
			DeepfakeConfidence:      &deepfakeConfidence,
			DeepfakeRuntime:         &deepfakeRuntime,
			DeepfakeTrained:         false,
			ForensicResult:          &forensicResult,
			ForensicConfidence:      &forensicConfidence,
			ForensicRuntime:         &forensicRuntime,
			CompletedJobCount:       2,
			TerminalJobCount:        2,
			AllJobsTerminal:         true,
		},
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("calculate trust assessment: %v", err)
	}

	if assessment.Verdict != TrustVerdictAuthentic {
		t.Fatalf(
			"expected %s, got %s",
			TrustVerdictAuthentic,
			assessment.Verdict,
		)
	}
	if assessment.RiskLevel != TrustRiskLow {
		t.Fatalf(
			"expected LOW risk, got %s",
			assessment.RiskLevel,
		)
	}
	if !assessment.RequiresHumanReview {
		t.Fatal(
			"heuristic-only assessment must require human review",
		)
	}
	if assessment.ConfidenceScore > 70 {
		t.Fatalf(
			"fallback confidence must be capped at 70, got %.2f",
			assessment.ConfidenceScore,
		)
	}
}

func TestCalculateMediaTrustAssessmentCriticalManipulation(
	t *testing.T,
) {
	deepfakeResult := DetectionResultDeepfake
	deepfakeProbability := 98.0
	deepfakeConfidence := 95.0
	deepfakeRuntime := "ONNX_RUNTIME"
	forensicResult := ForensicResultManipulated
	forensicConfidence := 90.0
	forensicRuntime := "OPENCV"

	assessment, err := calculateMediaTrustAssessment(
		trustAnalysisSnapshot{
			Asset: MediaAnalysisAsset{
				ID:             uuid.New(),
				OrganizationID: uuid.New(),
				FileHash:       strings.Repeat("b", 64),
				HashAlgorithm:  "SHA256",
			},
			DeepfakeResult:      &deepfakeResult,
			DeepfakeProbability: &deepfakeProbability,
			DeepfakeConfidence:  &deepfakeConfidence,
			DeepfakeRuntime:     &deepfakeRuntime,
			DeepfakeTrained:     true,
			ForensicResult:      &forensicResult,
			ForensicConfidence:  &forensicConfidence,
			ForensicRuntime:     &forensicRuntime,
			CompletedJobCount:   2,
			TerminalJobCount:    2,
			AllJobsTerminal:     true,
		},
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("calculate trust assessment: %v", err)
	}

	if assessment.Verdict != TrustVerdictManipulated {
		t.Fatalf(
			"expected %s, got %s",
			TrustVerdictManipulated,
			assessment.Verdict,
		)
	}
	if assessment.RiskLevel != TrustRiskCritical {
		t.Fatalf(
			"expected CRITICAL risk, got %s",
			assessment.RiskLevel,
		)
	}
	if !assessment.RequiresEscalation() {
		t.Fatal(
			"critical assessment must require escalation",
		)
	}
}

func TestCalculateMediaTrustAssessmentRequiresCoreEvidence(
	t *testing.T,
) {
	_, err := calculateMediaTrustAssessment(
		trustAnalysisSnapshot{
			Asset: MediaAnalysisAsset{
				ID:             uuid.New(),
				OrganizationID: uuid.New(),
				FileHash:       strings.Repeat("c", 64),
			},
		},
		time.Now().UTC(),
	)
	if err != ErrInsufficientMediaTrustEvidence {
		t.Fatalf(
			"expected insufficient evidence error, got %v",
			err,
		)
	}
}

func TestValidateModelActivationCandidateRejectsPlaceholder(
	t *testing.T,
) {
	err := validateModelActivationCandidate(
		"models/deepfake/image/model.pth",
		strings.Repeat("0", 64),
		"PTH",
		[]byte(`{"placeholder_file":true}`),
	)
	if err == nil {
		t.Fatal("placeholder model must not activate")
	}
}

func TestValidateModelActivationCandidateAcceptsVerifiedModel(
	t *testing.T,
) {
	err := validateModelActivationCandidate(
		"models/deepfake/image/model.onnx",
		strings.Repeat("a", 64),
		"ONNX",
		[]byte(`{"placeholder_file":false}`),
	)
	if err != nil {
		t.Fatalf(
			"verified model should activate: %v",
			err,
		)
	}
}
