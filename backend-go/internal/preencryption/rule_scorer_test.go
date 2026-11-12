package preencryption

import (
	"testing"

	"github.com/google/uuid"
)

func TestDeceptionInteractionAloneIsNotClassifiedAsRansomware(t *testing.T) {
	features := DetectionFeatures{
		TotalEventCount:     1,
		UniqueFileCount:     1,
		ModifiedEventCount:  1,
		CanaryEventCount:    1,
		EventRatePerMinute:  60,
		HasCanaryTrigger:    true,
		HasRapidFileChanges: true,
	}
	events := []FileEventObservation{{
		ID:           uuid.New(),
		SourceType:   "CANARY_FILE",
		EventType:    "MODIFIED",
		IsSuspicious: true,
	}}

	assessment, err := EvaluateRuleAssessment(
		features,
		events,
		DefaultFeaturePolicy(),
	)
	if err != nil {
		t.Fatalf("evaluate rule assessment: %v", err)
	}
	if assessment.RuleScore >= CriticalRiskThreshold {
		t.Fatalf("single canary interaction was scored critical: %.0f", assessment.RuleScore)
	}
	if assessment.Classification == ClassificationLikelyRansomware {
		t.Fatalf("single canary interaction was classified as ransomware")
	}
	if assessment.RequiresEndpointIsolation {
		t.Fatalf("single canary interaction requested endpoint isolation")
	}
	if !assessment.RequiresHumanReview {
		t.Fatalf("single canary interaction must still require human review")
	}
}

func TestDeceptionInteractionWithEncryptionEvidenceIsCritical(t *testing.T) {
	features := DetectionFeatures{
		TotalEventCount:       2,
		UniqueFileCount:       2,
		ModifiedEventCount:    1,
		EncryptedEventCount:   1,
		CanaryEventCount:      1,
		HighEntropyWriteCount: 1,
		HasCanaryTrigger:      true,
		HasHighEntropyWrites:  true,
		HasEncryptionActivity: true,
	}
	events := []FileEventObservation{
		{ID: uuid.New(), SourceType: "CANARY_FILE", EventType: "MODIFIED", IsSuspicious: true},
		{ID: uuid.New(), SourceType: "FILE_MONITOR", EventType: "ENCRYPTED", IsSuspicious: true},
	}

	assessment, err := EvaluateRuleAssessment(
		features,
		events,
		DefaultFeaturePolicy(),
	)
	if err != nil {
		t.Fatalf("evaluate rule assessment: %v", err)
	}
	if assessment.RuleScore < CriticalRiskThreshold {
		t.Fatalf("corroborated encryption evidence was not critical: %.0f", assessment.RuleScore)
	}
	if assessment.Classification != ClassificationRansomware {
		t.Fatalf("got classification %q, want ransomware", assessment.Classification)
	}
	if !assessment.RequiresEndpointIsolation {
		t.Fatalf("corroborated encryption evidence must request endpoint isolation")
	}
}
