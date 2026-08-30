package honeytoken

import (
	"testing"

	"github.com/google/uuid"
)

func TestSameThreatResource(t *testing.T) {
	resourceID := uuid.New()
	existing := &Threat{CanaryFileID: &resourceID}
	if !isSameThreatResource(existing, ThreatSignal{CanaryFileID: &resourceID}) {
		t.Fatal("same canary file should be counted as one affected file")
	}
	if isSameThreatResource(existing, ThreatSignal{CanaryFileID: uuidPointer(uuid.New())}) {
		t.Fatal("different canary files must not be treated as the same resource")
	}
}

func uuidPointer(value uuid.UUID) *uuid.UUID { return &value }

func TestAssessThreatSignalCalibratesCanarySignal(t *testing.T) {
	assessment, err := assessThreatSignal(ThreatSignal{
		ResourceType: "CANARY_FILE",
		EventType:    "OPENED",
	})
	if err != nil {
		t.Fatalf("assess canary signal: %v", err)
	}
	if assessment.Score != 45 {
		t.Fatalf("score = %d, want 45 for an uncorroborated canary open", assessment.Score)
	}
	if assessment.Severity != ThreatLevelMedium {
		t.Fatalf("severity = %s, want %s", assessment.Severity, ThreatLevelMedium)
	}
}

func TestAssessThreatSignalDoesNotGiveCanaryPerfectScore(t *testing.T) {
	assessment, err := assessThreatSignal(ThreatSignal{
		ResourceType: "CANARY_FILE",
		EventType:    "ENCRYPTED",
		Suspicious:   true,
	})
	if err != nil {
		t.Fatalf("assess canary encryption signal: %v", err)
	}
	if assessment.Score != 80 {
		t.Fatalf("score = %d, want calibrated 80", assessment.Score)
	}
	if assessment.Score >= 100 {
		t.Fatalf("an isolated canary event must not be a perfect score")
	}
}

func TestAssessThreatSignalKeepsGenericEncryptionCritical(t *testing.T) {
	assessment, err := assessThreatSignal(ThreatSignal{
		ResourceType: "PROTECTED_FILE",
		EventType:    "ENCRYPTED",
	})
	if err != nil {
		t.Fatalf("assess protected-file encryption signal: %v", err)
	}
	if assessment.Score != 100 || assessment.Severity != ThreatLevelCritical {
		t.Fatalf("generic encryption score/severity = %d/%s, want 100/%s", assessment.Score, assessment.Severity, ThreatLevelCritical)
	}
}
