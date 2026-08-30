package modelsecurity

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestScoreModelSecurityRisk(t *testing.T) {
	assessment := ScoreModelSecurityRisk("phi-4", true, true, false)
	if assessment.RiskScore != 0 || assessment.RequiresReview {
		t.Fatalf("expected verified model to be low risk, got %#v", assessment)
	}
}

func TestFlexibleBoolAcceptsAPIAndFormValues(t *testing.T) {
	for _, input := range []string{`true`, `"true"`} {
		var value FlexibleBool
		if err := json.Unmarshal([]byte(input), &value); err != nil || !bool(value) {
			t.Fatalf("expected %s to decode as true: %v", input, err)
		}
	}
}

func TestScoreModelSecurityRiskBlocksUnsafeArtifact(t *testing.T) {
	assessment := ScoreModelSecurityRisk("phi-4", false, false, true)
	if assessment.RiskLevel != "CRITICAL" || !assessment.RequiresReview || len(assessment.RiskFlags) != 3 {
		t.Fatalf("expected unsafe model to be blocked with explainable findings, got %#v", assessment)
	}
}

func TestNormalizedHash(t *testing.T) {
	valid := strings.Repeat("A0", 32)
	got, err := normalizedHash(valid)
	if err != nil || got != strings.ToLower(valid) {
		t.Fatalf("unexpected normalized hash: %q %v", got, err)
	}
	if _, err := normalizedHash("not-a-hash"); err == nil {
		t.Fatal("expected invalid hash rejection")
	}
}
