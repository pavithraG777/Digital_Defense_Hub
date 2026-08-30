package auth

import "testing"

func TestScoreAdaptiveLoginRisk(t *testing.T) {
	assessment := ScoreAdaptiveLoginRisk("198.51.100.10", "Mozilla/5.0", true)
	if assessment.RiskLevel != "LOW" {
		t.Fatalf("expected low baseline login risk, got %s", assessment.RiskLevel)
	}

	assessment = ScoreAdaptiveLoginRisk("203.0.113.71", "curl/8.0", false)
	if assessment.RiskLevel != "MEDIUM" {
		t.Fatalf("expected medium login risk from suspicious client and IP, got %s", assessment.RiskLevel)
	}
}
