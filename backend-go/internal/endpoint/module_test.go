package endpoint

import "testing"

func TestScoreEndpointProtectionRisk(t *testing.T) {
	assessment := ScoreEndpointProtectionRisk("win-01", true, true, false)
	if assessment.RiskScore != 0 || assessment.RequiresContainment {
		t.Fatalf("expected a healthy endpoint posture, got %#v", assessment)
	}
}
