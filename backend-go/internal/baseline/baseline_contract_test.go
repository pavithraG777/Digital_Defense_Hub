package baseline

import "testing"

func TestScoreBaselineRisk(t *testing.T) {
	assessment := ScoreBaselineRisk("organization-a", 95, false)
	if assessment.RiskScore < 40 {
		t.Fatalf("expected a measurable baseline posture, got %#v", assessment)
	}
}
