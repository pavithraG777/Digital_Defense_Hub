package networksecurity

import "testing"

func TestScoreNetworkSecurityRisk(t *testing.T) {
	assessment := ScoreNetworkSecurityRisk("sensor-a", false, true, false)
	if assessment.RiskScore < 35 {
		t.Fatalf("expected a measurable network security posture, got %#v", assessment)
	}
}
