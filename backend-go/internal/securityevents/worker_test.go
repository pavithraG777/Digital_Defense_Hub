package securityevents

import (
	"testing"
	"time"
)

func TestRetryDelayIsBoundedExponential(t *testing.T) {
	cases := []struct {
		attempt int
		want    time.Duration
	}{{1, time.Second}, {2, 2 * time.Second}, {5, 16 * time.Second}, {20, 300 * time.Second}}
	for _, c := range cases {
		if got := retryDelay(c.attempt); got != c.want {
			t.Fatalf("attempt %d: got %s want %s", c.attempt, got, c.want)
		}
	}
}
func TestCorrelationConfidence(t *testing.T) {
	low := correlationConfidence(2, 2, 29*time.Minute, 30*time.Minute)
	high := correlationConfidence(5, 4, time.Minute, 30*time.Minute)
	if high <= low || high > 1 {
		t.Fatalf("unexpected confidence ordering: low=%f high=%f", low, high)
	}
}
func TestAnomalyScore(t *testing.T) {
	normal, _ := anomalyScore(10, 10, 2)
	abnormal, z := anomalyScore(30, 10, 2)
	if normal != 0 || abnormal < .9 || z != 10 {
		t.Fatalf("unexpected anomaly result normal=%f abnormal=%f z=%f", normal, abnormal, z)
	}
}
func TestBehaviorRiskIsExplainable(t *testing.T) {
	score, rule, why := behaviorRisk("POWERSHELL_ENCODED", nil)
	if score < .8 || rule == "" || len(why) == 0 {
		t.Fatalf("unexpected behavior finding: %f %s %#v", score, rule, why)
	}
}
