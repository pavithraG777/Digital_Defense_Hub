package baseline

import (
    "context"
    "fmt"
    "strings"
    "time"

    "github.com/google/uuid"
)

// BaselineRiskAssessment describes a baseline posture and anomaly-driven
// readiness signal for downstream risk scoring.
type BaselineRiskAssessment struct {
    RiskScore       int      `json:"risk_score"`
    RiskLevel       string   `json:"risk_level"`
    RequiresReview  bool     `json:"requires_review"`
    RiskFlags       []string `json:"risk_flags"`
    Summary         string   `json:"summary"`
}

// ScoreBaselineRisk creates the smallest stable interface the package can expose
// for explainable baseline posture scoring and dashboard readiness.
func ScoreBaselineRisk(orgID string, observedValue float64, anomaly bool) BaselineRiskAssessment {
    flags := make([]string, 0, 3)
    riskScore := 25

    orgID = strings.TrimSpace(orgID)
    if orgID == "" {
        flags = append(flags, "organization_id_missing")
        riskScore += 15
    }

    if observedValue >= 90 {
        flags = append(flags, "high_observed_metric")
        riskScore += 20
    }

    if anomaly {
        flags = append(flags, "baseline_anomaly_detected")
        riskScore += 30
    }

    if riskScore < 0 {
        riskScore = 0
    }
    if riskScore > 95 {
        riskScore = 95
    }

    requiresReview := false
    riskLevel := "LOW"
    if riskScore >= 72 {
        riskLevel = "HIGH"
        requiresReview = true
    } else if riskScore >= 45 {
        riskLevel = "MEDIUM"
        requiresReview = true
    } else {
        riskLevel = "LOW"
    }

    summary := "baseline anomaly monitoring is healthy"
    if requiresReview {
        summary = "baseline posture requires analyst review"
    }

    return BaselineRiskAssessment{
        RiskScore:      riskScore,
        RiskLevel:      riskLevel,
        RequiresReview: requiresReview,
        RiskFlags:      flags,
        Summary:        summary,
    }
}

type Service struct {
    repo *Repository
}

func NewService(r *Repository) *Service {
    return &Service{repo: r}
}

// AnalyzeMetric performs a lightweight anomaly detection and persists high-confidence anomalies.
func (s *Service) AnalyzeMetric(ctx context.Context, orgID uuid.UUID, metric string, value float64, metadata map[string]interface{}) (bool, error) {
    if s == nil {
        return false, fmt.Errorf("service unavailable")
    }

    // very simple heuristic: flag values above a hard threshold as anomalies
    threshold := 100.0
    if metric == "cpu_usage" {
        threshold = 90.0
    }

    if value > threshold {
        a := &Anomaly{
            OrganizationID: orgID,
            Metric:         metric,
            Value:          value,
            Metadata:       metadata,
            CreatedAt:      time.Now(),
        }
        // persist only if repository is available
        if s.repo != nil {
            if err := s.repo.CreateAnomaly(ctx, a); err != nil {
                return false, err
            }
        }
        return true, nil
    }

    return false, nil
}
