package securityscore

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
)

const (
	threatWeight   = 0.50
	incidentWeight = 0.30
	behaviorWeight = 0.20
)

type Service struct {
	repository signalRepository
	clock      func() time.Time
}

func NewService(repository signalRepository) *Service {
	return &Service{repository: repository, clock: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) Organization(ctx context.Context, organizationID uuid.UUID) (*OrganizationRisk, error) {
	rows, err := s.repository.listOrganizationSignals(ctx, &organizationID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("organization security score not found")
	}
	result := calculateOrganizationRisk(rows[0])
	return &result, nil
}

func (s *Service) Organizations(ctx context.Context) (*ComparisonResponse, error) {
	rows, err := s.repository.listOrganizationSignals(ctx, nil)
	if err != nil {
		return nil, err
	}
	items := make([]OrganizationRisk, 0, len(rows))
	for _, row := range rows {
		items = append(items, calculateOrganizationRisk(row))
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].RiskScore == nil {
			return false
		}
		if items[j].RiskScore == nil {
			return true
		}
		return *items[i].RiskScore > *items[j].RiskScore
	})
	return &ComparisonResponse{CalculatedAt: s.clock(), Methodology: methodology(), Organizations: items}, nil
}

func (s *Service) Threats(ctx context.Context, organizationID uuid.UUID) (*ThreatScoreResponse, error) {
	risk, err := s.Organization(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	inventory, err := s.repository.threatInventory(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	trend, err := s.repository.threatTrend(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	topThreats, err := s.repository.topThreats(ctx, organizationID, 20)
	if err != nil {
		return nil, err
	}
	return &ThreatScoreResponse{
		CalculatedAt: s.clock(), Risk: *risk, Inventory: inventory,
		Trend: trend, TopThreats: topThreats, Methodology: methodology(),
	}, nil
}

func calculateOrganizationRisk(raw rawOrganizationSignals) OrganizationRisk {
	factors := []RiskFactor{
		{Code: "THREATS", Label: "Open threat exposure", Weight: threatWeight, RecordCount: raw.TotalThreats, Available: raw.TotalThreats > 0},
		{Code: "INCIDENTS", Label: "Unresolved incident pressure", Weight: incidentWeight, RecordCount: raw.TotalIncidents, Available: raw.TotalIncidents > 0},
		{Code: "BEHAVIOR", Label: "Recent behavior detections", Weight: behaviorWeight, RecordCount: raw.BehaviorDetections, Available: raw.BehaviorDetections > 0},
	}

	if factors[0].Available {
		score := 0.0
		if raw.OpenThreats > 0 {
			score = clamp(0.65*raw.MaximumThreatScore + 0.35*raw.AverageThreatScore)
		}
		factors[0].Score = floatPointer(score)
		factors[0].Explanation = fmt.Sprintf("%d total threat record(s), %d currently open; maximum %.1f and average %.1f open-threat score.", raw.TotalThreats, raw.OpenThreats, raw.MaximumThreatScore, raw.AverageThreatScore)
	} else {
		factors[0].Explanation = "No open threat record is available for scoring."
	}
	if factors[1].Available {
		score := clamp(float64(raw.OpenCriticalIncidents*25 + raw.OpenHighIncidents*15 + raw.OpenMediumIncidents*8 + raw.OpenLowIncidents*3))
		factors[1].Score = floatPointer(score)
		factors[1].Explanation = fmt.Sprintf("%d total incident record(s), %d unresolved: %d critical, %d high, %d medium and %d low.", raw.TotalIncidents, raw.OpenIncidents, raw.OpenCriticalIncidents, raw.OpenHighIncidents, raw.OpenMediumIncidents, raw.OpenLowIncidents)
	} else {
		factors[1].Explanation = "No unresolved incident record is available for scoring."
	}
	if factors[2].Available {
		score := clamp(0.60*raw.MaximumBehaviorScore + 0.40*raw.AverageBehaviorScore)
		factors[2].Score = floatPointer(score)
		factors[2].Explanation = fmt.Sprintf("%d behavior detection(s) in the last %d days; maximum %.1f and average %.1f risk score.", raw.BehaviorDetections, behaviorWindowDays, raw.MaximumBehaviorScore, raw.AverageBehaviorScore)
	} else {
		factors[2].Explanation = fmt.Sprintf("No behavior detection record is available in the last %d days.", behaviorWindowDays)
	}

	availableWeight := 0.0
	for _, factor := range factors {
		if factor.Available {
			availableWeight += factor.Weight
		}
	}
	var score *float64
	level := "NOT_AVAILABLE"
	if availableWeight > 0 {
		total := 0.0
		for index := range factors {
			if !factors[index].Available || factors[index].Score == nil {
				continue
			}
			factors[index].EffectiveWeight = math.Round(factors[index].Weight/availableWeight*1000) / 1000
			rawContribution := *factors[index].Score * factors[index].Weight / availableWeight
			factors[index].NormalizedContribution = round1(rawContribution)
			total += rawContribution
		}
		value := round1(total)
		score = &value
		level = riskLevel(value)
	}

	return OrganizationRisk{
		Organization: raw.Organization, DataAvailable: score != nil, RiskScore: score, RiskLevel: level,
		Factors:      factors,
		SourceCounts: SourceCounts{TotalThreats: raw.TotalThreats, OpenThreats: raw.OpenThreats, TotalIncidents: raw.TotalIncidents, OpenIncidents: raw.OpenIncidents, RecentBehaviorDetections: raw.BehaviorDetections},
		LastSignalAt: latestTime(raw.LastThreatAt, raw.LastIncidentAt, raw.LastBehaviorAt),
	}
}

func methodology() Methodology {
	return Methodology{
		Version: methodologyVersion, BehaviorWindowDays: behaviorWindowDays,
		Weights:           map[string]float64{"threats": threatWeight, "incidents": incidentWeight, "behavior": behaviorWeight},
		Thresholds:        map[string]float64{"critical": 80, "high": 60, "medium": 35, "low": 0},
		MissingDataPolicy: "Factors without real records are excluded and remaining weights are normalized. If no scored records exist, risk_score is null and risk_level is NOT_AVAILABLE.",
		Formula:           "threat=.65*max_open+.35*avg_open; incident=min(100,25*critical+15*high+8*medium+3*low); behavior=.60*max_30d+.40*avg_30d",
	}
}

func riskLevel(score float64) string {
	switch {
	case score >= 80:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 35:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func latestTime(values ...*time.Time) *time.Time {
	var latest *time.Time
	for _, value := range values {
		if value != nil && (latest == nil || value.After(*latest)) {
			copyValue := *value
			latest = &copyValue
		}
	}
	return latest
}

func clamp(value float64) float64         { return math.Max(0, math.Min(100, value)) }
func round1(value float64) float64        { return math.Round(value*10) / 10 }
func floatPointer(value float64) *float64 { value = round1(value); return &value }
