package securityscore

import "time"

const (
	methodologyVersion = "organization-risk-v1"
	behaviorWindowDays = 30
)

type OrganizationIdentity struct {
	ID     string `json:"id"`
	Code   string `json:"code"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type RiskFactor struct {
	Code                   string   `json:"code"`
	Label                  string   `json:"label"`
	Score                  *float64 `json:"score"`
	Weight                 float64  `json:"weight"`
	EffectiveWeight        float64  `json:"effective_weight"`
	NormalizedContribution float64  `json:"normalized_contribution"`
	RecordCount            int64    `json:"record_count"`
	Available              bool     `json:"available"`
	Explanation            string   `json:"explanation"`
}

type SourceCounts struct {
	TotalThreats             int64 `json:"total_threats"`
	OpenThreats              int64 `json:"open_threats"`
	TotalIncidents           int64 `json:"total_incidents"`
	OpenIncidents            int64 `json:"open_incidents"`
	RecentBehaviorDetections int64 `json:"recent_behavior_detections"`
}

type OrganizationRisk struct {
	Organization  OrganizationIdentity `json:"organization"`
	DataAvailable bool                 `json:"data_available"`
	RiskScore     *float64             `json:"risk_score"`
	RiskLevel     string               `json:"risk_level"`
	Factors       []RiskFactor         `json:"factors"`
	SourceCounts  SourceCounts         `json:"source_counts"`
	LastSignalAt  *time.Time           `json:"last_signal_at,omitempty"`
}

type Methodology struct {
	Version            string             `json:"version"`
	BehaviorWindowDays int                `json:"behavior_window_days"`
	Weights            map[string]float64 `json:"weights"`
	Thresholds         map[string]float64 `json:"thresholds"`
	MissingDataPolicy  string             `json:"missing_data_policy"`
	Formula            string             `json:"formula"`
}

type ComparisonResponse struct {
	CalculatedAt  time.Time          `json:"calculated_at"`
	Methodology   Methodology        `json:"methodology"`
	Organizations []OrganizationRisk `json:"organizations"`
}

type DistributionItem struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type ThreatInventory struct {
	Total               int64              `json:"total"`
	Open                int64              `json:"open"`
	Resolved            int64              `json:"resolved"`
	FalsePositive       int64              `json:"false_positive"`
	Severity            []DistributionItem `json:"severity"`
	Status              []DistributionItem `json:"status"`
	Category            []DistributionItem `json:"category"`
	DetectionMethod     []DistributionItem `json:"detection_method"`
	TotalOccurrences    int64              `json:"total_occurrences"`
	AffectedFileCount   int64              `json:"affected_file_count"`
	AffectedDeviceCount int64              `json:"affected_device_count"`
}

type ThreatTrendPoint struct {
	Date         string  `json:"date"`
	Detected     int64   `json:"detected"`
	AverageScore float64 `json:"average_score"`
	MaximumScore float64 `json:"maximum_score"`
}

type SafeThreatRecord struct {
	ID                string    `json:"id"`
	Code              string    `json:"code"`
	Title             string    `json:"title"`
	Type              string    `json:"type"`
	Category          string    `json:"category"`
	DetectionMethod   string    `json:"detection_method"`
	Severity          string    `json:"severity"`
	Score             int       `json:"score"`
	Confidence        float64   `json:"confidence"`
	Classification    string    `json:"classification"`
	Status            string    `json:"status"`
	OccurrenceCount   int       `json:"occurrence_count"`
	AffectedFileCount int       `json:"affected_file_count"`
	FirstDetectedAt   time.Time `json:"first_detected_at"`
	LastDetectedAt    time.Time `json:"last_detected_at"`
}

type ThreatScoreResponse struct {
	CalculatedAt time.Time          `json:"calculated_at"`
	Risk         OrganizationRisk   `json:"risk"`
	Inventory    ThreatInventory    `json:"inventory"`
	Trend        []ThreatTrendPoint `json:"trend"`
	TopThreats   []SafeThreatRecord `json:"top_threats"`
	Methodology  Methodology        `json:"methodology"`
}

type rawOrganizationSignals struct {
	Organization OrganizationIdentity

	TotalThreats        int64
	OpenThreats         int64
	OpenCriticalThreats int64
	OpenHighThreats     int64
	OpenMediumThreats   int64
	OpenLowThreats      int64
	AverageThreatScore  float64
	MaximumThreatScore  float64
	LastThreatAt        *time.Time

	TotalIncidents        int64
	OpenIncidents         int64
	OpenCriticalIncidents int64
	OpenHighIncidents     int64
	OpenMediumIncidents   int64
	OpenLowIncidents      int64
	LastIncidentAt        *time.Time

	BehaviorDetections   int64
	AverageBehaviorScore float64
	MaximumBehaviorScore float64
	LastBehaviorAt       *time.Time
}
