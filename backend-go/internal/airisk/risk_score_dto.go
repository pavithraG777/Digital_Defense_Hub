package airisk

import (
	"time"

	"github.com/google/uuid"
)

// CalculateIncidentRiskRequest controls incident risk recalculation.
type CalculateIncidentRiskRequest struct {
	ForceRecalculate bool `json:"force_recalculate"`

	ValidityHours *int `json:"validity_hours,omitempty" binding:"omitempty,min=1,max=720"`
}

// ListRiskScoresRequest contains supported risk-score filters.
type ListRiskScoresRequest struct {
	RiskSubjectType string `form:"risk_subject_type"`
	RiskSubjectID   string `form:"risk_subject_id"`
	RiskLevel       string `form:"risk_level"`
	Status          string `form:"status"`

	Page     int `form:"page"`
	PageSize int `form:"page_size"`
}

// RiskFactor describes one factor that contributed to an AI risk score.
type RiskFactor struct {
	Code         string  `json:"code"`
	Name         string  `json:"name"`
	Category     string  `json:"category"`
	Description  string  `json:"description,omitempty"`
	Weight       float64 `json:"weight"`
	Score        float64 `json:"score"`
	Contribution float64 `json:"contribution"`
}

// RiskEngineAssessment represents the validated result returned
// by the local Python AI Risk Scoring Engine.
type RiskEngineAssessment struct {
	OverallRiskScore float64 `json:"overall_risk_score"`
	RiskLevel        string  `json:"risk_level"`

	ThreatProbability        float64 `json:"threat_probability"`
	IntegrityRiskScore       float64 `json:"integrity_risk_score"`
	ConfidentialityRiskScore float64 `json:"confidentiality_risk_score"`
	AvailabilityRiskScore    float64 `json:"availability_risk_score"`
	ConfidenceScore          float64 `json:"confidence_score"`

	RiskFactors []RiskFactor `json:"risk_factors"`

	ScoreExplanation  string `json:"score_explanation"`
	RecommendedAction string `json:"recommended_action"`

	RequiresHumanReview bool `json:"requires_human_review"`

	ModelName    string `json:"model_name"`
	ModelVersion string `json:"model_version"`
}

// RiskScoreResponse is returned by risk-score API endpoints.
type RiskScoreResponse struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`

	AnalysisJobID *uuid.UUID `json:"analysis_job_id,omitempty"`
	IncidentID    *uuid.UUID `json:"incident_id,omitempty"`
	AlertID       *uuid.UUID `json:"alert_id,omitempty"`
	EvidenceID    *uuid.UUID `json:"evidence_id,omitempty"`

	RiskSubjectType string    `json:"risk_subject_type"`
	RiskSubjectID   uuid.UUID `json:"risk_subject_id"`

	OverallRiskScore float64 `json:"overall_risk_score"`
	RiskLevel        string  `json:"risk_level"`

	ThreatProbability        *float64 `json:"threat_probability,omitempty"`
	IntegrityRiskScore       *float64 `json:"integrity_risk_score,omitempty"`
	ConfidentialityRiskScore *float64 `json:"confidentiality_risk_score,omitempty"`
	AvailabilityRiskScore    *float64 `json:"availability_risk_score,omitempty"`
	ConfidenceScore          *float64 `json:"confidence_score,omitempty"`

	RiskFactors []RiskFactor `json:"risk_factors"`

	ScoreExplanation  *string `json:"score_explanation,omitempty"`
	RecommendedAction *string `json:"recommended_action,omitempty"`

	RequiresHumanReview bool   `json:"requires_human_review"`
	Status              string `json:"status"`

	CalculatedAt time.Time  `json:"calculated_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// CalculateIncidentRiskResponse indicates whether an existing active
// score was reused or a new score was calculated.
type CalculateIncidentRiskResponse struct {
	RiskScore RiskScoreResponse `json:"risk_score"`
	Reused    bool              `json:"reused"`

	ModelName    string `json:"model_name,omitempty"`
	ModelVersion string `json:"model_version,omitempty"`
}

// ListRiskScoresResponse contains paginated risk-score records.
type ListRiskScoresResponse struct {
	Items      []RiskScoreResponse `json:"items"`
	Total      int64               `json:"total"`
	Page       int                 `json:"page"`
	PageSize   int                 `json:"page_size"`
	TotalPages int                 `json:"total_pages"`
}
