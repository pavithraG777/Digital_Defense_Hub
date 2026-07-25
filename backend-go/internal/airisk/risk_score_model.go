package airisk

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// RiskScore represents an AI-generated security risk assessment
// stored in the ai_risk_scores table.
type RiskScore struct {
	ID             uuid.UUID `json:"id" db:"id"`
	OrganizationID uuid.UUID `json:"organization_id" db:"organization_id"`

	AnalysisJobID *uuid.UUID `json:"analysis_job_id,omitempty" db:"analysis_job_id"`
	IncidentID    *uuid.UUID `json:"incident_id,omitempty" db:"incident_id"`
	AlertID       *uuid.UUID `json:"alert_id,omitempty" db:"alert_id"`
	EvidenceID    *uuid.UUID `json:"evidence_id,omitempty" db:"evidence_id"`

	RiskSubjectType string    `json:"risk_subject_type" db:"risk_subject_type"`
	RiskSubjectID   uuid.UUID `json:"risk_subject_id" db:"risk_subject_id"`

	OverallRiskScore float64 `json:"overall_risk_score" db:"overall_risk_score"`
	RiskLevel        string  `json:"risk_level" db:"risk_level"`

	ThreatProbability        *float64 `json:"threat_probability,omitempty" db:"threat_probability"`
	IntegrityRiskScore       *float64 `json:"integrity_risk_score,omitempty" db:"integrity_risk_score"`
	ConfidentialityRiskScore *float64 `json:"confidentiality_risk_score,omitempty" db:"confidentiality_risk_score"`
	AvailabilityRiskScore    *float64 `json:"availability_risk_score,omitempty" db:"availability_risk_score"`
	ConfidenceScore          *float64 `json:"confidence_score,omitempty" db:"confidence_score"`

	RiskFactors       json.RawMessage `json:"risk_factors,omitempty" db:"risk_factors"`
	ScoreExplanation  *string         `json:"score_explanation,omitempty" db:"score_explanation"`
	RecommendedAction *string         `json:"recommended_action,omitempty" db:"recommended_action"`

	RequiresHumanReview bool   `json:"requires_human_review" db:"requires_human_review"`
	Status              string `json:"status" db:"status"`

	CalculatedAt time.Time  `json:"calculated_at" db:"calculated_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}
