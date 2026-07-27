package deepfakeforensics

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const (
	TrustVerdictAuthentic         = "AUTHENTIC"
	TrustVerdictLikelyAuthentic   = "LIKELY_AUTHENTIC"
	TrustVerdictSuspicious        = "SUSPICIOUS"
	TrustVerdictLikelyManipulated = "LIKELY_MANIPULATED"
	TrustVerdictManipulated       = "MANIPULATED"
	TrustVerdictInconclusive      = "INCONCLUSIVE"

	TrustClassificationAuthentic    = "AUTHENTIC"
	TrustClassificationSuspicious   = "SUSPICIOUS"
	TrustClassificationManipulated  = "MANIPULATED"
	TrustClassificationInconclusive = "INCONCLUSIVE"

	TrustRiskLow      = "LOW"
	TrustRiskMedium   = "MEDIUM"
	TrustRiskHigh     = "HIGH"
	TrustRiskCritical = "CRITICAL"

	TrustEscalationNone       = "NONE"
	TrustEscalationPending    = "PENDING"
	TrustEscalationInProgress = "IN_PROGRESS"
	TrustEscalationCompleted  = "COMPLETED"
	TrustEscalationFailed     = "FAILED"
)

// MediaTrustAssessment is the explainable combined decision derived from the
// latest deepfake and classical forensic results for one media asset.
type MediaTrustAssessment struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	MediaAssetID   uuid.UUID `json:"media_asset_id"`

	TrustScore      float64 `json:"trust_score"`
	RiskScore       float64 `json:"risk_score"`
	ConfidenceScore float64 `json:"confidence_score"`

	Verdict        string `json:"verdict"`
	Classification string `json:"classification"`
	RiskLevel      string `json:"risk_level"`

	TrainedModelUsed    bool `json:"trained_model_used"`
	RequiresHumanReview bool `json:"requires_human_review"`
	Finalized           bool `json:"finalized"`

	ComponentScores map[string]any   `json:"component_scores"`
	Signals         []map[string]any `json:"signals"`
	Warnings        []string         `json:"warnings"`

	CompletedJobCount int `json:"completed_job_count"`
	TerminalJobCount  int `json:"terminal_job_count"`

	LatestAnalysisJobID *uuid.UUID `json:"latest_analysis_job_id,omitempty"`

	EscalationStatus       string     `json:"escalation_status"`
	EscalationAttemptCount int        `json:"escalation_attempt_count"`
	EscalationError        *string    `json:"escalation_error,omitempty"`
	IncidentID             *uuid.UUID `json:"incident_id,omitempty"`
	IncidentEvidenceID     *uuid.UUID `json:"incident_evidence_id,omitempty"`
	NotificationSentAt     *time.Time `json:"notification_sent_at,omitempty"`
	EscalatedAt            *time.Time `json:"escalated_at,omitempty"`

	EvaluatedAt time.Time `json:"evaluated_at"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (assessment MediaTrustAssessment) RequiresEscalation() bool {
	if !assessment.Finalized ||
		assessment.IncidentID != nil ||
		assessment.EscalationStatus == TrustEscalationCompleted {
		return false
	}

	return assessment.RiskLevel == TrustRiskHigh ||
		assessment.RiskLevel == TrustRiskCritical
}

type trustAnalysisSnapshot struct {
	Asset MediaAnalysisAsset

	DeepfakeResult          *string
	DeepfakeProbability     *float64
	AuthenticityProbability *float64
	DeepfakeConfidence      *float64
	DeepfakeRuntime         *string
	DeepfakeTrained         bool
	DeepfakeWarnings        []string

	ForensicResult     *string
	ForensicConfidence *float64
	ForensicRuntime    *string
	ForensicWarnings   []string

	OCRResult               *string
	OCRConfidence           *float64
	OCRRequiresManualReview bool

	CompletedJobCount int
	TerminalJobCount  int
	AllJobsTerminal   bool
	LatestJobID       *uuid.UUID
}

// MediaTrustEscalationEvent is emitted only after an assessment is
// atomically claimed for high/critical escalation.
type MediaTrustEscalationEvent struct {
	Assessment  MediaTrustAssessment
	Asset       MediaAnalysisAsset
	ActorUserID uuid.UUID
}

type MediaTrustEscalationResult struct {
	IncidentID         uuid.UUID
	IncidentEvidenceID uuid.UUID
	NotificationSentAt *time.Time
}

type MediaTrustEscalationPublisher interface {
	PublishMediaTrustEscalation(
		ctx context.Context,
		event MediaTrustEscalationEvent,
	) (*MediaTrustEscalationResult, error)
}
