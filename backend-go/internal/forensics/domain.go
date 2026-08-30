package forensics

import (
	"time"

	"github.com/google/uuid"
)

// ForensicCase represents an investigation case that can group
// evidence items, incidents and forensic results.
type ForensicCase struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	IncidentIDs    []string  `json:"incident_ids"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ForensicEvidence stores organization-scoped evidence details
// that can be associated with a forensic case.
type ForensicEvidence struct {
	ID             uuid.UUID      `json:"id"`
	CaseID         uuid.UUID      `json:"case_id"`
	OrganizationID uuid.UUID      `json:"organization_id"`
	EvidenceType   string         `json:"evidence_type"`
	SourceType     string         `json:"source_type"`
	SourcePath     string         `json:"source_path"`
	FileHash       string         `json:"file_hash"`
	Metadata       map[string]any `json:"metadata"`
	CreatedAt      time.Time      `json:"created_at"`
}

// ForensicAnalysisResult is a shared contract for an analysis result
// produced by the media forensics engine.
type ForensicAnalysisResult struct {
	ID              uuid.UUID      `json:"id"`
	OrganizationID  uuid.UUID      `json:"organization_id"`
	AnalysisJobID   uuid.UUID      `json:"analysis_job_id"`
	CaseID          *uuid.UUID     `json:"case_id,omitempty"`
	EvidenceID      *uuid.UUID     `json:"evidence_id,omitempty"`
	EvidenceFileID  *uuid.UUID     `json:"evidence_file_id,omitempty"`
	ResultType      string         `json:"result_type"`
	Result          string         `json:"result"`
	ConfidenceScore *float64       `json:"confidence_score,omitempty"`
	Summary         string         `json:"summary"`
	Findings        []string       `json:"findings"`
	ResultData      map[string]any `json:"result_data"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}
