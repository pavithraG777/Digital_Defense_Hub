package deepfakeforensics

import (
	"time"

	"github.com/google/uuid"
)

// UploadMediaAssetRequest contains optional multipart
// metadata supplied with a direct organization upload.
type UploadMediaAssetRequest struct {
	DepartmentID string `form:"department_id"`
	IncidentID   string `form:"incident_id"`

	SourceType string `form:"source_type"`
	Metadata   string `form:"metadata"`
}

// CreateMediaAssetInput contains the normalized and
// securely stored media-file information.
type CreateMediaAssetInput struct {
	OrganizationID uuid.UUID
	DepartmentID   *uuid.UUID
	IncidentID     *uuid.UUID

	OriginalFileName string
	StoredFileName   string
	StoragePath      string

	MediaType     string
	MimeType      string
	FileExtension *string
	FileSizeBytes int64

	FileHash string

	IsEncrypted         bool
	EncryptionAlgorithm *string

	SourceType string
	Status     string
	UploadedBy uuid.UUID

	Metadata map[string]any
}

// StartMediaAnalysisRequest starts one or more offline
// analysis operations for an uploaded media asset.
type StartMediaAnalysisRequest struct {
	AnalysisModes []string `json:"analysis_modes"`

	Priority        string `json:"priority"`
	ExecutionDevice string `json:"execution_device"`

	ForceReanalysis bool `json:"force_reanalysis"`
}

// MediaAssetQuarantineRequest records the security reason
// for isolating or releasing one organization asset.
type MediaAssetQuarantineRequest struct {
	Reason string `json:"reason"`
}

// MediaAssetSecurityEventPage returns an organization-safe
// slice of the immutable media security audit trail.
type MediaAssetSecurityEventPage struct {
	Items []MediaAssetSecurityEvent `json:"items"`

	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalPages int   `json:"total_pages"`
}

// AnalyzeEvidenceRequest imports an existing evidence
// file into the organization media-analysis workflow.
type AnalyzeEvidenceRequest struct {
	EvidenceID     string `json:"evidence_id"`
	EvidenceFileID string `json:"evidence_file_id"`

	AnalysisModes []string `json:"analysis_modes"`

	Priority        string `json:"priority"`
	ExecutionDevice string `json:"execution_device"`
}

// AnalysisJobSummary is returned after jobs are queued.
type AnalysisJobSummary struct {
	ID uuid.UUID `json:"id"`

	JobNumber string `json:"job_number"`
	JobType   string `json:"job_type"`
	Priority  string `json:"priority"`
	Status    string `json:"status"`
}

// StartMediaAnalysisResponse confirms the accepted
// organization-scoped analysis jobs.
type StartMediaAnalysisResponse struct {
	Asset MediaAnalysisAsset `json:"asset"`

	Jobs []AnalysisJobSummary `json:"jobs"`

	SubmittedAt time.Time `json:"submitted_at"`
}

// MediaAssetListFilter contains normalized repository
// filters for organization media assets.
type MediaAssetListFilter struct {
	MediaType  string
	Status     string
	SourceType string

	IncidentID *uuid.UUID
	UploadedBy *uuid.UUID

	CreatedFrom *time.Time
	CreatedTo   *time.Time

	Limit  int
	Offset int
}

// MediaAssetListResponse is a paginated asset response.
type MediaAssetListResponse struct {
	Items []MediaAnalysisAsset `json:"items"`

	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalPages int   `json:"total_pages"`
}

// AnalysisJobListFilter contains organization-scoped
// analysis-job filters.
type AnalysisJobListFilter struct {
	MediaAssetID *uuid.UUID

	JobType  string
	Status   string
	Priority string

	CreatedFrom *time.Time
	CreatedTo   *time.Time

	Limit  int
	Offset int
}

// AnalysisJobListResponse is a paginated job response.
type AnalysisJobListResponse struct {
	Items []AIAnalysisJob `json:"items"`

	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalPages int   `json:"total_pages"`
}
