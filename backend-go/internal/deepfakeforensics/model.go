package deepfakeforensics

import (
	"time"

	"github.com/google/uuid"
)

// MediaAnalysisAsset represents an organization-scoped
// image, video, audio or document uploaded for analysis.
type MediaAnalysisAsset struct {
	ID            uuid.UUID `json:"id"`
	AssetSequence int64     `json:"asset_sequence"`
	AssetCode     string    `json:"asset_code"`

	OrganizationID uuid.UUID  `json:"organization_id"`
	DepartmentID   *uuid.UUID `json:"department_id,omitempty"`
	IncidentID     *uuid.UUID `json:"incident_id,omitempty"`

	EvidenceID     *uuid.UUID `json:"evidence_id,omitempty"`
	EvidenceFileID *uuid.UUID `json:"evidence_file_id,omitempty"`

	OriginalFileName string `json:"original_file_name"`
	StoredFileName   string `json:"stored_file_name"`
	StoragePath      string `json:"-"`

	MediaType     string  `json:"media_type"`
	MimeType      string  `json:"mime_type"`
	FileExtension *string `json:"file_extension,omitempty"`
	FileSizeBytes int64   `json:"file_size_bytes"`

	FileHash      string `json:"file_hash"`
	HashAlgorithm string `json:"hash_algorithm"`

	IsEncrypted         bool    `json:"is_encrypted"`
	EncryptionAlgorithm *string `json:"encryption_algorithm,omitempty"`

	SourceType string `json:"source_type"`
	Status     string `json:"status"`

	UploadedBy *uuid.UUID `json:"uploaded_by,omitempty"`

	Metadata map[string]any `json:"metadata"`

	UploadedAt time.Time  `json:"uploaded_at"`
	AnalyzedAt *time.Time `json:"analyzed_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	DeletedAt  *time.Time `json:"-"`
}

// MediaAssetSecurityEvent is an immutable organization
// audit record for quarantine, integrity and retention.
type MediaAssetSecurityEvent struct {
	ID             uuid.UUID      `json:"id"`
	OrganizationID uuid.UUID      `json:"organization_id"`
	MediaAssetID   uuid.UUID      `json:"media_asset_id"`
	EventType      string         `json:"event_type"`
	ActorUserID    *uuid.UUID     `json:"actor_user_id,omitempty"`
	Reason         string         `json:"reason"`
	Metadata       map[string]any `json:"metadata"`
	CreatedAt      time.Time      `json:"created_at"`
}

// AIAnalysisJob represents one queued offline analysis
// request for a media asset or forensic evidence item.
type AIAnalysisJob struct {
	ID uuid.UUID `json:"id"`

	OrganizationID uuid.UUID  `json:"organization_id"`
	IncidentID     *uuid.UUID `json:"incident_id,omitempty"`

	MediaAssetID   *uuid.UUID `json:"media_asset_id,omitempty"`
	EvidenceID     *uuid.UUID `json:"evidence_id,omitempty"`
	EvidenceFileID *uuid.UUID `json:"evidence_file_id,omitempty"`

	AIModelID        uuid.UUID `json:"ai_model_id"`
	AIModelVersionID uuid.UUID `json:"ai_model_version_id"`

	JobNumber string `json:"job_number"`
	JobType   string `json:"job_type"`
	Priority  string `json:"priority"`
	Status    string `json:"status"`

	RequestedBy *uuid.UUID `json:"requested_by,omitempty"`

	RequestParameters map[string]any `json:"request_parameters,omitempty"`
	ResponseData      map[string]any `json:"response_data,omitempty"`

	ProgressPercentage float64 `json:"progress_percentage"`

	RetryCount     int `json:"retry_count"`
	MaximumRetries int `json:"maximum_retries"`

	ErrorCode    *string `json:"error_code,omitempty"`
	ErrorMessage *string `json:"error_message,omitempty"`

	ProcessingNode  *string `json:"processing_node,omitempty"`
	ExecutionDevice *string `json:"execution_device,omitempty"`

	ProcessingDurationMS *int64 `json:"processing_duration_ms,omitempty"`

	QueuedAt    *time.Time `json:"queued_at,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	CancelledAt *time.Time `json:"cancelled_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AnalysisModelReference contains the active offline model
// and version selected for an analysis job.
type AnalysisModelReference struct {
	ModelID        uuid.UUID `json:"model_id"`
	ModelVersionID uuid.UUID `json:"model_version_id"`

	ModelCode   string `json:"model_code"`
	ModelName   string `json:"model_name"`
	ModelType   string `json:"model_type"`
	ModelStatus string `json:"model_status"`

	Framework  string `json:"framework"`
	InputType  string `json:"input_type"`
	OutputType string `json:"output_type"`

	SupportsCPU bool `json:"supports_cpu"`
	SupportsGPU bool `json:"supports_gpu"`

	MaximumFileSizeBytes *int64 `json:"maximum_file_size_bytes,omitempty"`

	VersionNumber string `json:"version_number"`
	ModelFilePath string `json:"model_file_path"`
	ModelFileHash string `json:"model_file_hash"`
	ModelFormat   string `json:"model_format"`
	VersionStatus string `json:"version_status"`
	IsDefault     bool   `json:"is_default"`

	ConfidenceThreshold *float64 `json:"confidence_threshold,omitempty"`

	Configuration map[string]any `json:"configuration,omitempty"`
}

// AnalysisSource joins the media asset with its selected
// model before it is submitted to the offline engine.
type AnalysisSource struct {
	Asset MediaAnalysisAsset     `json:"asset"`
	Model AnalysisModelReference `json:"model"`
	Job   AIAnalysisJob          `json:"job"`
}
