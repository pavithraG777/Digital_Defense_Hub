package deepfakeforensics

import (
	"time"

	"github.com/google/uuid"
)

const (
	mediaEngineRequestType   = "MULTIMODAL_MEDIA_ANALYSIS"
	mediaEngineSchemaVersion = "1.0.0"
)

// MediaEngineRequest is the authenticated request sent to
// the offline Python multimodal analysis engine.
type MediaEngineRequest struct {
	RequestID     uuid.UUID `json:"request_id"`
	RequestType   string    `json:"request_type"`
	SchemaVersion string    `json:"schema_version"`

	OrganizationID uuid.UUID `json:"organization_id"`
	AnalysisJobID  uuid.UUID `json:"analysis_job_id"`

	MediaAssetID   *uuid.UUID `json:"media_asset_id,omitempty"`
	EvidenceID     *uuid.UUID `json:"evidence_id,omitempty"`
	EvidenceFileID *uuid.UUID `json:"evidence_file_id,omitempty"`

	JobType   string `json:"job_type"`
	MediaType string `json:"media_type"`

	FileName       string `json:"file_name"`
	MimeType       string `json:"mime_type"`
	SourceFilePath string `json:"source_file_path"`
	FileSizeBytes  int64  `json:"file_size_bytes"`
	FileHash       string `json:"file_hash"`

	ExecutionDevice string `json:"execution_device"`

	Model *MediaEngineModelSpecification `json:"model,omitempty"`

	Parameters map[string]any `json:"parameters"`

	RequestedAt time.Time `json:"requested_at"`
}

// MediaEngineModelSpecification is included only for an
// ACTIVE, verified PyTorch or ONNX model version.
type MediaEngineModelSpecification struct {
	ModelName    string `json:"model_name"`
	ModelVersion string `json:"model_version"`

	ModelFormat   string `json:"model_format"`
	ModelFilePath string `json:"model_file_path"`
	ModelFileHash string `json:"model_file_hash"`

	ConfidenceThreshold float64 `json:"confidence_threshold"`

	Configuration map[string]any `json:"configuration"`
}

// MediaEngineResponse is the normalized response returned
// by the offline Python service.
type MediaEngineResponse struct {
	RequestID      uuid.UUID `json:"request_id"`
	AnalysisJobID  uuid.UUID `json:"analysis_job_id"`
	OrganizationID uuid.UUID `json:"organization_id"`

	Success bool   `json:"success"`
	Runtime string `json:"runtime,omitempty"`

	DeepfakeAssessment  *EngineDeepfakeAssessment  `json:"deepfake_assessment,omitempty"`
	ForensicsAssessment *EngineForensicsAssessment `json:"forensics_assessment,omitempty"`
	OCRAssessment       *EngineOCRAssessment       `json:"ocr_assessment,omitempty"`

	ProcessingDurationMS int64    `json:"processing_duration_ms"`
	Warnings             []string `json:"warnings"`

	ErrorCode    *string `json:"error_code,omitempty"`
	ErrorMessage *string `json:"error_message,omitempty"`

	ProcessedAt time.Time `json:"processed_at"`
}

type EngineAnalysisSignal struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`

	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Detected   bool    `json:"detected"`
}

type EngineSuspiciousRegion struct {
	RegionType string `json:"region_type"`

	FrameNumber      *int     `json:"frame_number,omitempty"`
	PageNumber       *int     `json:"page_number,omitempty"`
	TimestampSeconds *float64 `json:"timestamp_seconds,omitempty"`

	BoundingBox []float64 `json:"bounding_box,omitempty"`

	Score       float64 `json:"score"`
	Description string  `json:"description"`
}

type EngineDeepfakeAssessment struct {
	MediaType       string `json:"media_type"`
	DetectionResult string `json:"detection_result"`

	DeepfakeProbability     float64 `json:"deepfake_probability"`
	AuthenticityProbability float64 `json:"authenticity_probability"`
	ConfidenceScore         float64 `json:"confidence_score"`

	FacesDetected            *int `json:"faces_detected,omitempty"`
	ManipulatedFacesDetected *int `json:"manipulated_faces_detected,omitempty"`
	TotalFramesAnalyzed      *int `json:"total_frames_analyzed,omitempty"`
	SuspiciousFrames         *int `json:"suspicious_frames,omitempty"`

	AudioDurationSeconds *float64 `json:"audio_duration_seconds,omitempty"`

	LipSyncAnomalyDetected        bool `json:"lip_sync_anomaly_detected"`
	FacialArtifactDetected        bool `json:"facial_artifact_detected"`
	AudioManipulationDetected     bool `json:"audio_manipulation_detected"`
	MetadataInconsistencyDetected bool `json:"metadata_inconsistency_detected"`

	DetectionSummary string `json:"detection_summary"`

	Signals []EngineAnalysisSignal `json:"signals"`

	FeatureData map[string]any `json:"feature_data"`

	SuspiciousRegions []EngineSuspiciousRegion `json:"suspicious_regions"`

	VisualizationFilePath *string `json:"visualization_file_path,omitempty"`
}

type EngineForensicsAssessment struct {
	MediaType       string  `json:"media_type"`
	ForensicResult  string  `json:"forensic_result"`
	ConfidenceScore float64 `json:"confidence_score"`

	EditingTraceDetected       bool `json:"editing_trace_detected"`
	CompressionAnomalyDetected bool `json:"compression_anomaly_detected"`
	CopyMoveDetected           bool `json:"copy_move_detected"`
	SplicingDetected           bool `json:"splicing_detected"`
	FrameDuplicationDetected   bool `json:"frame_duplication_detected"`
	FrameDeletionDetected      bool `json:"frame_deletion_detected"`
	AudioDiscontinuityDetected bool `json:"audio_discontinuity_detected"`
	NoiseInconsistencyDetected bool `json:"noise_inconsistency_detected"`
	TimestampAnomalyDetected   bool `json:"timestamp_anomaly_detected"`

	AnalysisSummary string   `json:"analysis_summary"`
	Findings        []string `json:"findings"`

	Signals []EngineAnalysisSignal `json:"signals"`

	SuspiciousLocations []EngineSuspiciousRegion `json:"suspicious_locations"`
	ForensicFeatureData map[string]any           `json:"forensic_feature_data"`

	VisualizationFilePath *string `json:"visualization_file_path,omitempty"`
}

type EngineOCRAssessment struct {
	SourceMediaType  string `json:"source_media_type"`
	ExtractionResult string `json:"extraction_result"`

	OCREngine     string  `json:"ocr_engine"`
	EngineVersion *string `json:"engine_version,omitempty"`

	DetectedLanguage *string `json:"detected_language,omitempty"`

	TotalPages  *int `json:"total_pages,omitempty"`
	TotalFrames *int `json:"total_frames,omitempty"`

	ExtractedText   *string  `json:"extracted_text,omitempty"`
	ConfidenceScore *float64 `json:"confidence_score,omitempty"`

	WordCount      int `json:"word_count"`
	CharacterCount int `json:"character_count"`

	PageResults       []map[string]any `json:"page_results"`
	BoundingBoxData   []map[string]any `json:"bounding_box_data"`
	PreprocessingData map[string]any   `json:"preprocessing_data"`
	Metadata          map[string]any   `json:"metadata"`

	RequiresManualCorrection bool `json:"requires_manual_correction"`

	OutputFilePath *string `json:"output_file_path,omitempty"`
}

type MediaEngineHealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`

	SupportedJobTypes []string `json:"supported_job_types"`

	Runtime map[string]any `json:"runtime"`

	Timestamp time.Time `json:"timestamp"`
}
