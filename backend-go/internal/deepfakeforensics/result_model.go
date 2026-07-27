package deepfakeforensics

import (
	"time"

	"github.com/google/uuid"
)

// DeepfakeDetectionResult stores one image, video or audio
// synthetic-media assessment.
type DeepfakeDetectionResult struct {
	ID uuid.UUID `json:"id"`

	AnalysisJobID  uuid.UUID  `json:"analysis_job_id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	MediaAssetID   *uuid.UUID `json:"media_asset_id,omitempty"`
	EvidenceID     *uuid.UUID `json:"evidence_id,omitempty"`
	EvidenceFileID *uuid.UUID `json:"evidence_file_id,omitempty"`

	MediaType       string `json:"media_type"`
	DetectionResult string `json:"detection_result"`

	DeepfakeProbability     *float64 `json:"deepfake_probability,omitempty"`
	AuthenticityProbability *float64 `json:"authenticity_probability,omitempty"`
	ConfidenceScore         *float64 `json:"confidence_score,omitempty"`

	FacesDetected            *int `json:"faces_detected,omitempty"`
	ManipulatedFacesDetected *int `json:"manipulated_faces_detected,omitempty"`
	TotalFramesAnalyzed      *int `json:"total_frames_analyzed,omitempty"`
	SuspiciousFrames         *int `json:"suspicious_frames,omitempty"`

	AudioDurationSeconds *float64 `json:"audio_duration_seconds,omitempty"`

	LipSyncAnomalyDetected        bool `json:"lip_sync_anomaly_detected"`
	FacialArtifactDetected        bool `json:"facial_artifact_detected"`
	AudioManipulationDetected     bool `json:"audio_manipulation_detected"`
	MetadataInconsistencyDetected bool `json:"metadata_inconsistency_detected"`

	DetectionSummary *string `json:"detection_summary,omitempty"`

	FeatureData       map[string]any   `json:"feature_data,omitempty"`
	SuspiciousRegions []map[string]any `json:"suspicious_regions,omitempty"`

	VisualizationFilePath *string `json:"visualization_file_path,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// MediaForensicsResult stores classical image, video or
// audio forensic findings.
type MediaForensicsResult struct {
	ID uuid.UUID `json:"id"`

	AnalysisJobID  uuid.UUID  `json:"analysis_job_id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	MediaAssetID   *uuid.UUID `json:"media_asset_id,omitempty"`
	EvidenceID     *uuid.UUID `json:"evidence_id,omitempty"`
	EvidenceFileID *uuid.UUID `json:"evidence_file_id,omitempty"`

	MediaType       string   `json:"media_type"`
	ForensicResult  string   `json:"forensic_result"`
	ConfidenceScore *float64 `json:"confidence_score,omitempty"`

	EditingTraceDetected       bool `json:"editing_trace_detected"`
	CompressionAnomalyDetected bool `json:"compression_anomaly_detected"`
	CopyMoveDetected           bool `json:"copy_move_detected"`
	SplicingDetected           bool `json:"splicing_detected"`
	FrameDuplicationDetected   bool `json:"frame_duplication_detected"`
	FrameDeletionDetected      bool `json:"frame_deletion_detected"`
	AudioDiscontinuityDetected bool `json:"audio_discontinuity_detected"`
	NoiseInconsistencyDetected bool `json:"noise_inconsistency_detected"`
	TimestampAnomalyDetected   bool `json:"timestamp_anomaly_detected"`

	AnalysisSummary *string  `json:"analysis_summary,omitempty"`
	Findings        []string `json:"findings,omitempty"`

	SuspiciousLocations []map[string]any `json:"suspicious_locations,omitempty"`
	ForensicFeatureData map[string]any   `json:"forensic_feature_data,omitempty"`

	VisualizationFilePath *string `json:"visualization_file_path,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// OCRResult stores offline OCR text, confidence,
// page/frame information and optional correction state.
type OCRResult struct {
	ID uuid.UUID `json:"id"`

	AnalysisJobID  uuid.UUID  `json:"analysis_job_id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	MediaAssetID   *uuid.UUID `json:"media_asset_id,omitempty"`
	EvidenceID     *uuid.UUID `json:"evidence_id,omitempty"`
	EvidenceFileID *uuid.UUID `json:"evidence_file_id,omitempty"`

	SourceMediaType  string `json:"source_media_type"`
	ExtractionResult string `json:"extraction_result"`

	OCREngine        *string `json:"ocr_engine,omitempty"`
	DetectedLanguage *string `json:"detected_language,omitempty"`

	TotalPages  *int `json:"total_pages,omitempty"`
	TotalFrames *int `json:"total_frames,omitempty"`

	ExtractedText   *string  `json:"extracted_text,omitempty"`
	ConfidenceScore *float64 `json:"confidence_score,omitempty"`

	WordCount      *int `json:"word_count,omitempty"`
	CharacterCount *int `json:"character_count,omitempty"`

	PageResults     []map[string]any `json:"page_results,omitempty"`
	BoundingBoxData []map[string]any `json:"bounding_box_data,omitempty"`

	RequiresManualCorrection bool `json:"requires_manual_correction"`

	CorrectedText *string    `json:"corrected_text,omitempty"`
	CorrectedBy   *uuid.UUID `json:"corrected_by,omitempty"`
	CorrectedAt   *time.Time `json:"corrected_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EvidenceAnalysis stores the normalized high-level
// analysis record shared by evidence and direct media jobs.
type EvidenceAnalysis struct {
	ID uuid.UUID `json:"id"`

	OrganizationID uuid.UUID  `json:"organization_id"`
	AnalysisJobID  *uuid.UUID `json:"analysis_job_id,omitempty"`
	MediaAssetID   *uuid.UUID `json:"media_asset_id,omitempty"`
	EvidenceID     *uuid.UUID `json:"evidence_id,omitempty"`
	EvidenceFileID *uuid.UUID `json:"evidence_file_id,omitempty"`

	AnalysisType   string `json:"analysis_type"`
	AnalysisMethod string `json:"analysis_method"`

	AnalysisTool *string `json:"analysis_tool,omitempty"`
	ToolVersion  *string `json:"tool_version,omitempty"`

	AIModelName    *string `json:"ai_model_name,omitempty"`
	AIModelVersion *string `json:"ai_model_version,omitempty"`

	AnalyzedBy *uuid.UUID `json:"analyzed_by,omitempty"`

	AnalysisStatus string  `json:"analysis_status"`
	Result         *string `json:"result,omitempty"`

	ConfidenceScore *float64 `json:"confidence_score,omitempty"`

	Summary        *string `json:"summary,omitempty"`
	Findings       *string `json:"findings,omitempty"`
	Recommendation *string `json:"recommendation,omitempty"`

	ExtractedMetadata map[string]any `json:"extracted_metadata,omitempty"`
	ResultData        map[string]any `json:"result_data,omitempty"`

	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	ReviewedBy  *uuid.UUID `json:"reviewed_by,omitempty"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
	ReviewNotes *string    `json:"review_notes,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AnalysisResultBundle contains exactly one specialized
// result and the shared evidence-analysis summary.
type AnalysisResultBundle struct {
	Deepfake  *DeepfakeDetectionResult `json:"deepfake,omitempty"`
	Forensics *MediaForensicsResult    `json:"forensics,omitempty"`
	OCR       *OCRResult               `json:"ocr,omitempty"`

	EvidenceAnalysis EvidenceAnalysis `json:"evidence_analysis"`
}
