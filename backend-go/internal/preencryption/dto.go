package preencryption

import (
	"time"

	"github.com/google/uuid"
)

// ListDetectionsQuery contains supported detection filters.
type ListDetectionsQuery struct {
	RiskLevel       string `form:"risk_level"`
	Classification  string `form:"classification"`
	DetectionStage  string `form:"detection_stage"`
	DetectionMethod string `form:"detection_method"`

	Status       string `form:"status"`
	ActionStatus string `form:"action_status"`

	DeviceIdentifier string `form:"device_identifier"`
	ProcessName      string `form:"process_name"`

	RequiresHumanReview *bool `form:"requires_human_review"`

	DetectedFrom string `form:"detected_from"`
	DetectedTo   string `form:"detected_to"`

	Page     int `form:"page"`
	PageSize int `form:"page_size"`
}

// UpdateDetectionStatusRequest updates the investigation
// and endpoint-action state of one detection.
type UpdateDetectionStatusRequest struct {
	Status *string `json:"status,omitempty"`

	ActionStatus *string `json:"action_status,omitempty"`

	ReviewNotes *string `json:"review_notes,omitempty" binding:"omitempty,max=4000"`

	MitigationSummary *string `json:"mitigation_summary,omitempty" binding:"omitempty,max=4000"`
}

// RiskFactor describes one behavioural factor that
// contributed to a ransomware detection score.
type RiskFactor struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description,omitempty"`

	Weight       float64 `json:"weight"`
	Score        float64 `json:"score"`
	Contribution float64 `json:"contribution"`

	SignalCount int `json:"signal_count,omitempty"`
}

// RecommendedAction describes one response action suggested
// by the pre-encryption detection engine.
type RecommendedAction struct {
	Code        string `json:"code"`
	Title       string `json:"title"`
	Description string `json:"description"`

	Priority string `json:"priority"`

	Automatic bool `json:"automatic"`
}

// DetectionEventResponse contains the linked file-event
// information required for investigation.
type DetectionEventResponse struct {
	LinkID uuid.UUID `json:"link_id"`

	FileEventID     uuid.UUID `json:"file_event_id"`
	EventCode       string    `json:"event_code"`
	EventType       string    `json:"event_type"`
	EventSource     string    `json:"event_source"`
	SourceType      string    `json:"source_type"`
	DetectionMethod string    `json:"detection_method"`

	FileName         string  `json:"file_name"`
	FilePath         string  `json:"file_path"`
	PreviousFilePath *string `json:"previous_file_path,omitempty"`
	FileExtension    *string `json:"file_extension,omitempty"`
	FileSizeBefore   *int64  `json:"file_size_before,omitempty"`
	FileSizeAfter    *int64  `json:"file_size_after,omitempty"`

	PreviousHash *string `json:"previous_hash,omitempty"`
	CurrentHash  *string `json:"current_hash,omitempty"`

	ProcessID      *int64  `json:"process_id,omitempty"`
	ProcessName    *string `json:"process_name,omitempty"`
	ExecutablePath *string `json:"executable_path,omitempty"`

	ParentProcessID   *int64  `json:"parent_process_id,omitempty"`
	ParentProcessName *string `json:"parent_process_name,omitempty"`
	CommandLine       *string `json:"command_line,omitempty"`

	DeviceName       *string `json:"device_name,omitempty"`
	DeviceIdentifier *string `json:"device_identifier,omitempty"`

	Severity     string `json:"severity"`
	ThreatScore  int    `json:"threat_score"`
	IsSuspicious bool   `json:"is_suspicious"`

	SignalTypes       []string `json:"signal_types"`
	ContributionScore float64  `json:"contribution_score"`

	OccurredAt time.Time `json:"occurred_at"`
	LinkedAt   time.Time `json:"linked_at"`
}

// DetectionDetailsResponse returns a detection together
// with all contributing file events.
type DetectionDetailsResponse struct {
	Detection Detection `json:"detection"`

	Events []DetectionEventResponse `json:"events"`
}

// ListDetectionsResponse contains paginated detections.
type ListDetectionsResponse struct {
	Items []Detection `json:"items"`

	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalPages int   `json:"total_pages"`
}

// DetectionEngineHealthResponse represents the Python
// pre-encryption scoring engine health.
type DetectionEngineHealthResponse struct {
	Status string `json:"status"`
}
