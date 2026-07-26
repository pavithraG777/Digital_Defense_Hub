package adaptivedeception

// CheckCanaryHealthRequest controls an on-demand
// canary filesystem health verification.
type CheckCanaryHealthRequest struct {
	CheckType string `json:"check_type,omitempty"`
}

// CanaryHealthDetailsResponse combines the current canary
// database state with its most recent health-check result.
type CanaryHealthDetailsResponse struct {
	CanaryFile        CanaryFileSnapshot `json:"canary_file"`
	LatestHealthCheck CanaryHealthCheck  `json:"latest_health_check"`
}

// RotateCanaryRequest controls a manual dynamic
// canary rotation request.
type RotateCanaryRequest struct {
	RotationReason string `json:"rotation_reason,omitempty"`

	RotationStrategy string `json:"rotation_strategy,omitempty"`

	NewFileName string `json:"new_file_name,omitempty"`
}
