package adaptivedeception

// ListFingerprintsRequest contains organization-scoped
// canary interaction fingerprint filters.
type ListFingerprintsRequest struct {
	CanaryFileID string `form:"canary_file_id"`

	EventType string `form:"event_type"`

	IsSuspicious *bool `form:"is_suspicious"`

	RansomwareSuspected *bool `form:"ransomware_suspected"`

	MinimumBehaviouralScore *float64 `form:"minimum_behavioural_score"`

	ObservedFrom string `form:"observed_from"`
	ObservedTo   string `form:"observed_to"`

	Page     int `form:"page"`
	PageSize int `form:"page_size"`
}

// ListFingerprintsResponse contains one paginated
// fingerprint result set.
type ListFingerprintsResponse struct {
	Items []CanaryInteractionFingerprint `json:"items"`

	Total int64 `json:"total"`

	Page     int `json:"page"`
	PageSize int `json:"page_size"`

	TotalPages int `json:"total_pages"`
}
