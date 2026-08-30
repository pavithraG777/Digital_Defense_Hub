package deepfakeforensics

import "strings"

const (
	MediaTypeImage    = "IMAGE"
	MediaTypeVideo    = "VIDEO"
	MediaTypeAudio    = "AUDIO"
	MediaTypeDocument = "DOCUMENT"
)

const (
	AnalysisModeDeepfake  = "DEEPFAKE"
	AnalysisModeSynthetic = "SYNTHETIC"
	AnalysisModeForensics = "FORENSICS"
	AnalysisModeCombined  = "COMBINED"
	AnalysisModeOCR       = "OCR"
)

const (
	AnalysisModeCrossModal = "CROSS_MODAL"
)

const (
	JobTypeDeepfakeImage  = "DEEPFAKE_IMAGE_DETECTION"
	JobTypeSyntheticImage = "AI_GENERATED_IMAGE_DETECTION"
	JobTypeDeepfakeVideo  = "DEEPFAKE_VIDEO_DETECTION"
	JobTypeDeepfakeAudio  = "DEEPFAKE_AUDIO_DETECTION"

	JobTypeImageForensics    = "IMAGE_FORENSICS"
	JobTypeVideoForensics    = "VIDEO_FORENSICS"
	JobTypeAudioForensics    = "AUDIO_FORENSICS"
	JobTypeDocumentForensics = "DOCUMENT_FORENSICS"

	JobTypeOCRExtraction = "OCR_EXTRACTION"
)

const (
	JobTypeAudioVisualConsistency = "AUDIO_VISUAL_CONSISTENCY"
	JobTypeLipSyncConsistency     = "LIP_SYNC_CONSISTENCY"
	JobTypeMetadataIntegrity      = "METADATA_INTEGRITY"
)

const (
	JobStatusPending        = "PENDING"
	JobStatusQueued         = "QUEUED"
	JobStatusProcessing     = "PROCESSING"
	JobStatusCompleted      = "COMPLETED"
	JobStatusFailed         = "FAILED"
	JobStatusCancelled      = "CANCELLED"
	JobStatusRetrying       = "RETRYING"
	JobStatusReviewRequired = "REVIEW_REQUIRED"
)

const (
	JobPriorityLow    = "LOW"
	JobPriorityNormal = "NORMAL"
	JobPriorityHigh   = "HIGH"
	JobPriorityUrgent = "URGENT"
)

const (
	DetectionResultAuthentic       = "AUTHENTIC"
	DetectionResultLikelyAuthentic = "LIKELY_AUTHENTIC"
	DetectionResultSuspicious      = "SUSPICIOUS"
	DetectionResultLikelyDeepfake  = "LIKELY_DEEPFAKE"
	DetectionResultDeepfake        = "DEEPFAKE"
	DetectionResultInconclusive    = "INCONCLUSIVE"
	DetectionResultError           = "ERROR"
)

const (
	ForensicResultAuthentic    = "AUTHENTIC"
	ForensicResultSuspicious   = "SUSPICIOUS"
	ForensicResultManipulated  = "MANIPULATED"
	ForensicResultCorrupted    = "CORRUPTED"
	ForensicResultInconclusive = "INCONCLUSIVE"
	ForensicResultError        = "ERROR"
)

const (
	AnalysisMethodAIBased = "AI_BASED"
	AnalysisMethodHybrid  = "HYBRID"
)

const (
	AnalysisStatusPending        = "PENDING"
	AnalysisStatusQueued         = "QUEUED"
	AnalysisStatusProcessing     = "PROCESSING"
	AnalysisStatusCompleted      = "COMPLETED"
	AnalysisStatusFailed         = "FAILED"
	AnalysisStatusCancelled      = "CANCELLED"
	AnalysisStatusReviewRequired = "REVIEW_REQUIRED"
	AnalysisStatusVerified       = "VERIFIED"
)

func NormalizeConstant(value string) string {
	return strings.ToUpper(
		strings.TrimSpace(value),
	)
}

func IsSupportedMediaType(value string) bool {
	switch NormalizeConstant(value) {
	case MediaTypeImage,
		MediaTypeVideo,
		MediaTypeAudio,
		MediaTypeDocument:
		return true

	default:
		return false
	}
}

func IsSupportedAnalysisMode(value string) bool {
	switch NormalizeConstant(value) {
	case AnalysisModeDeepfake,
		AnalysisModeSynthetic,
		AnalysisModeForensics,
		AnalysisModeCombined,
		AnalysisModeOCR,
		AnalysisModeCrossModal:
		return true

	default:
		return false
	}
}

func IsSupportedJobPriority(value string) bool {
	switch NormalizeConstant(value) {
	case JobPriorityLow,
		JobPriorityNormal,
		JobPriorityHigh,
		JobPriorityUrgent:
		return true

	default:
		return false
	}
}

func IsDeepfakeJobType(value string) bool {
	switch NormalizeConstant(value) {
	case JobTypeDeepfakeImage,
		JobTypeDeepfakeVideo,
		JobTypeDeepfakeAudio:
		return true

	default:
		return false
	}
}

func IsSyntheticJobType(value string) bool {
	return NormalizeConstant(value) == JobTypeSyntheticImage
}

// IsDeepfakeAssessmentJobType identifies jobs that use the shared
// deepfake_assessment response and persistence schema. The synthetic image
// detector is operationally separate from the face-manipulation detector, but
// both return the same binary authenticity assessment contract.
func IsDeepfakeAssessmentJobType(value string) bool {
	return IsDeepfakeJobType(value) || IsSyntheticJobType(value)
}

func IsForensicsJobType(value string) bool {
	switch NormalizeConstant(value) {
	case JobTypeImageForensics,
		JobTypeVideoForensics,
		JobTypeAudioForensics,
		JobTypeDocumentForensics:
		return true

	default:
		return false
	}
}

func IsSupportedJobType(value string) bool {
	return IsDeepfakeJobType(value) ||
		IsSyntheticJobType(value) ||
		IsForensicsJobType(value) ||
		NormalizeConstant(value) == JobTypeOCRExtraction ||
		NormalizeConstant(value) == JobTypeAudioVisualConsistency ||
		NormalizeConstant(value) == JobTypeLipSyncConsistency ||
		NormalizeConstant(value) == JobTypeMetadataIntegrity

}
