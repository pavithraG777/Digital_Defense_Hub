package deepfakeforensics

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// BuildAnalysisResultBundle converts one validated Python
// response into the specialized result and shared evidence
// analysis records persisted by PostgreSQL.
func BuildAnalysisResultBundle(
	source AnalysisSource,
	engineResponse *MediaEngineResponse,
) (*AnalysisResultBundle, error) {
	if engineResponse == nil ||
		!engineResponse.Success ||
		source.Job.ID == uuid.Nil ||
		source.Asset.ID == uuid.Nil ||
		source.Job.OrganizationID == uuid.Nil ||
		engineResponse.AnalysisJobID !=
			source.Job.ID ||
		engineResponse.OrganizationID !=
			source.Job.OrganizationID {
		return nil, ErrInvalidMediaEngineResponse
	}

	completedAt := engineResponse.ProcessedAt.UTC()
	if completedAt.IsZero() {
		completedAt = time.Now().UTC()
	}

	bundle := &AnalysisResultBundle{}

	result, confidence, summary, findings,
		reviewRequired, resultData, err :=
		mapSpecializedResult(
			source,
			engineResponse,
			bundle,
			completedAt,
		)
	if err != nil {
		return nil, err
	}

	jobID := source.Job.ID
	analysisTool := engineResponse.Runtime
	modelName := source.Model.ModelName
	modelVersion := source.Model.VersionNumber

	analysisMethod := AnalysisMethodHybrid
	trainedModelUsed :=
		source.Model.IsInferenceReady() &&
			(engineResponse.Runtime == "PYTORCH" ||
				engineResponse.Runtime == "ONNX_RUNTIME")
	if trainedModelUsed {
		analysisMethod = AnalysisMethodAIBased
	}

	analysisStatus := AnalysisStatusCompleted
	if reviewRequired {
		analysisStatus =
			AnalysisStatusReviewRequired
	}

	extractedMetadata := map[string]any{
		"runtime":              engineResponse.Runtime,
		"warnings":             engineResponse.Warnings,
		"media_type":           source.Asset.MediaType,
		"source_file_hash":     source.Asset.FileHash,
		"model_code":           source.Model.ModelCode,
		"model_status":         source.Model.ModelStatus,
		"model_version_status": source.Model.VersionStatus,
		"trained_model_used":   trainedModelUsed,
	}

	bundle.EvidenceAnalysis = EvidenceAnalysis{
		ID: uuid.New(),

		OrganizationID: source.Job.OrganizationID,
		AnalysisJobID:  &jobID,
		MediaAssetID:   source.Job.MediaAssetID,
		EvidenceID:     source.Job.EvidenceID,
		EvidenceFileID: source.Job.EvidenceFileID,

		AnalysisType:   evidenceAnalysisTypeForJob(source.Job.JobType),
		AnalysisMethod: analysisMethod,

		AnalysisTool: &analysisTool,

		AIModelName:    &modelName,
		AIModelVersion: &modelVersion,

		AnalyzedBy: source.Job.RequestedBy,

		AnalysisStatus: analysisStatus,
		Result:         &result,

		ConfidenceScore: confidence,

		Summary:  summary,
		Findings: findings,

		ExtractedMetadata: extractedMetadata,
		ResultData:        resultData,

		StartedAt:   source.Job.StartedAt,
		CompletedAt: &completedAt,

		CreatedAt: completedAt,
		UpdatedAt: completedAt,
	}

	return bundle, nil
}

func mapSpecializedResult(
	source AnalysisSource,
	engineResponse *MediaEngineResponse,
	bundle *AnalysisResultBundle,
	completedAt time.Time,
) (
	string,
	*float64,
	*string,
	*string,
	bool,
	map[string]any,
	error,
) {
	switch {
	case IsDeepfakeAssessmentJobType(source.Job.JobType):
		return mapDeepfakeResult(
			source,
			engineResponse,
			bundle,
			completedAt,
		)

	case IsForensicsJobType(source.Job.JobType):
		return mapForensicsResult(
			source,
			engineResponse,
			bundle,
			completedAt,
		)

	case NormalizeConstant(source.Job.JobType) == JobTypeAudioVisualConsistency,
		NormalizeConstant(source.Job.JobType) == JobTypeLipSyncConsistency,
		NormalizeConstant(source.Job.JobType) == JobTypeMetadataIntegrity:
		return mapConsistencyResult(
			source,
			engineResponse,
			bundle,
			completedAt,
		)

	case NormalizeConstant(source.Job.JobType) ==
		JobTypeOCRExtraction:
		return mapOCRResult(
			source,
			engineResponse,
			bundle,
			completedAt,
		)

	default:
		return "", nil, nil, nil, false, nil,
			fmt.Errorf(
				"%w: unsupported result job type",
				ErrInvalidMediaEngineResponse,
			)
	}
}

func mapDeepfakeResult(
	source AnalysisSource,
	engineResponse *MediaEngineResponse,
	bundle *AnalysisResultBundle,
	completedAt time.Time,
) (
	string,
	*float64,
	*string,
	*string,
	bool,
	map[string]any,
	error,
) {
	assessment := engineResponse.DeepfakeAssessment
	if assessment == nil {
		return "", nil, nil, nil, false, nil,
			ErrInvalidMediaEngineResponse
	}

	deepfakeProbability :=
		assessment.DeepfakeProbability
	authenticityProbability :=
		assessment.AuthenticityProbability
	confidence := assessment.ConfidenceScore
	summary := strings.TrimSpace(
		assessment.DetectionSummary,
	)

	// Persist only the evidence needed by the UI and report pipeline. The raw
	// extractor payload can be disproportionately large for phone photos and
	// is not needed to reproduce the displayed verdict.
	featureData := map[string]any{
		"signals":  assessment.Signals,
		"runtime":  engineResponse.Runtime,
		"warnings": engineResponse.Warnings,
	}
	if inference, ok := assessment.FeatureData["model_inference"]; ok {
		featureData["model_inference"] = inference
	}
	if heuristic, ok := assessment.FeatureData["heuristic_probability"]; ok {
		featureData["heuristic_probability"] = heuristic
	}

	regions, err := valuesToMaps(
		assessment.SuspiciousRegions,
	)
	if err != nil {
		return "", nil, nil, nil, false, nil, err
	}

	bundle.Deepfake = &DeepfakeDetectionResult{
		ID: uuid.New(),

		AnalysisJobID:  source.Job.ID,
		OrganizationID: source.Job.OrganizationID,
		MediaAssetID:   source.Job.MediaAssetID,
		EvidenceID:     source.Job.EvidenceID,
		EvidenceFileID: source.Job.EvidenceFileID,

		MediaType:       assessment.MediaType,
		DetectionResult: assessment.DetectionResult,

		DeepfakeProbability:     &deepfakeProbability,
		AuthenticityProbability: &authenticityProbability,
		ConfidenceScore:         &confidence,

		FacesDetected:            assessment.FacesDetected,
		ManipulatedFacesDetected: assessment.ManipulatedFacesDetected,
		TotalFramesAnalyzed:      assessment.TotalFramesAnalyzed,
		SuspiciousFrames:         assessment.SuspiciousFrames,

		AudioDurationSeconds: assessment.AudioDurationSeconds,

		LipSyncAnomalyDetected:        assessment.LipSyncAnomalyDetected,
		FacialArtifactDetected:        assessment.FacialArtifactDetected,
		AudioManipulationDetected:     assessment.AudioManipulationDetected,
		MetadataInconsistencyDetected: assessment.MetadataInconsistencyDetected,

		DetectionSummary: &summary,

		FeatureData:       featureData,
		SuspiciousRegions: regions,

		VisualizationFilePath: assessment.VisualizationFilePath,

		CreatedAt: completedAt,
	}

	// The detailed feature payload is already stored in the specialized
	// result. Keep the shared evidence record compact: phone-camera images can
	// produce a much larger forensic payload and serializing it twice blocked
	// workers after they had reported 85% progress.
	resultData := map[string]any{
		"media_type":                 assessment.MediaType,
		"detection_result":           assessment.DetectionResult,
		"deepfake_probability":       assessment.DeepfakeProbability,
		"authenticity_probability":   assessment.AuthenticityProbability,
		"confidence_score":           assessment.ConfidenceScore,
		"faces_detected":             assessment.FacesDetected,
		"manipulated_faces_detected": assessment.ManipulatedFacesDetected,
		"detection_summary":          assessment.DetectionSummary,
		"visualization_file_path":    assessment.VisualizationFilePath,
	}

	reviewRequired := false
	switch NormalizeConstant(
		assessment.DetectionResult,
	) {
	case DetectionResultSuspicious,
		DetectionResultLikelyDeepfake,
		DetectionResultDeepfake,
		DetectionResultInconclusive,
		DetectionResultError:
		reviewRequired = true
	}

	return evidenceAnalysisDeepfakeResult(assessment.DetectionResult),
		&confidence,
		&summary,
		nil,
		reviewRequired,
		resultData,
		nil
}

func mapForensicsResult(
	source AnalysisSource,
	engineResponse *MediaEngineResponse,
	bundle *AnalysisResultBundle,
	completedAt time.Time,
) (
	string,
	*float64,
	*string,
	*string,
	bool,
	map[string]any,
	error,
) {
	assessment := engineResponse.ForensicsAssessment
	if assessment == nil {
		return "", nil, nil, nil, false, nil,
			ErrInvalidMediaEngineResponse
	}

	confidence := assessment.ConfidenceScore
	summary := strings.TrimSpace(
		assessment.AnalysisSummary,
	)
	findingsText := strings.Join(
		assessment.Findings,
		"\n",
	)

	featureData := cloneMap(
		assessment.ForensicFeatureData,
	)
	featureData["signals"] = assessment.Signals
	featureData["runtime"] = engineResponse.Runtime
	featureData["warnings"] = engineResponse.Warnings

	locations, err := valuesToMaps(
		assessment.SuspiciousLocations,
	)
	if err != nil {
		return "", nil, nil, nil, false, nil, err
	}

	bundle.Forensics = &MediaForensicsResult{
		ID: uuid.New(),

		AnalysisJobID:  source.Job.ID,
		OrganizationID: source.Job.OrganizationID,
		MediaAssetID:   source.Job.MediaAssetID,
		EvidenceID:     source.Job.EvidenceID,
		EvidenceFileID: source.Job.EvidenceFileID,

		MediaType:       assessment.MediaType,
		ForensicResult:  assessment.ForensicResult,
		ConfidenceScore: &confidence,

		EditingTraceDetected:       assessment.EditingTraceDetected,
		CompressionAnomalyDetected: assessment.CompressionAnomalyDetected,
		CopyMoveDetected:           assessment.CopyMoveDetected,
		SplicingDetected:           assessment.SplicingDetected,
		FrameDuplicationDetected:   assessment.FrameDuplicationDetected,
		FrameDeletionDetected:      assessment.FrameDeletionDetected,
		AudioDiscontinuityDetected: assessment.AudioDiscontinuityDetected,
		NoiseInconsistencyDetected: assessment.NoiseInconsistencyDetected,
		TimestampAnomalyDetected:   assessment.TimestampAnomalyDetected,

		AnalysisSummary: &summary,
		Findings:        assessment.Findings,

		SuspiciousLocations: locations,
		ForensicFeatureData: featureData,

		VisualizationFilePath: assessment.VisualizationFilePath,

		CreatedAt: completedAt,
	}

	resultData, err := valueToMap(assessment)
	if err != nil {
		return "", nil, nil, nil, false, nil, err
	}

	reviewRequired := false
	switch NormalizeConstant(
		assessment.ForensicResult,
	) {
	case ForensicResultSuspicious,
		ForensicResultManipulated,
		ForensicResultCorrupted,
		ForensicResultInconclusive,
		ForensicResultError:
		reviewRequired = true
	}

	var findings *string
	if strings.TrimSpace(findingsText) != "" {
		findings = &findingsText
	}

	return evidenceAnalysisForensicsResult(assessment.ForensicResult),
		&confidence,
		&summary,
		findings,
		reviewRequired,
		resultData,
		nil
}

func mapOCRResult(
	source AnalysisSource,
	engineResponse *MediaEngineResponse,
	bundle *AnalysisResultBundle,
	completedAt time.Time,
) (
	string,
	*float64,
	*string,
	*string,
	bool,
	map[string]any,
	error,
) {
	assessment := engineResponse.OCRAssessment
	if assessment == nil {
		return "", nil, nil, nil, false, nil,
			ErrInvalidMediaEngineResponse
	}

	ocrEngine := strings.TrimSpace(
		assessment.OCREngine,
	)
	wordCount := assessment.WordCount
	characterCount := assessment.CharacterCount

	bundle.OCR = &OCRResult{
		ID: uuid.New(),

		AnalysisJobID:  source.Job.ID,
		OrganizationID: source.Job.OrganizationID,
		MediaAssetID:   source.Job.MediaAssetID,
		EvidenceID:     source.Job.EvidenceID,
		EvidenceFileID: source.Job.EvidenceFileID,

		SourceMediaType:  assessment.SourceMediaType,
		ExtractionResult: assessment.ExtractionResult,

		OCREngine:        &ocrEngine,
		DetectedLanguage: assessment.DetectedLanguage,

		TotalPages:  assessment.TotalPages,
		TotalFrames: assessment.TotalFrames,

		ExtractedText:   assessment.ExtractedText,
		ConfidenceScore: assessment.ConfidenceScore,

		WordCount:      &wordCount,
		CharacterCount: &characterCount,

		PageResults:     assessment.PageResults,
		BoundingBoxData: assessment.BoundingBoxData,

		RequiresManualCorrection: assessment.RequiresManualCorrection,

		CreatedAt: completedAt,
		UpdatedAt: completedAt,
	}

	resultData, err := valueToMap(assessment)
	if err != nil {
		return "", nil, nil, nil, false, nil, err
	}

	summaryText := fmt.Sprintf(
		"OCR result %s with %d extracted words",
		assessment.ExtractionResult,
		assessment.WordCount,
	)

	reviewRequired :=
		assessment.RequiresManualCorrection
	switch NormalizeConstant(
		assessment.ExtractionResult,
	) {
	case "PARTIAL", "INCONCLUSIVE", "ERROR":
		reviewRequired = true
	}

	return evidenceAnalysisOCRResult(assessment.ExtractionResult),
		assessment.ConfidenceScore,
		&summaryText,
		nil,
		reviewRequired,
		resultData,
		nil
}

func mapConsistencyResult(
	source AnalysisSource,
	engineResponse *MediaEngineResponse,
	bundle *AnalysisResultBundle,
	completedAt time.Time,
) (
	string,
	*float64,
	*string,
	*string,
	bool,
	map[string]any,
	error,
) {
	assessment := engineResponse.ConsistencyAssessment
	if assessment == nil {
		return "", nil, nil, nil, false, nil,
			ErrInvalidMediaEngineResponse
	}

	confidence := assessment.ConfidenceScore
	summary := strings.TrimSpace(assessment.ConsistencyResult)

	featureData := cloneMap(assessment.FeatureData)
	featureData["signals"] = assessment.Signals
	featureData["runtime"] = engineResponse.Runtime
	featureData["warnings"] = engineResponse.Warnings

	regions, err := valuesToMaps(assessment.SuspiciousRegions)
	if err != nil {
		return "", nil, nil, nil, false, nil, err
	}

	bundle.Forensics = &MediaForensicsResult{
		ID: uuid.New(),

		AnalysisJobID:  source.Job.ID,
		OrganizationID: source.Job.OrganizationID,
		MediaAssetID:   source.Job.MediaAssetID,
		EvidenceID:     source.Job.EvidenceID,
		EvidenceFileID: source.Job.EvidenceFileID,

		MediaType:       assessment.MediaType,
		ForensicResult:  assessment.ConsistencyResult,
		ConfidenceScore: &confidence,

		AnalysisSummary: &summary,

		SuspiciousLocations: regions,
		ForensicFeatureData: featureData,

		VisualizationFilePath: assessment.VisualizationFilePath,

		CreatedAt: completedAt,
	}

	resultData, err := valueToMap(assessment)
	if err != nil {
		return "", nil, nil, nil, false, nil, err
	}

	reviewRequired := false
	// treat non-clean consistency results as review-required
	switch NormalizeConstant(assessment.ConsistencyResult) {
	case "CLEAN":
		reviewRequired = false
	default:
		reviewRequired = true
	}

	return evidenceAnalysisForensicsResult(assessment.ConsistencyResult),
		&confidence,
		&summary,
		nil,
		reviewRequired,
		resultData,
		nil
}

// evidenceAnalysisTypeForJob maps specialized media job
// types to the shared evidence_analysis domain.
func evidenceAnalysisTypeForJob(
	jobType string,
) string {
	normalizedJobType := NormalizeConstant(jobType)

	if IsDeepfakeAssessmentJobType(normalizedJobType) {
		return "DEEPFAKE_DETECTION"
	}

	return normalizedJobType
}

// evidenceAnalysisDeepfakeResult maps detailed deepfake
// outcomes to values allowed by evidence_analysis.result.
func evidenceAnalysisDeepfakeResult(
	detectionResult string,
) string {
	switch NormalizeConstant(detectionResult) {
	case DetectionResultAuthentic,
		DetectionResultLikelyAuthentic:
		return "AUTHENTIC"

	case DetectionResultSuspicious:
		return "SUSPICIOUS"

	case DetectionResultLikelyDeepfake,
		DetectionResultDeepfake:
		return "MANIPULATED"

	case DetectionResultError:
		return "ERROR"

	default:
		return "INCONCLUSIVE"
	}
}

// evidenceAnalysisForensicsResult maps specialized
// forensic outcomes to the shared result domain.
func evidenceAnalysisForensicsResult(
	forensicResult string,
) string {
	switch NormalizeConstant(forensicResult) {
	case ForensicResultAuthentic:
		return "AUTHENTIC"

	case ForensicResultSuspicious,
		ForensicResultCorrupted:
		return "SUSPICIOUS"

	case ForensicResultManipulated:
		return "MANIPULATED"

	case ForensicResultError:
		return "ERROR"

	default:
		return "INCONCLUSIVE"
	}
}

// evidenceAnalysisOCRResult records the generic outcome in
// evidence_analysis while the exact OCR result remains in
// ocr_results and result_data.
func evidenceAnalysisOCRResult(
	extractionResult string,
) string {
	switch NormalizeConstant(extractionResult) {
	case "TEXT_FOUND":
		return "CLEAN"

	case "ERROR":
		return "ERROR"

	default:
		return "INCONCLUSIVE"
	}
}

func cloneMap(
	source map[string]any,
) map[string]any {
	result := make(
		map[string]any,
		len(source)+3,
	)
	for key, value := range source {
		result[key] = value
	}

	return result
}

func valueToMap(value any) (
	map[string]any,
	error,
) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf(
			"encode analysis result data: %w",
			err,
		)
	}

	result := map[string]any{}
	if err = json.Unmarshal(
		encoded,
		&result,
	); err != nil {
		return nil, fmt.Errorf(
			"decode analysis result data: %w",
			err,
		)
	}

	return result, nil
}

func valuesToMaps[T any](
	values []T,
) ([]map[string]any, error) {
	if len(values) == 0 {
		return []map[string]any{}, nil
	}

	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf(
			"encode suspicious locations: %w",
			err,
		)
	}

	result := make(
		[]map[string]any,
		0,
		len(values),
	)
	if err = json.Unmarshal(
		encoded,
		&result,
	); err != nil {
		return nil, fmt.Errorf(
			"decode suspicious locations: %w",
			err,
		)
	}

	return result, nil
}
