package deepfakeforensics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GetAnalysisResult returns the specialized result and
// shared evidence-analysis record for one organization job.
func (r *Repository) GetAnalysisResult(
	ctx context.Context,
	organizationID uuid.UUID,
	analysisJobID uuid.UUID,
) (*AnalysisResultBundle, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}
	if ctx == nil ||
		organizationID == uuid.Nil ||
		analysisJobID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	job, err := r.GetAnalysisJob(
		ctx,
		organizationID,
		analysisJobID,
	)
	if err != nil {
		return nil, err
	}

	if NormalizeConstant(job.Status) !=
		JobStatusCompleted &&
		NormalizeConstant(job.Status) !=
			JobStatusReviewRequired {
		return nil, ErrAnalysisResultNotFound
	}

	evidenceAnalysis, err :=
		r.getEvidenceAnalysisByJob(
			ctx,
			organizationID,
			analysisJobID,
		)
	if err != nil {
		return nil, err
	}

	bundle := &AnalysisResultBundle{
		EvidenceAnalysis: *evidenceAnalysis,
	}

	switch {
	case IsDeepfakeAssessmentJobType(job.JobType):
		bundle.Deepfake, err =
			r.getDeepfakeResultByJob(
				ctx,
				organizationID,
				analysisJobID,
			)

	case IsForensicsJobType(job.JobType):
		bundle.Forensics, err =
			r.getForensicsResultByJob(
				ctx,
				organizationID,
				analysisJobID,
			)

	case NormalizeConstant(job.JobType) ==
		JobTypeOCRExtraction:
		bundle.OCR, err =
			r.getOCRResultByJob(
				ctx,
				organizationID,
				analysisJobID,
			)

	default:
		return nil, ErrAnalysisResultNotFound
	}
	if err != nil {
		return nil, err
	}

	return bundle, nil
}

func (r *Repository) getDeepfakeResultByJob(
	ctx context.Context,
	organizationID uuid.UUID,
	analysisJobID uuid.UUID,
) (*DeepfakeDetectionResult, error) {
	result, err := scanDeepfakeDetectionResult(
		r.databasePool.QueryRow(
			ctx,
			`
				SELECT
					id,
					analysis_job_id,
					organization_id,
					media_asset_id,
					evidence_id,
					evidence_file_id,
					media_type,
					detection_result,
					deepfake_probability,
					authenticity_probability,
					confidence_score,
					faces_detected,
					manipulated_faces_detected,
					total_frames_analyzed,
					suspicious_frames,
					audio_duration_seconds,
					lip_sync_anomaly_detected,
					facial_artifact_detected,
					audio_manipulation_detected,
					metadata_inconsistency_detected,
					detection_summary,
					COALESCE(
						feature_data,
						'{}'::jsonb
					),
					COALESCE(
						suspicious_regions,
						'[]'::jsonb
					),
					visualization_file_path,
					created_at
				FROM deepfake_detection_results
				WHERE organization_id = $1
					AND analysis_job_id = $2
			`,
			organizationID,
			analysisJobID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisResultNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"get deepfake detection result: %w",
			err,
		)
	}

	return result, nil
}

func (r *Repository) getForensicsResultByJob(
	ctx context.Context,
	organizationID uuid.UUID,
	analysisJobID uuid.UUID,
) (*MediaForensicsResult, error) {
	result, err := scanMediaForensicsResult(
		r.databasePool.QueryRow(
			ctx,
			`
				SELECT
					id,
					analysis_job_id,
					organization_id,
					media_asset_id,
					evidence_id,
					evidence_file_id,
					media_type,
					forensic_result,
					confidence_score,
					editing_trace_detected,
					compression_anomaly_detected,
					copy_move_detected,
					splicing_detected,
					frame_duplication_detected,
					frame_deletion_detected,
					audio_discontinuity_detected,
					noise_inconsistency_detected,
					timestamp_anomaly_detected,
					analysis_summary,
					findings,
					COALESCE(
						suspicious_locations,
						'[]'::jsonb
					),
					COALESCE(
						forensic_feature_data,
						'{}'::jsonb
					),
					visualization_file_path,
					created_at
				FROM media_forensics_results
				WHERE organization_id = $1
					AND analysis_job_id = $2
			`,
			organizationID,
			analysisJobID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisResultNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"get media forensics result: %w",
			err,
		)
	}

	return result, nil
}

func (r *Repository) getOCRResultByJob(
	ctx context.Context,
	organizationID uuid.UUID,
	analysisJobID uuid.UUID,
) (*OCRResult, error) {
	result, err := scanOCRResult(
		r.databasePool.QueryRow(
			ctx,
			`
				SELECT
					id,
					analysis_job_id,
					organization_id,
					media_asset_id,
					evidence_id,
					evidence_file_id,
					source_media_type,
					extraction_result,
					ocr_engine,
					detected_language,
					total_pages,
					total_frames,
					extracted_text,
					confidence_score,
					word_count,
					character_count,
					COALESCE(
						page_results,
						'[]'::jsonb
					),
					COALESCE(
						bounding_box_data,
						'[]'::jsonb
					),
					requires_manual_correction,
					corrected_text,
					corrected_by,
					corrected_at,
					created_at,
					updated_at
				FROM ocr_results
				WHERE organization_id = $1
					AND analysis_job_id = $2
			`,
			organizationID,
			analysisJobID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisResultNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"get OCR result: %w",
			err,
		)
	}

	return result, nil
}

func (r *Repository) getEvidenceAnalysisByJob(
	ctx context.Context,
	organizationID uuid.UUID,
	analysisJobID uuid.UUID,
) (*EvidenceAnalysis, error) {
	analysis, err := scanEvidenceAnalysis(
		r.databasePool.QueryRow(
			ctx,
			`
				SELECT
					id,
					organization_id,
					analysis_job_id,
					media_asset_id,
					evidence_id,
					evidence_file_id,
					analysis_type,
					analysis_method,
					analysis_tool,
					tool_version,
					ai_model_name,
					ai_model_version,
					analyzed_by,
					analysis_status,
					result,
					confidence_score,
					summary,
					findings,
					recommendation,
					COALESCE(
						extracted_metadata,
						'{}'::jsonb
					),
					COALESCE(
						result_data,
						'{}'::jsonb
					),
					started_at,
					completed_at,
					reviewed_by,
					reviewed_at,
					review_notes,
					created_at,
					updated_at
				FROM evidence_analysis
				WHERE organization_id = $1
					AND analysis_job_id = $2
				ORDER BY created_at DESC
				LIMIT 1
			`,
			organizationID,
			analysisJobID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisResultNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"get evidence analysis result: %w",
			err,
		)
	}

	return analysis, nil
}

func scanDeepfakeDetectionResult(
	scanner databaseRowScanner,
) (*DeepfakeDetectionResult, error) {
	if scanner == nil {
		return nil, ErrRepositoryUnavailable
	}

	result := &DeepfakeDetectionResult{}
	var featureDataJSON []byte
	var suspiciousRegionsJSON []byte

	err := scanner.Scan(
		&result.ID,
		&result.AnalysisJobID,
		&result.OrganizationID,
		&result.MediaAssetID,
		&result.EvidenceID,
		&result.EvidenceFileID,
		&result.MediaType,
		&result.DetectionResult,
		&result.DeepfakeProbability,
		&result.AuthenticityProbability,
		&result.ConfidenceScore,
		&result.FacesDetected,
		&result.ManipulatedFacesDetected,
		&result.TotalFramesAnalyzed,
		&result.SuspiciousFrames,
		&result.AudioDurationSeconds,
		&result.LipSyncAnomalyDetected,
		&result.FacialArtifactDetected,
		&result.AudioManipulationDetected,
		&result.MetadataInconsistencyDetected,
		&result.DetectionSummary,
		&featureDataJSON,
		&suspiciousRegionsJSON,
		&result.VisualizationFilePath,
		&result.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	result.FeatureData = map[string]any{}
	if err = decodeStoredAnalysisJSON(
		featureDataJSON,
		&result.FeatureData,
	); err != nil {
		return nil, err
	}

	result.SuspiciousRegions =
		[]map[string]any{}
	if err = decodeStoredAnalysisJSON(
		suspiciousRegionsJSON,
		&result.SuspiciousRegions,
	); err != nil {
		return nil, err
	}

	return result, nil
}

func scanMediaForensicsResult(
	scanner databaseRowScanner,
) (*MediaForensicsResult, error) {
	if scanner == nil {
		return nil, ErrRepositoryUnavailable
	}

	result := &MediaForensicsResult{}
	var findingsText *string
	var suspiciousLocationsJSON []byte
	var forensicFeatureDataJSON []byte

	err := scanner.Scan(
		&result.ID,
		&result.AnalysisJobID,
		&result.OrganizationID,
		&result.MediaAssetID,
		&result.EvidenceID,
		&result.EvidenceFileID,
		&result.MediaType,
		&result.ForensicResult,
		&result.ConfidenceScore,
		&result.EditingTraceDetected,
		&result.CompressionAnomalyDetected,
		&result.CopyMoveDetected,
		&result.SplicingDetected,
		&result.FrameDuplicationDetected,
		&result.FrameDeletionDetected,
		&result.AudioDiscontinuityDetected,
		&result.NoiseInconsistencyDetected,
		&result.TimestampAnomalyDetected,
		&result.AnalysisSummary,
		&findingsText,
		&suspiciousLocationsJSON,
		&forensicFeatureDataJSON,
		&result.VisualizationFilePath,
		&result.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	result.Findings = splitStoredFindings(
		findingsText,
	)

	result.SuspiciousLocations =
		[]map[string]any{}
	if err = decodeStoredAnalysisJSON(
		suspiciousLocationsJSON,
		&result.SuspiciousLocations,
	); err != nil {
		return nil, err
	}

	result.ForensicFeatureData =
		map[string]any{}
	if err = decodeStoredAnalysisJSON(
		forensicFeatureDataJSON,
		&result.ForensicFeatureData,
	); err != nil {
		return nil, err
	}

	return result, nil
}

func scanOCRResult(
	scanner databaseRowScanner,
) (*OCRResult, error) {
	if scanner == nil {
		return nil, ErrRepositoryUnavailable
	}

	result := &OCRResult{}
	var pageResultsJSON []byte
	var boundingBoxDataJSON []byte

	err := scanner.Scan(
		&result.ID,
		&result.AnalysisJobID,
		&result.OrganizationID,
		&result.MediaAssetID,
		&result.EvidenceID,
		&result.EvidenceFileID,
		&result.SourceMediaType,
		&result.ExtractionResult,
		&result.OCREngine,
		&result.DetectedLanguage,
		&result.TotalPages,
		&result.TotalFrames,
		&result.ExtractedText,
		&result.ConfidenceScore,
		&result.WordCount,
		&result.CharacterCount,
		&pageResultsJSON,
		&boundingBoxDataJSON,
		&result.RequiresManualCorrection,
		&result.CorrectedText,
		&result.CorrectedBy,
		&result.CorrectedAt,
		&result.CreatedAt,
		&result.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	result.PageResults = []map[string]any{}
	if err = decodeStoredAnalysisJSON(
		pageResultsJSON,
		&result.PageResults,
	); err != nil {
		return nil, err
	}

	result.BoundingBoxData =
		[]map[string]any{}
	if err = decodeStoredAnalysisJSON(
		boundingBoxDataJSON,
		&result.BoundingBoxData,
	); err != nil {
		return nil, err
	}

	return result, nil
}

func scanEvidenceAnalysis(
	scanner databaseRowScanner,
) (*EvidenceAnalysis, error) {
	if scanner == nil {
		return nil, ErrRepositoryUnavailable
	}

	analysis := &EvidenceAnalysis{}
	var extractedMetadataJSON []byte
	var resultDataJSON []byte

	err := scanner.Scan(
		&analysis.ID,
		&analysis.OrganizationID,
		&analysis.AnalysisJobID,
		&analysis.MediaAssetID,
		&analysis.EvidenceID,
		&analysis.EvidenceFileID,
		&analysis.AnalysisType,
		&analysis.AnalysisMethod,
		&analysis.AnalysisTool,
		&analysis.ToolVersion,
		&analysis.AIModelName,
		&analysis.AIModelVersion,
		&analysis.AnalyzedBy,
		&analysis.AnalysisStatus,
		&analysis.Result,
		&analysis.ConfidenceScore,
		&analysis.Summary,
		&analysis.Findings,
		&analysis.Recommendation,
		&extractedMetadataJSON,
		&resultDataJSON,
		&analysis.StartedAt,
		&analysis.CompletedAt,
		&analysis.ReviewedBy,
		&analysis.ReviewedAt,
		&analysis.ReviewNotes,
		&analysis.CreatedAt,
		&analysis.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	analysis.ExtractedMetadata =
		map[string]any{}
	if err = decodeStoredAnalysisJSON(
		extractedMetadataJSON,
		&analysis.ExtractedMetadata,
	); err != nil {
		return nil, err
	}

	analysis.ResultData = map[string]any{}
	if err = decodeStoredAnalysisJSON(
		resultDataJSON,
		&analysis.ResultData,
	); err != nil {
		return nil, err
	}

	return analysis, nil
}

func decodeStoredAnalysisJSON(
	data []byte,
	destination any,
) error {
	if destination == nil {
		return ErrInvalidRepositoryInput
	}
	if len(data) == 0 {
		return nil
	}

	if err := json.Unmarshal(
		data,
		destination,
	); err != nil {
		return fmt.Errorf(
			"decode stored media analysis JSON: %w",
			err,
		)
	}

	return nil
}

func splitStoredFindings(
	value *string,
) []string {
	if value == nil ||
		strings.TrimSpace(*value) == "" {
		return []string{}
	}

	lines := strings.Split(
		*value,
		"\n",
	)
	findings := make(
		[]string,
		0,
		len(lines),
	)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			findings = append(
				findings,
				line,
			)
		}
	}

	return findings
}
