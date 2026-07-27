package deepfakeforensics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PersistAnalysisResult atomically stores one specialized
// result, its shared evidence-analysis record, the complete
// engine response and the media asset analysis timestamp.
func (r *Repository) PersistAnalysisResult(
	ctx context.Context,
	source AnalysisSource,
	engineResponse *MediaEngineResponse,
	bundle *AnalysisResultBundle,
) error {
	if err := r.validateAvailable(); err != nil {
		return err
	}

	if err := validateAnalysisResultPersistence(
		ctx,
		source,
		engineResponse,
		bundle,
	); err != nil {
		return err
	}

	responseDataJSON, err := json.Marshal(
		engineResponse,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: encode media engine response: %v",
			ErrInvalidRepositoryInput,
			err,
		)
	}

	tx, err := r.databasePool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return fmt.Errorf(
			"begin media result transaction: %w",
			err,
		)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if err = lockProcessingAnalysisJob(
		ctx,
		tx,
		source,
	); err != nil {
		return err
	}

	switch {
	case bundle.Deepfake != nil:
		err = insertDeepfakeDetectionResult(
			ctx,
			tx,
			bundle.Deepfake,
		)

	case bundle.Forensics != nil:
		err = insertMediaForensicsResult(
			ctx,
			tx,
			bundle.Forensics,
		)

	case bundle.OCR != nil:
		err = insertOCRResult(
			ctx,
			tx,
			bundle.OCR,
		)

	default:
		err = ErrInvalidRepositoryInput
	}
	if err != nil {
		return err
	}

	if err = insertEvidenceAnalysis(
		ctx,
		tx,
		&bundle.EvidenceAnalysis,
	); err != nil {
		return err
	}

	completedAt := resultCompletionTime(
		engineResponse,
		bundle,
	)

	if err = completePersistedAnalysisJob(
		ctx,
		tx,
		source,
		responseDataJSON,
		engineResponse.ProcessingDurationMS,
		completedAt,
	); err != nil {
		return err
	}

	if err = markMediaAssetAnalyzed(
		ctx,
		tx,
		source,
		completedAt,
	); err != nil {
		return err
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit media analysis result: %w",
			err,
		)
	}

	return nil
}

func validateAnalysisResultPersistence(
	ctx context.Context,
	source AnalysisSource,
	engineResponse *MediaEngineResponse,
	bundle *AnalysisResultBundle,
) error {
	if ctx == nil ||
		engineResponse == nil ||
		!engineResponse.Success ||
		bundle == nil ||
		source.Job.ID == uuid.Nil ||
		source.Job.OrganizationID == uuid.Nil ||
		source.Asset.ID == uuid.Nil ||
		source.Asset.OrganizationID ==
			uuid.Nil ||
		source.Job.MediaAssetID == nil ||
		*source.Job.MediaAssetID ==
			uuid.Nil ||
		engineResponse.AnalysisJobID !=
			source.Job.ID ||
		engineResponse.OrganizationID !=
			source.Job.OrganizationID ||
		source.Asset.ID !=
			*source.Job.MediaAssetID ||
		source.Asset.OrganizationID !=
			source.Job.OrganizationID {
		return ErrInvalidRepositoryInput
	}

	specializedResultCount := 0
	if bundle.Deepfake != nil {
		specializedResultCount++
	}
	if bundle.Forensics != nil {
		specializedResultCount++
	}
	if bundle.OCR != nil {
		specializedResultCount++
	}
	if specializedResultCount != 1 {
		return fmt.Errorf(
			"%w: exactly one specialized result is required",
			ErrInvalidRepositoryInput,
		)
	}

	switch {
	case IsDeepfakeJobType(source.Job.JobType):
		if bundle.Deepfake == nil ||
			!validSpecializedResultIdentity(
				source,
				bundle.Deepfake.AnalysisJobID,
				bundle.Deepfake.OrganizationID,
				bundle.Deepfake.MediaAssetID,
			) {
			return ErrInvalidRepositoryInput
		}

	case IsForensicsJobType(source.Job.JobType):
		if bundle.Forensics == nil ||
			!validSpecializedResultIdentity(
				source,
				bundle.Forensics.AnalysisJobID,
				bundle.Forensics.OrganizationID,
				bundle.Forensics.MediaAssetID,
			) {
			return ErrInvalidRepositoryInput
		}

	case NormalizeConstant(source.Job.JobType) ==
		JobTypeOCRExtraction:
		if bundle.OCR == nil ||
			!validSpecializedResultIdentity(
				source,
				bundle.OCR.AnalysisJobID,
				bundle.OCR.OrganizationID,
				bundle.OCR.MediaAssetID,
			) {
			return ErrInvalidRepositoryInput
		}

	default:
		return ErrInvalidRepositoryInput
	}

	evidenceAnalysis := bundle.EvidenceAnalysis
	if evidenceAnalysis.ID == uuid.Nil ||
		evidenceAnalysis.OrganizationID !=
			source.Job.OrganizationID ||
		evidenceAnalysis.AnalysisJobID == nil ||
		*evidenceAnalysis.AnalysisJobID !=
			source.Job.ID ||
		evidenceAnalysis.MediaAssetID == nil ||
		*evidenceAnalysis.MediaAssetID !=
			source.Asset.ID ||
		strings.TrimSpace(
			evidenceAnalysis.AnalysisType,
		) == "" ||
		strings.TrimSpace(
			evidenceAnalysis.AnalysisMethod,
		) == "" ||
		strings.TrimSpace(
			evidenceAnalysis.AnalysisStatus,
		) == "" {
		return ErrInvalidRepositoryInput
	}

	return nil
}

func validSpecializedResultIdentity(
	source AnalysisSource,
	analysisJobID uuid.UUID,
	organizationID uuid.UUID,
	mediaAssetID *uuid.UUID,
) bool {
	return analysisJobID == source.Job.ID &&
		organizationID ==
			source.Job.OrganizationID &&
		mediaAssetID != nil &&
		*mediaAssetID == source.Asset.ID
}

func lockProcessingAnalysisJob(
	ctx context.Context,
	tx pgx.Tx,
	source AnalysisSource,
) error {
	var lockedJobID uuid.UUID

	err := tx.QueryRow(
		ctx,
		`
			SELECT id
			FROM ai_analysis_jobs
			WHERE id = $1
				AND organization_id = $2
				AND media_asset_id = $3
				AND status = $4
			FOR UPDATE
		`,
		source.Job.ID,
		source.Job.OrganizationID,
		source.Asset.ID,
		JobStatusProcessing,
	).Scan(&lockedJobID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAnalysisJobConflict
	}
	if err != nil {
		return fmt.Errorf(
			"lock processing AI analysis job: %w",
			err,
		)
	}

	return nil
}

func insertDeepfakeDetectionResult(
	ctx context.Context,
	tx pgx.Tx,
	result *DeepfakeDetectionResult,
) error {
	featureDataJSON, err := marshalAnalysisJSON(
		result.FeatureData,
		map[string]any{},
		"deepfake feature data",
	)
	if err != nil {
		return err
	}

	suspiciousRegionsJSON, err :=
		marshalAnalysisJSON(
			result.SuspiciousRegions,
			[]map[string]any{},
			"deepfake suspicious regions",
		)
	if err != nil {
		return err
	}

	commandTag, err := tx.Exec(
		ctx,
		`
			INSERT INTO deepfake_detection_results (
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
				feature_data,
				suspicious_regions,
				visualization_file_path,
				created_at
			)
			VALUES (
				$1, $2, $3, $4, $5,
				$6, $7, $8, $9, $10,
				$11, $12, $13, $14, $15,
				$16, $17, $18, $19, $20,
				$21, $22, $23, $24, $25
			)
		`,
		result.ID,
		result.AnalysisJobID,
		result.OrganizationID,
		result.MediaAssetID,
		result.EvidenceID,
		result.EvidenceFileID,
		NormalizeConstant(result.MediaType),
		NormalizeConstant(result.DetectionResult),
		result.DeepfakeProbability,
		result.AuthenticityProbability,
		result.ConfidenceScore,
		result.FacesDetected,
		result.ManipulatedFacesDetected,
		result.TotalFramesAnalyzed,
		result.SuspiciousFrames,
		result.AudioDurationSeconds,
		result.LipSyncAnomalyDetected,
		result.FacialArtifactDetected,
		result.AudioManipulationDetected,
		result.MetadataInconsistencyDetected,
		result.DetectionSummary,
		featureDataJSON,
		suspiciousRegionsJSON,
		result.VisualizationFilePath,
		result.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf(
			"create deepfake detection result: %w",
			err,
		)
	}
	if commandTag.RowsAffected() != 1 {
		return ErrAnalysisJobConflict
	}

	return nil
}

func insertMediaForensicsResult(
	ctx context.Context,
	tx pgx.Tx,
	result *MediaForensicsResult,
) error {
	suspiciousLocationsJSON, err :=
		marshalAnalysisJSON(
			result.SuspiciousLocations,
			[]map[string]any{},
			"forensic suspicious locations",
		)
	if err != nil {
		return err
	}

	featureDataJSON, err := marshalAnalysisJSON(
		result.ForensicFeatureData,
		map[string]any{},
		"forensic feature data",
	)
	if err != nil {
		return err
	}

	findings := optionalJoinedFindings(
		result.Findings,
	)

	commandTag, err := tx.Exec(
		ctx,
		`
			INSERT INTO media_forensics_results (
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
				suspicious_locations,
				forensic_feature_data,
				visualization_file_path,
				created_at
			)
			VALUES (
				$1, $2, $3, $4, $5,
				$6, $7, $8, $9, $10,
				$11, $12, $13, $14, $15,
				$16, $17, $18, $19, $20,
				$21, $22, $23, $24
			)
		`,
		result.ID,
		result.AnalysisJobID,
		result.OrganizationID,
		result.MediaAssetID,
		result.EvidenceID,
		result.EvidenceFileID,
		NormalizeConstant(result.MediaType),
		NormalizeConstant(result.ForensicResult),
		result.ConfidenceScore,
		result.EditingTraceDetected,
		result.CompressionAnomalyDetected,
		result.CopyMoveDetected,
		result.SplicingDetected,
		result.FrameDuplicationDetected,
		result.FrameDeletionDetected,
		result.AudioDiscontinuityDetected,
		result.NoiseInconsistencyDetected,
		result.TimestampAnomalyDetected,
		result.AnalysisSummary,
		findings,
		suspiciousLocationsJSON,
		featureDataJSON,
		result.VisualizationFilePath,
		result.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf(
			"create media forensics result: %w",
			err,
		)
	}
	if commandTag.RowsAffected() != 1 {
		return ErrAnalysisJobConflict
	}

	return nil
}

func insertOCRResult(
	ctx context.Context,
	tx pgx.Tx,
	result *OCRResult,
) error {
	pageResultsJSON, err := marshalAnalysisJSON(
		result.PageResults,
		[]map[string]any{},
		"OCR page results",
	)
	if err != nil {
		return err
	}

	boundingBoxDataJSON, err :=
		marshalAnalysisJSON(
			result.BoundingBoxData,
			[]map[string]any{},
			"OCR bounding box data",
		)
	if err != nil {
		return err
	}

	commandTag, err := tx.Exec(
		ctx,
		`
			INSERT INTO ocr_results (
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
				page_results,
				bounding_box_data,
				requires_manual_correction,
				corrected_text,
				corrected_by,
				corrected_at,
				created_at,
				updated_at
			)
			VALUES (
				$1, $2, $3, $4, $5,
				$6, $7, $8, $9, $10,
				$11, $12, $13, $14, $15,
				$16, $17, $18, $19, $20,
				$21, $22, $23, $24
			)
		`,
		result.ID,
		result.AnalysisJobID,
		result.OrganizationID,
		result.MediaAssetID,
		result.EvidenceID,
		result.EvidenceFileID,
		NormalizeConstant(result.SourceMediaType),
		NormalizeConstant(result.ExtractionResult),
		result.OCREngine,
		result.DetectedLanguage,
		result.TotalPages,
		result.TotalFrames,
		result.ExtractedText,
		result.ConfidenceScore,
		result.WordCount,
		result.CharacterCount,
		pageResultsJSON,
		boundingBoxDataJSON,
		result.RequiresManualCorrection,
		result.CorrectedText,
		result.CorrectedBy,
		result.CorrectedAt,
		result.CreatedAt.UTC(),
		result.UpdatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf(
			"create OCR result: %w",
			err,
		)
	}
	if commandTag.RowsAffected() != 1 {
		return ErrAnalysisJobConflict
	}

	return nil
}

func insertEvidenceAnalysis(
	ctx context.Context,
	tx pgx.Tx,
	analysis *EvidenceAnalysis,
) error {
	extractedMetadataJSON, err :=
		marshalAnalysisJSON(
			analysis.ExtractedMetadata,
			map[string]any{},
			"evidence analysis metadata",
		)
	if err != nil {
		return err
	}

	resultDataJSON, err := marshalAnalysisJSON(
		analysis.ResultData,
		map[string]any{},
		"evidence analysis result data",
	)
	if err != nil {
		return err
	}

	commandTag, err := tx.Exec(
		ctx,
		`
			INSERT INTO evidence_analysis (
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
				extracted_metadata,
				result_data,
				started_at,
				completed_at,
				reviewed_by,
				reviewed_at,
				review_notes,
				created_at,
				updated_at
			)
			VALUES (
				$1, $2, $3, $4, $5,
				$6, $7, $8, $9, $10,
				$11, $12, $13, $14, $15,
				$16, $17, $18, $19, $20,
				$21, $22, $23, $24, $25,
				$26, $27, $28
			)
		`,
		analysis.ID,
		analysis.OrganizationID,
		analysis.AnalysisJobID,
		analysis.MediaAssetID,
		analysis.EvidenceID,
		analysis.EvidenceFileID,
		NormalizeConstant(analysis.AnalysisType),
		NormalizeConstant(analysis.AnalysisMethod),
		analysis.AnalysisTool,
		analysis.ToolVersion,
		analysis.AIModelName,
		analysis.AIModelVersion,
		analysis.AnalyzedBy,
		NormalizeConstant(analysis.AnalysisStatus),
		analysis.Result,
		analysis.ConfidenceScore,
		analysis.Summary,
		analysis.Findings,
		analysis.Recommendation,
		extractedMetadataJSON,
		resultDataJSON,
		analysis.StartedAt,
		analysis.CompletedAt,
		analysis.ReviewedBy,
		analysis.ReviewedAt,
		analysis.ReviewNotes,
		analysis.CreatedAt.UTC(),
		analysis.UpdatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf(
			"create evidence analysis result: %w",
			err,
		)
	}
	if commandTag.RowsAffected() != 1 {
		return ErrAnalysisJobConflict
	}

	return nil
}

func completePersistedAnalysisJob(
	ctx context.Context,
	tx pgx.Tx,
	source AnalysisSource,
	responseDataJSON []byte,
	processingDurationMS int64,
	completedAt time.Time,
) error {
	commandTag, err := tx.Exec(
		ctx,
		`
			UPDATE ai_analysis_jobs
			SET
				status = $4,
				response_data = $5,
				progress_percentage = 100,
				error_code = NULL,
				error_message = NULL,
				processing_duration_ms = $6,
				completed_at = $7,
				updated_at = $7
			WHERE id = $1
				AND organization_id = $2
				AND media_asset_id = $3
				AND status = $8
		`,
		source.Job.ID,
		source.Job.OrganizationID,
		source.Asset.ID,
		JobStatusCompleted,
		responseDataJSON,
		processingDurationMS,
		completedAt,
		JobStatusProcessing,
	)
	if err != nil {
		return fmt.Errorf(
			"complete AI analysis job: %w",
			err,
		)
	}
	if commandTag.RowsAffected() != 1 {
		return ErrAnalysisJobConflict
	}

	return nil
}

func markMediaAssetAnalyzed(
	ctx context.Context,
	tx pgx.Tx,
	source AnalysisSource,
	completedAt time.Time,
) error {
	commandTag, err := tx.Exec(
		ctx,
		`
			UPDATE media_analysis_assets
			SET
				analyzed_at = CASE
					WHEN analyzed_at IS NULL
						OR analyzed_at < $3
						THEN $3
					ELSE analyzed_at
				END,
				updated_at = $3
			WHERE id = $1
				AND organization_id = $2
				AND deleted_at IS NULL
		`,
		source.Asset.ID,
		source.Job.OrganizationID,
		completedAt,
	)
	if err != nil {
		return fmt.Errorf(
			"mark media asset analyzed: %w",
			err,
		)
	}
	if commandTag.RowsAffected() != 1 {
		return ErrMediaAssetNotFound
	}

	return nil
}

func marshalAnalysisJSON(
	value any,
	emptyValue any,
	fieldName string,
) ([]byte, error) {
	if value == nil {
		value = emptyValue
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: encode %s: %v",
			ErrInvalidRepositoryInput,
			fieldName,
			err,
		)
	}

	return encoded, nil
}

func optionalJoinedFindings(
	findings []string,
) *string {
	normalizedFindings := make(
		[]string,
		0,
		len(findings),
	)

	for _, finding := range findings {
		finding = strings.TrimSpace(finding)
		if finding != "" {
			normalizedFindings = append(
				normalizedFindings,
				finding,
			)
		}
	}

	if len(normalizedFindings) == 0 {
		return nil
	}

	value := strings.Join(
		normalizedFindings,
		"\n",
	)

	return &value
}

func resultCompletionTime(
	engineResponse *MediaEngineResponse,
	bundle *AnalysisResultBundle,
) time.Time {
	if bundle != nil &&
		bundle.EvidenceAnalysis.CompletedAt != nil &&
		!bundle.EvidenceAnalysis.CompletedAt.IsZero() {
		return bundle.EvidenceAnalysis.CompletedAt.UTC()
	}

	if engineResponse != nil &&
		!engineResponse.ProcessedAt.IsZero() {
		return engineResponse.ProcessedAt.UTC()
	}

	return time.Now().UTC()
}
