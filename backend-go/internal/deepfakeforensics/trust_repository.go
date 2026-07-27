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

const mediaTrustAssessmentSelectColumns = `
	id,
	organization_id,
	media_asset_id,
	trust_score,
	risk_score,
	confidence_score,
	verdict,
	classification,
	risk_level,
	trained_model_used,
	requires_human_review,
	finalized,
	COALESCE(component_scores, '{}'::jsonb),
	COALESCE(signals, '[]'::jsonb),
	COALESCE(warnings, '[]'::jsonb),
	completed_job_count,
	terminal_job_count,
	latest_analysis_job_id,
	escalation_status,
	escalation_attempt_count,
	escalation_error,
	incident_id,
	incident_evidence_id,
	notification_sent_at,
	escalated_at,
	evaluated_at,
	created_at,
	updated_at
`

func (r *Repository) RecalculateMediaTrustAssessment(
	ctx context.Context,
	organizationID uuid.UUID,
	mediaAssetID uuid.UUID,
) (*MediaTrustAssessment, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}
	if ctx == nil ||
		organizationID == uuid.Nil ||
		mediaAssetID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	snapshot, err := r.loadTrustAnalysisSnapshot(
		ctx,
		organizationID,
		mediaAssetID,
	)
	if err != nil {
		return nil, err
	}

	assessment, err := calculateMediaTrustAssessment(
		*snapshot,
		time.Now().UTC(),
	)
	if err != nil {
		return nil, err
	}

	return r.upsertMediaTrustAssessment(
		ctx,
		assessment,
	)
}

func (r *Repository) GetMediaTrustAssessment(
	ctx context.Context,
	organizationID uuid.UUID,
	mediaAssetID uuid.UUID,
) (*MediaTrustAssessment, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}
	if ctx == nil ||
		organizationID == uuid.Nil ||
		mediaAssetID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	assessment, err := scanMediaTrustAssessment(
		r.databasePool.QueryRow(
			ctx,
			`
				SELECT
					`+mediaTrustAssessmentSelectColumns+`
				FROM media_trust_assessments
				WHERE organization_id = $1
					AND media_asset_id = $2
			`,
			organizationID,
			mediaAssetID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrMediaTrustAssessmentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"get media trust assessment: %w",
			err,
		)
	}

	return assessment, nil
}

func (r *Repository) ClaimMediaTrustEscalation(
	ctx context.Context,
	assessmentID uuid.UUID,
) (*MediaTrustAssessment, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}
	if ctx == nil || assessmentID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	assessment, err := scanMediaTrustAssessment(
		r.databasePool.QueryRow(
			ctx,
			`
				UPDATE media_trust_assessments
				SET
					escalation_status = $2,
					escalation_attempt_count =
						escalation_attempt_count + 1,
					escalation_error = NULL,
					updated_at = CURRENT_TIMESTAMP
				WHERE id = $1
					AND incident_id IS NULL
					AND risk_level IN ($3, $4)
					AND escalation_status IN ($5, $6)
				RETURNING
					`+mediaTrustAssessmentSelectColumns+`
			`,
			assessmentID,
			TrustEscalationInProgress,
			TrustRiskHigh,
			TrustRiskCritical,
			TrustEscalationPending,
			TrustEscalationFailed,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisJobConflict
	}
	if err != nil {
		return nil, fmt.Errorf(
			"claim media trust escalation: %w",
			err,
		)
	}

	return assessment, nil
}

func (r *Repository) CompleteMediaTrustEscalation(
	ctx context.Context,
	assessmentID uuid.UUID,
	result MediaTrustEscalationResult,
) error {
	if err := r.validateAvailable(); err != nil {
		return err
	}
	if ctx == nil ||
		assessmentID == uuid.Nil ||
		result.IncidentID == uuid.Nil ||
		result.IncidentEvidenceID == uuid.Nil {
		return ErrInvalidRepositoryInput
	}

	var notificationSentAt *time.Time
	if result.NotificationSentAt != nil {
		normalized := result.NotificationSentAt.UTC()
		if !normalized.IsZero() {
			notificationSentAt = &normalized
		}
	}

	commandTag, err := r.databasePool.Exec(
		ctx,
		`
			UPDATE media_trust_assessments
			SET
				escalation_status = $2,
				escalation_error = NULL,
				incident_id = $3,
				incident_evidence_id = $4,
				notification_sent_at = $5,
				escalated_at = CURRENT_TIMESTAMP,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = $1
				AND escalation_status = $6
		`,
		assessmentID,
		TrustEscalationCompleted,
		result.IncidentID,
		result.IncidentEvidenceID,
		notificationSentAt,
		TrustEscalationInProgress,
	)
	if err != nil {
		return fmt.Errorf(
			"complete media trust escalation: %w",
			err,
		)
	}
	if commandTag.RowsAffected() != 1 {
		return ErrAnalysisJobConflict
	}

	return nil
}

func (r *Repository) FailMediaTrustEscalation(
	ctx context.Context,
	assessmentID uuid.UUID,
	cause error,
) error {
	if err := r.validateAvailable(); err != nil {
		return err
	}
	if ctx == nil || assessmentID == uuid.Nil {
		return ErrInvalidRepositoryInput
	}

	errorMessage := "media trust escalation failed"
	if cause != nil &&
		strings.TrimSpace(cause.Error()) != "" {
		errorMessage = strings.TrimSpace(cause.Error())
	}
	if len(errorMessage) > 4000 {
		errorMessage = errorMessage[:4000]
	}

	_, err := r.databasePool.Exec(
		ctx,
		`
			UPDATE media_trust_assessments
			SET
				escalation_status = $2,
				escalation_error = $3,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = $1
				AND escalation_status = $4
		`,
		assessmentID,
		TrustEscalationFailed,
		errorMessage,
		TrustEscalationInProgress,
	)
	if err != nil {
		return fmt.Errorf(
			"fail media trust escalation: %w",
			err,
		)
	}

	return nil
}

func (r *Repository) loadTrustAnalysisSnapshot(
	ctx context.Context,
	organizationID uuid.UUID,
	mediaAssetID uuid.UUID,
) (*trustAnalysisSnapshot, error) {
	asset, err := r.GetMediaAsset(
		ctx,
		organizationID,
		mediaAssetID,
	)
	if err != nil {
		return nil, err
	}

	snapshot := &trustAnalysisSnapshot{
		Asset: *asset,
	}

	if err = r.loadLatestDeepfakeTrustComponent(
		ctx,
		organizationID,
		mediaAssetID,
		snapshot,
	); err != nil {
		return nil, err
	}
	if err = r.loadLatestForensicTrustComponent(
		ctx,
		organizationID,
		mediaAssetID,
		snapshot,
	); err != nil {
		return nil, err
	}
	if err = r.loadLatestOCRTrustComponent(
		ctx,
		organizationID,
		mediaAssetID,
		snapshot,
	); err != nil {
		return nil, err
	}
	if err = r.loadLatestTrustJobState(
		ctx,
		organizationID,
		mediaAssetID,
		snapshot,
	); err != nil {
		return nil, err
	}

	return snapshot, nil
}

func (r *Repository) loadLatestDeepfakeTrustComponent(
	ctx context.Context,
	organizationID uuid.UUID,
	mediaAssetID uuid.UUID,
	snapshot *trustAnalysisSnapshot,
) error {
	var warningsJSON []byte

	err := r.databasePool.QueryRow(
		ctx,
		`
			SELECT
				detection_result,
				deepfake_probability,
				authenticity_probability,
				confidence_score,
				NULLIF(feature_data->>'runtime', ''),
				COALESCE(
					(feature_data->>'runtime') IN (
						'PYTORCH',
						'ONNX_RUNTIME'
					),
					false
				),
				COALESCE(feature_data->'warnings', '[]'::jsonb)
			FROM deepfake_detection_results
			WHERE organization_id = $1
				AND media_asset_id = $2
			ORDER BY created_at DESC, id DESC
			LIMIT 1
		`,
		organizationID,
		mediaAssetID,
	).Scan(
		&snapshot.DeepfakeResult,
		&snapshot.DeepfakeProbability,
		&snapshot.AuthenticityProbability,
		&snapshot.DeepfakeConfidence,
		&snapshot.DeepfakeRuntime,
		&snapshot.DeepfakeTrained,
		&warningsJSON,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf(
			"load deepfake trust component: %w",
			err,
		)
	}

	return decodeTrustWarnings(
		warningsJSON,
		&snapshot.DeepfakeWarnings,
	)
}

func (r *Repository) loadLatestForensicTrustComponent(
	ctx context.Context,
	organizationID uuid.UUID,
	mediaAssetID uuid.UUID,
	snapshot *trustAnalysisSnapshot,
) error {
	var warningsJSON []byte

	err := r.databasePool.QueryRow(
		ctx,
		`
			SELECT
				forensic_result,
				confidence_score,
				NULLIF(forensic_feature_data->>'runtime', ''),
				COALESCE(
					forensic_feature_data->'warnings',
					'[]'::jsonb
				)
			FROM media_forensics_results
			WHERE organization_id = $1
				AND media_asset_id = $2
			ORDER BY created_at DESC, id DESC
			LIMIT 1
		`,
		organizationID,
		mediaAssetID,
	).Scan(
		&snapshot.ForensicResult,
		&snapshot.ForensicConfidence,
		&snapshot.ForensicRuntime,
		&warningsJSON,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf(
			"load forensic trust component: %w",
			err,
		)
	}

	return decodeTrustWarnings(
		warningsJSON,
		&snapshot.ForensicWarnings,
	)
}

func (r *Repository) loadLatestOCRTrustComponent(
	ctx context.Context,
	organizationID uuid.UUID,
	mediaAssetID uuid.UUID,
	snapshot *trustAnalysisSnapshot,
) error {
	err := r.databasePool.QueryRow(
		ctx,
		`
			SELECT
				extraction_result,
				confidence_score,
				requires_manual_correction
			FROM ocr_results
			WHERE organization_id = $1
				AND media_asset_id = $2
			ORDER BY created_at DESC, id DESC
			LIMIT 1
		`,
		organizationID,
		mediaAssetID,
	).Scan(
		&snapshot.OCRResult,
		&snapshot.OCRConfidence,
		&snapshot.OCRRequiresManualReview,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf(
			"load OCR trust component: %w",
			err,
		)
	}

	return nil
}

func (r *Repository) loadLatestTrustJobState(
	ctx context.Context,
	organizationID uuid.UUID,
	mediaAssetID uuid.UUID,
	snapshot *trustAnalysisSnapshot,
) error {
	var completedCount int64
	var totalCount int64

	err := r.databasePool.QueryRow(
		ctx,
		`
			WITH latest_jobs AS (
				SELECT DISTINCT ON (job_type)
					id,
					status,
					created_at
				FROM ai_analysis_jobs
				WHERE organization_id = $1
					AND media_asset_id = $2
					AND job_type IN (
						$3, $4, $5, $6, $7, $8, $9
					)
				ORDER BY
					job_type,
					created_at DESC,
					id DESC
			)
			SELECT
				COUNT(*) FILTER (
					WHERE status = $10
				),
				COUNT(*),
				COALESCE(
					BOOL_AND(
						status IN ($10, $11, $12)
					),
					false
				),
				(
					SELECT id
					FROM latest_jobs
					ORDER BY created_at DESC, id DESC
					LIMIT 1
				)
			FROM latest_jobs
		`,
		organizationID,
		mediaAssetID,
		JobTypeDeepfakeImage,
		JobTypeDeepfakeVideo,
		JobTypeDeepfakeAudio,
		JobTypeImageForensics,
		JobTypeVideoForensics,
		JobTypeAudioForensics,
		JobTypeOCRExtraction,
		JobStatusCompleted,
		JobStatusFailed,
		JobStatusCancelled,
	).Scan(
		&completedCount,
		&totalCount,
		&snapshot.AllJobsTerminal,
		&snapshot.LatestJobID,
	)
	if err != nil {
		return fmt.Errorf(
			"load media trust job state: %w",
			err,
		)
	}

	snapshot.CompletedJobCount = int(completedCount)
	snapshot.TerminalJobCount = int(totalCount)
	return nil
}

func (r *Repository) upsertMediaTrustAssessment(
	ctx context.Context,
	assessment *MediaTrustAssessment,
) (*MediaTrustAssessment, error) {
	if assessment == nil {
		return nil, ErrInvalidRepositoryInput
	}

	componentScoresJSON, err := json.Marshal(
		assessment.ComponentScores,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode media trust component scores: %w",
			err,
		)
	}
	signalsJSON, err := json.Marshal(assessment.Signals)
	if err != nil {
		return nil, fmt.Errorf(
			"encode media trust signals: %w",
			err,
		)
	}
	warningsJSON, err := json.Marshal(assessment.Warnings)
	if err != nil {
		return nil, fmt.Errorf(
			"encode media trust warnings: %w",
			err,
		)
	}

	stored, err := scanMediaTrustAssessment(
		r.databasePool.QueryRow(
			ctx,
			`
				INSERT INTO media_trust_assessments (
					id,
					organization_id,
					media_asset_id,
					trust_score,
					risk_score,
					confidence_score,
					verdict,
					classification,
					risk_level,
					trained_model_used,
					requires_human_review,
					finalized,
					component_scores,
					signals,
					warnings,
					completed_job_count,
					terminal_job_count,
					latest_analysis_job_id,
					escalation_status,
					evaluated_at,
					created_at,
					updated_at
				)
				VALUES (
					$1, $2, $3, $4, $5, $6,
					$7, $8, $9, $10, $11, $12,
					$13, $14, $15, $16, $17, $18,
					$19, $20, $21, $22
				)
				ON CONFLICT (
					organization_id,
					media_asset_id
				)
				DO UPDATE SET
					trust_score = EXCLUDED.trust_score,
					risk_score = EXCLUDED.risk_score,
					confidence_score = EXCLUDED.confidence_score,
					verdict = EXCLUDED.verdict,
					classification = EXCLUDED.classification,
					risk_level = EXCLUDED.risk_level,
					trained_model_used = EXCLUDED.trained_model_used,
					requires_human_review =
						EXCLUDED.requires_human_review,
					finalized = EXCLUDED.finalized,
					component_scores = EXCLUDED.component_scores,
					signals = EXCLUDED.signals,
					warnings = EXCLUDED.warnings,
					completed_job_count =
						EXCLUDED.completed_job_count,
					terminal_job_count =
						EXCLUDED.terminal_job_count,
					latest_analysis_job_id =
						EXCLUDED.latest_analysis_job_id,
					escalation_status = CASE
						WHEN media_trust_assessments.incident_id
							IS NOT NULL
							THEN $23
						WHEN EXCLUDED.risk_level IN ($24, $25)
							AND media_trust_assessments.escalation_status
								<> $26
							THEN $27
						WHEN EXCLUDED.risk_level NOT IN ($24, $25)
							AND media_trust_assessments.escalation_status
								NOT IN ($23, $26)
							THEN $28
						ELSE media_trust_assessments.escalation_status
					END,
					evaluated_at = EXCLUDED.evaluated_at,
					updated_at = EXCLUDED.updated_at
				RETURNING
					`+mediaTrustAssessmentSelectColumns+`
			`,
			assessment.ID,
			assessment.OrganizationID,
			assessment.MediaAssetID,
			assessment.TrustScore,
			assessment.RiskScore,
			assessment.ConfidenceScore,
			assessment.Verdict,
			assessment.Classification,
			assessment.RiskLevel,
			assessment.TrainedModelUsed,
			assessment.RequiresHumanReview,
			assessment.Finalized,
			componentScoresJSON,
			signalsJSON,
			warningsJSON,
			assessment.CompletedJobCount,
			assessment.TerminalJobCount,
			assessment.LatestAnalysisJobID,
			assessment.EscalationStatus,
			assessment.EvaluatedAt,
			assessment.CreatedAt,
			assessment.UpdatedAt,
			TrustEscalationCompleted,
			TrustRiskHigh,
			TrustRiskCritical,
			TrustEscalationInProgress,
			TrustEscalationPending,
			TrustEscalationNone,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"upsert media trust assessment: %w",
			err,
		)
	}

	return stored, nil
}

func scanMediaTrustAssessment(
	scanner databaseRowScanner,
) (*MediaTrustAssessment, error) {
	if scanner == nil {
		return nil, ErrRepositoryUnavailable
	}

	assessment := &MediaTrustAssessment{}
	var componentScoresJSON []byte
	var signalsJSON []byte
	var warningsJSON []byte

	err := scanner.Scan(
		&assessment.ID,
		&assessment.OrganizationID,
		&assessment.MediaAssetID,
		&assessment.TrustScore,
		&assessment.RiskScore,
		&assessment.ConfidenceScore,
		&assessment.Verdict,
		&assessment.Classification,
		&assessment.RiskLevel,
		&assessment.TrainedModelUsed,
		&assessment.RequiresHumanReview,
		&assessment.Finalized,
		&componentScoresJSON,
		&signalsJSON,
		&warningsJSON,
		&assessment.CompletedJobCount,
		&assessment.TerminalJobCount,
		&assessment.LatestAnalysisJobID,
		&assessment.EscalationStatus,
		&assessment.EscalationAttemptCount,
		&assessment.EscalationError,
		&assessment.IncidentID,
		&assessment.IncidentEvidenceID,
		&assessment.NotificationSentAt,
		&assessment.EscalatedAt,
		&assessment.EvaluatedAt,
		&assessment.CreatedAt,
		&assessment.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	assessment.ComponentScores = map[string]any{}
	if err = json.Unmarshal(
		componentScoresJSON,
		&assessment.ComponentScores,
	); err != nil {
		return nil, fmt.Errorf(
			"decode media trust component scores: %w",
			err,
		)
	}

	assessment.Signals = []map[string]any{}
	if err = json.Unmarshal(
		signalsJSON,
		&assessment.Signals,
	); err != nil {
		return nil, fmt.Errorf(
			"decode media trust signals: %w",
			err,
		)
	}

	assessment.Warnings = []string{}
	if err = json.Unmarshal(
		warningsJSON,
		&assessment.Warnings,
	); err != nil {
		return nil, fmt.Errorf(
			"decode media trust warnings: %w",
			err,
		)
	}

	return assessment, nil
}

func decodeTrustWarnings(
	encoded []byte,
	target *[]string,
) error {
	if target == nil {
		return ErrInvalidRepositoryInput
	}

	*target = []string{}
	if len(encoded) == 0 {
		return nil
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		return fmt.Errorf(
			"decode media trust warnings: %w",
			err,
		)
	}

	return nil
}
