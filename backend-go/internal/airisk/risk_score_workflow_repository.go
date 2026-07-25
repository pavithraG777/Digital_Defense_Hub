package airisk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SaveCalculatedRiskScore atomically checks the current score,
// archives it when required and saves the newly calculated score.
//
// When replaceExisting is false and another valid active score
// already exists, that existing score is returned with created=false.
func (r *Repository) SaveCalculatedRiskScore(
	ctx context.Context,
	riskScore *RiskScore,
	replaceExisting bool,
) (*RiskScore, bool, error) {
	if r == nil || r.db == nil {
		return nil, false, errors.New(
			"AI risk repository is unavailable",
		)
	}

	if riskScore == nil {
		return nil, false, errors.New(
			"AI risk score is required",
		)
	}

	if riskScore.OrganizationID == uuid.Nil {
		return nil, false, errors.New(
			"organization ID is required",
		)
	}

	if riskScore.RiskSubjectID == uuid.Nil {
		return nil, false, errors.New(
			"risk subject ID is required",
		)
	}

	if !IsSupportedRiskSubjectType(
		riskScore.RiskSubjectType,
	) {
		return nil, false, errors.New(
			"risk subject type is invalid",
		)
	}

	if riskScore.ID == uuid.Nil {
		riskScore.ID = uuid.New()
	}

	if riskScore.Status == "" {
		riskScore.Status = RiskStatusActive
	}

	if riskScore.CalculatedAt.IsZero() {
		riskScore.CalculatedAt =
			time.Now().UTC()
	} else {
		riskScore.CalculatedAt =
			riskScore.CalculatedAt.UTC()
	}

	if riskScore.ExpiresAt != nil {
		expiresAt := riskScore.ExpiresAt.UTC()
		riskScore.ExpiresAt = &expiresAt
	}

	if len(riskScore.RiskFactors) == 0 {
		riskScore.RiskFactors =
			json.RawMessage(`[]`)
	}

	transaction, err := r.db.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel: pgx.ReadCommitted,
		},
	)
	if err != nil {
		return nil, false, fmt.Errorf(
			"begin AI risk score transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(ctx)
	}()

	lockKey := fmt.Sprintf(
		"ai-risk:%s:%s:%s",
		riskScore.OrganizationID.String(),
		riskScore.RiskSubjectType,
		riskScore.RiskSubjectID.String(),
	)

	const lockQuery = `
		SELECT pg_advisory_xact_lock(
			hashtextextended(
				$1::text,
				0
			)
		);
	`

	if _, err = transaction.Exec(
		ctx,
		lockQuery,
		lockKey,
	); err != nil {
		return nil, false, fmt.Errorf(
			"lock AI risk subject: %w",
			err,
		)
	}

	const expireQuery = `
		UPDATE ai_risk_scores
		SET status = 'EXPIRED'
		WHERE
			organization_id = $1
			AND risk_subject_type = $2
			AND risk_subject_id = $3
			AND status = 'ACTIVE'
			AND expires_at IS NOT NULL
			AND expires_at <= $4;
	`

	if _, err = transaction.Exec(
		ctx,
		expireQuery,
		riskScore.OrganizationID,
		riskScore.RiskSubjectType,
		riskScore.RiskSubjectID,
		riskScore.CalculatedAt,
	); err != nil {
		return nil, false, fmt.Errorf(
			"expire previous AI risk scores: %w",
			err,
		)
	}

	findExistingQuery := `
		SELECT
	` + riskScoreSelectColumns + `
		FROM ai_risk_scores
		WHERE
			organization_id = $1
			AND risk_subject_type = $2
			AND risk_subject_id = $3
			AND status = 'ACTIVE'
			AND (
				expires_at IS NULL
				OR expires_at > $4
			)
		ORDER BY calculated_at DESC
		LIMIT 1
		FOR UPDATE;
	`

	existingRiskScore, findErr := scanRiskScore(
		transaction.QueryRow(
			ctx,
			findExistingQuery,
			riskScore.OrganizationID,
			riskScore.RiskSubjectType,
			riskScore.RiskSubjectID,
			riskScore.CalculatedAt,
		),
	)

	if findErr != nil &&
		!errors.Is(findErr, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf(
			"find existing AI risk score: %w",
			findErr,
		)
	}

	if findErr == nil && !replaceExisting {
		if err = transaction.Commit(ctx); err != nil {
			return nil, false, fmt.Errorf(
				"commit existing AI risk score transaction: %w",
				err,
			)
		}

		return existingRiskScore, false, nil
	}

	if findErr == nil && replaceExisting {
		const archiveQuery = `
			UPDATE ai_risk_scores
			SET status = 'ARCHIVED'
			WHERE
				organization_id = $1
				AND risk_subject_type = $2
				AND risk_subject_id = $3
				AND status = 'ACTIVE';
		`

		if _, err = transaction.Exec(
			ctx,
			archiveQuery,
			riskScore.OrganizationID,
			riskScore.RiskSubjectType,
			riskScore.RiskSubjectID,
		); err != nil {
			return nil, false, fmt.Errorf(
				"archive previous AI risk score: %w",
				err,
			)
		}
	}

	const insertQuery = `
		INSERT INTO ai_risk_scores (
			id,
			organization_id,
			analysis_job_id,
			incident_id,
			alert_id,
			evidence_id,
			risk_subject_type,
			risk_subject_id,
			overall_risk_score,
			risk_level,
			threat_probability,
			integrity_risk_score,
			confidentiality_risk_score,
			availability_risk_score,
			confidence_score,
			risk_factors,
			score_explanation,
			recommended_action,
			requires_human_review,
			status,
			calculated_at,
			expires_at
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			$8,
			$9,
			$10,
			$11,
			$12,
			$13,
			$14,
			$15,
			$16,
			$17,
			$18,
			$19,
			$20,
			$21,
			$22
		)
		RETURNING created_at;
	`

	err = transaction.QueryRow(
		ctx,
		insertQuery,
		riskScore.ID,
		riskScore.OrganizationID,
		riskScore.AnalysisJobID,
		riskScore.IncidentID,
		riskScore.AlertID,
		riskScore.EvidenceID,
		riskScore.RiskSubjectType,
		riskScore.RiskSubjectID,
		riskScore.OverallRiskScore,
		riskScore.RiskLevel,
		riskScore.ThreatProbability,
		riskScore.IntegrityRiskScore,
		riskScore.ConfidentialityRiskScore,
		riskScore.AvailabilityRiskScore,
		riskScore.ConfidenceScore,
		riskScore.RiskFactors,
		riskScore.ScoreExplanation,
		riskScore.RecommendedAction,
		riskScore.RequiresHumanReview,
		riskScore.Status,
		riskScore.CalculatedAt,
		riskScore.ExpiresAt,
	).Scan(
		&riskScore.CreatedAt,
	)
	if err != nil {
		return nil, false, fmt.Errorf(
			"insert calculated AI risk score: %w",
			err,
		)
	}

	if err = transaction.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf(
			"commit calculated AI risk score: %w",
			err,
		)
	}

	return riskScore, true, nil
}
