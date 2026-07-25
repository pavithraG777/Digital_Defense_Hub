package airisk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrRiskScoreNotFound = errors.New(
		"AI risk score not found",
	)

	ErrRiskSubjectNotFound = errors.New(
		"AI risk subject not found",
	)
)

const riskScoreSelectColumns = `
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
	expires_at,
	created_at
`

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(
	databasePool *pgxpool.Pool,
) *Repository {
	return &Repository{
		db: databasePool,
	}
}

func (r *Repository) ValidateIncidentSubject(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
) error {
	if r == nil || r.db == nil {
		return errors.New(
			"AI risk repository is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return errors.New(
			"organization ID is required",
		)
	}

	if incidentID == uuid.Nil {
		return errors.New(
			"incident ID is required",
		)
	}

	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM incidents
			WHERE
				id = $1
				AND organization_id = $2
				AND deleted_at IS NULL
		);
	`

	var exists bool

	err := r.db.QueryRow(
		ctx,
		query,
		incidentID,
		organizationID,
	).Scan(&exists)
	if err != nil {
		return fmt.Errorf(
			"validate incident risk subject: %w",
			err,
		)
	}

	if !exists {
		return ErrRiskSubjectNotFound
	}

	return nil
}

func (r *Repository) CreateRiskScore(
	ctx context.Context,
	riskScore *RiskScore,
) error {
	if r == nil || r.db == nil {
		return errors.New(
			"AI risk repository is unavailable",
		)
	}

	if riskScore == nil {
		return errors.New(
			"AI risk score is required",
		)
	}

	if riskScore.ID == uuid.Nil {
		riskScore.ID = uuid.New()
	}

	if riskScore.OrganizationID == uuid.Nil {
		return errors.New(
			"organization ID is required",
		)
	}

	if riskScore.RiskSubjectID == uuid.Nil {
		return errors.New(
			"risk subject ID is required",
		)
	}

	if riskScore.Status == "" {
		riskScore.Status = RiskStatusActive
	}

	if riskScore.CalculatedAt.IsZero() {
		riskScore.CalculatedAt = time.Now().UTC()
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

	const query = `
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

	err := r.db.QueryRow(
		ctx,
		query,
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
		return fmt.Errorf(
			"create AI risk score: %w",
			err,
		)
	}

	return nil
}

func (r *Repository) FindRiskScoreByID(
	ctx context.Context,
	organizationID uuid.UUID,
	riskScoreID uuid.UUID,
) (*RiskScore, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"AI risk repository is unavailable",
		)
	}

	query := `
		SELECT
	` + riskScoreSelectColumns + `
		FROM ai_risk_scores
		WHERE
			id = $1
			AND organization_id = $2;
	`

	riskScore, err := scanRiskScore(
		r.db.QueryRow(
			ctx,
			query,
			riskScoreID,
			organizationID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRiskScoreNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"find AI risk score by ID: %w",
			err,
		)
	}

	return riskScore, nil
}

func (r *Repository) FindActiveRiskScoreBySubject(
	ctx context.Context,
	organizationID uuid.UUID,
	riskSubjectType string,
	riskSubjectID uuid.UUID,
	at time.Time,
) (*RiskScore, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"AI risk repository is unavailable",
		)
	}

	if at.IsZero() {
		at = time.Now().UTC()
	} else {
		at = at.UTC()
	}

	query := `
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
		LIMIT 1;
	`

	riskScore, err := scanRiskScore(
		r.db.QueryRow(
			ctx,
			query,
			organizationID,
			riskSubjectType,
			riskSubjectID,
			at,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRiskScoreNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"find active AI risk score: %w",
			err,
		)
	}

	return riskScore, nil
}

func (r *Repository) ArchiveActiveRiskScores(
	ctx context.Context,
	organizationID uuid.UUID,
	riskSubjectType string,
	riskSubjectID uuid.UUID,
) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New(
			"AI risk repository is unavailable",
		)
	}

	const query = `
		UPDATE ai_risk_scores
		SET status = 'ARCHIVED'
		WHERE
			organization_id = $1
			AND risk_subject_type = $2
			AND risk_subject_id = $3
			AND status = 'ACTIVE';
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		organizationID,
		riskSubjectType,
		riskSubjectID,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"archive active AI risk scores: %w",
			err,
		)
	}

	return commandTag.RowsAffected(), nil
}

func (r *Repository) ExpireRiskScores(
	ctx context.Context,
	expiredAt time.Time,
) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New(
			"AI risk repository is unavailable",
		)
	}

	if expiredAt.IsZero() {
		expiredAt = time.Now().UTC()
	} else {
		expiredAt = expiredAt.UTC()
	}

	const query = `
		UPDATE ai_risk_scores
		SET status = 'EXPIRED'
		WHERE
			status = 'ACTIVE'
			AND expires_at IS NOT NULL
			AND expires_at <= $1;
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		expiredAt,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"expire AI risk scores: %w",
			err,
		)
	}

	return commandTag.RowsAffected(), nil
}

func scanRiskScore(
	row pgx.Row,
) (*RiskScore, error) {
	riskScore := &RiskScore{}

	err := row.Scan(
		&riskScore.ID,
		&riskScore.OrganizationID,
		&riskScore.AnalysisJobID,
		&riskScore.IncidentID,
		&riskScore.AlertID,
		&riskScore.EvidenceID,
		&riskScore.RiskSubjectType,
		&riskScore.RiskSubjectID,
		&riskScore.OverallRiskScore,
		&riskScore.RiskLevel,
		&riskScore.ThreatProbability,
		&riskScore.IntegrityRiskScore,
		&riskScore.ConfidentialityRiskScore,
		&riskScore.AvailabilityRiskScore,
		&riskScore.ConfidenceScore,
		&riskScore.RiskFactors,
		&riskScore.ScoreExplanation,
		&riskScore.RecommendedAction,
		&riskScore.RequiresHumanReview,
		&riskScore.Status,
		&riskScore.CalculatedAt,
		&riskScore.ExpiresAt,
		&riskScore.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return riskScore, nil
}
