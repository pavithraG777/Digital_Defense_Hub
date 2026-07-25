package airisk

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type RiskScoreListFilter struct {
	OrganizationID uuid.UUID

	RiskSubjectType string
	RiskSubjectID   *uuid.UUID
	RiskLevel       string
	Status          string

	Limit  int
	Offset int
}

func (r *Repository) ListRiskScores(
	ctx context.Context,
	filter RiskScoreListFilter,
) ([]RiskScore, int64, error) {
	if r == nil || r.db == nil {
		return nil, 0, errors.New(
			"AI risk repository is unavailable",
		)
	}

	if filter.OrganizationID == uuid.Nil {
		return nil, 0, errors.New(
			"organization ID is required",
		)
	}

	if filter.Limit <= 0 {
		return nil, 0, errors.New(
			"AI risk score query limit is required",
		)
	}

	if filter.Offset < 0 {
		return nil, 0, errors.New(
			"AI risk score query offset is invalid",
		)
	}

	conditions := []string{
		"organization_id = $1",
	}

	arguments := []any{
		filter.OrganizationID,
	}

	addCondition := func(
		condition string,
		value any,
	) {
		arguments = append(
			arguments,
			value,
		)

		conditions = append(
			conditions,
			fmt.Sprintf(
				condition,
				len(arguments),
			),
		)
	}

	if filter.RiskSubjectType != "" {
		addCondition(
			"risk_subject_type = $%d",
			filter.RiskSubjectType,
		)
	}

	if filter.RiskSubjectID != nil {
		addCondition(
			"risk_subject_id = $%d",
			*filter.RiskSubjectID,
		)
	}

	if filter.RiskLevel != "" {
		addCondition(
			"risk_level = $%d",
			filter.RiskLevel,
		)
	}

	if filter.Status != "" {
		addCondition(
			"status = $%d",
			filter.Status,
		)
	}

	whereClause := strings.Join(
		conditions,
		" AND ",
	)

	countQuery := `
		SELECT COUNT(*)
		FROM ai_risk_scores
		WHERE ` + whereClause + `;
	`

	var total int64

	err := r.db.QueryRow(
		ctx,
		countQuery,
		arguments...,
	).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"count AI risk scores: %w",
			err,
		)
	}

	queryArguments := append(
		[]any{},
		arguments...,
	)

	queryArguments = append(
		queryArguments,
		filter.Limit,
		filter.Offset,
	)

	limitPosition :=
		len(queryArguments) - 1

	offsetPosition :=
		len(queryArguments)

	listQuery := `
		SELECT
	` + riskScoreSelectColumns + `
		FROM ai_risk_scores
		WHERE ` + whereClause + `
		ORDER BY
			calculated_at DESC,
			id DESC
		LIMIT $` + fmt.Sprintf(
		"%d",
		limitPosition,
	) + `
		OFFSET $` + fmt.Sprintf(
		"%d",
		offsetPosition,
	) + `;
	`

	rows, err := r.db.Query(
		ctx,
		listQuery,
		queryArguments...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"list AI risk scores: %w",
			err,
		)
	}
	defer rows.Close()

	riskScores := make(
		[]RiskScore,
		0,
		filter.Limit,
	)

	for rows.Next() {
		riskScore, scanErr :=
			scanRiskScore(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf(
				"scan AI risk score: %w",
				scanErr,
			)
		}

		riskScores = append(
			riskScores,
			*riskScore,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"iterate AI risk scores: %w",
			err,
		)
	}

	return riskScores, total, nil
}
