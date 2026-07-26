package adaptivedeception

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	defaultFingerprintPageSize = 20
	maximumFingerprintPageSize = 100
)

type FingerprintListFilter struct {
	OrganizationID uuid.UUID
	CanaryFileID   *uuid.UUID

	EventType string

	IsSuspicious        *bool
	RansomwareSuspected *bool

	MinimumBehaviouralScore *float64

	ObservedFrom *time.Time
	ObservedTo   *time.Time

	Limit  int
	Offset int
}

const fingerprintFilterClause = `
	AND (
		$2::uuid IS NULL
		OR canary_file_id = $2
	)
	AND (
		$3::text = ''
		OR event_type = $3
	)
	AND (
		$4::boolean IS NULL
		OR is_suspicious = $4
	)
	AND (
		$5::boolean IS NULL
		OR ransomware_suspected = $5
	)
	AND (
		$6::numeric IS NULL
		OR behavioural_score >= $6
	)
	AND (
		$7::timestamp IS NULL
		OR last_observed_at >= $7
	)
	AND (
		$8::timestamp IS NULL
		OR last_observed_at <= $8
	)
`

func (r *Repository) GetCanaryInteractionFingerprint(
	ctx context.Context,
	organizationID uuid.UUID,
	fingerprintID uuid.UUID,
) (*CanaryInteractionFingerprint, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"adaptive deception repository is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if fingerprintID == uuid.Nil {
		return nil, errors.New(
			"fingerprint ID is required",
		)
	}

	const query = `
		SELECT ` + fingerprintSelectColumns + `
		FROM canary_interaction_fingerprints
		WHERE
			organization_id = $1
			AND id = $2
		LIMIT 1;
	`

	fingerprint, err :=
		scanCanaryInteractionFingerprint(
			r.db.QueryRow(
				ctx,
				query,
				organizationID,
				fingerprintID,
			),
		)
	if err != nil {
		if errors.Is(
			err,
			pgx.ErrNoRows,
		) {
			return nil,
				ErrCanaryFingerprintNotFound
		}

		return nil, fmt.Errorf(
			"get canary interaction fingerprint: %w",
			err,
		)
	}

	return fingerprint, nil
}

func (r *Repository) ListCanaryInteractionFingerprints(
	ctx context.Context,
	filter FingerprintListFilter,
) (
	[]CanaryInteractionFingerprint,
	int64,
	error,
) {
	if r == nil || r.db == nil {
		return nil, 0, errors.New(
			"adaptive deception repository is unavailable",
		)
	}

	if err := validateFingerprintListFilter(
		filter,
	); err != nil {
		return nil, 0, err
	}

	filter = normalizeFingerprintListFilter(
		filter,
	)

	if filter.OrganizationID == uuid.Nil {
		return nil, 0, errors.New(
			"organization ID is required",
		)
	}

	arguments := []any{
		filter.OrganizationID,
		filter.CanaryFileID,
		filter.EventType,
		filter.IsSuspicious,
		filter.RansomwareSuspected,
		filter.MinimumBehaviouralScore,
		filter.ObservedFrom,
		filter.ObservedTo,
	}

	countQuery := `
		SELECT COUNT(*)
		FROM canary_interaction_fingerprints
		WHERE organization_id = $1
	` + fingerprintFilterClause + `;
	`

	var total int64

	if err := r.db.QueryRow(
		ctx,
		countQuery,
		arguments...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf(
			"count canary interaction fingerprints: %w",
			err,
		)
	}

	listQuery := `
		SELECT ` + fingerprintSelectColumns + `
		FROM canary_interaction_fingerprints
		WHERE organization_id = $1
	` + fingerprintFilterClause + `
		ORDER BY
			last_observed_at DESC,
			fingerprint_sequence DESC
		LIMIT $9
		OFFSET $10;
	`

	listArguments := append(
		arguments,
		filter.Limit,
		filter.Offset,
	)

	rows, err := r.db.Query(
		ctx,
		listQuery,
		listArguments...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"list canary interaction fingerprints: %w",
			err,
		)
	}
	defer rows.Close()

	fingerprints := make(
		[]CanaryInteractionFingerprint,
		0,
		filter.Limit,
	)

	for rows.Next() {
		fingerprint, scanErr :=
			scanCanaryInteractionFingerprint(
				rows,
			)
		if scanErr != nil {
			return nil, 0, fmt.Errorf(
				"scan canary interaction fingerprint: %w",
				scanErr,
			)
		}

		fingerprints = append(
			fingerprints,
			*fingerprint,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"iterate canary interaction fingerprints: %w",
			err,
		)
	}

	return fingerprints, total, nil
}

func normalizeFingerprintListFilter(
	filter FingerprintListFilter,
) FingerprintListFilter {
	filter.EventType =
		NormalizeConstant(
			filter.EventType,
		)

	filter.CanaryFileID =
		normalizeFingerprintUUIDPointer(
			filter.CanaryFileID,
		)

	if filter.MinimumBehaviouralScore != nil {
		value := clampFingerprintScore(
			*filter.MinimumBehaviouralScore,
		)

		filter.MinimumBehaviouralScore =
			&value
	}

	if filter.ObservedFrom != nil {
		value := filter.ObservedFrom.UTC()
		filter.ObservedFrom = &value
	}

	if filter.ObservedTo != nil {
		value := filter.ObservedTo.UTC()
		filter.ObservedTo = &value
	}

	if filter.Limit <= 0 {
		filter.Limit =
			defaultFingerprintPageSize
	}

	if filter.Limit >
		maximumFingerprintPageSize {
		filter.Limit =
			maximumFingerprintPageSize
	}

	if filter.Offset < 0 {
		filter.Offset = 0
	}

	return filter
}

func validateFingerprintListFilter(
	filter FingerprintListFilter,
) error {
	if filter.EventType != "" &&
		strings.TrimSpace(
			filter.EventType,
		) == "" {
		return errors.New(
			"fingerprint event type is invalid",
		)
	}

	if filter.MinimumBehaviouralScore != nil &&
		(*filter.MinimumBehaviouralScore < 0 ||
			*filter.MinimumBehaviouralScore > 100) {
		return errors.New(
			"minimum behavioural score must be between 0 and 100",
		)
	}

	if filter.ObservedFrom != nil &&
		filter.ObservedTo != nil &&
		filter.ObservedTo.Before(
			*filter.ObservedFrom,
		) {
		return errors.New(
			"observed to time cannot precede observed from time",
		)
	}

	return nil
}
