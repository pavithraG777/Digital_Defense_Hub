package adaptivedeception

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

const canaryHealthCheckSelectColumns = `
	id,
	health_check_sequence,
	organization_id,
	canary_file_id,
	policy_id,
	check_type,
	expected_file_path,
	observed_file_path,
	expected_hash,
	observed_hash,
	hash_algorithm,
	expected_size_bytes,
	observed_size_bytes,
	file_exists,
	path_matches,
	hash_matches,
		COALESCE(
		size_matches,
		FALSE
	) AS size_matches,
	COALESCE(
		permissions_valid,
		FALSE
	) AS permissions_valid,
	is_healthy,
	health_score,
	health_status,
	failure_reason,
	check_metadata,
	checked_at,
	next_check_at,
	created_at
`

type healthCheckRowScanner interface {
	Scan(destinations ...any) error
}

func (r *Repository) CreateHealthCheck(
	ctx context.Context,
	healthCheck *CanaryHealthCheck,
) (*CanaryHealthCheck, error) {
	if r == nil || r.db == nil {
		return nil,
			ErrAdaptiveDeceptionRepositoryUnavailable
	}

	if healthCheck == nil {
		return nil, errors.New(
			"canary health check is required",
		)
	}

	if healthCheck.ID == uuid.Nil {
		healthCheck.ID = uuid.New()
	}

	if healthCheck.OrganizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if healthCheck.CanaryFileID == uuid.Nil {
		return nil, errors.New(
			"canary file ID is required",
		)
	}

	healthCheck.CheckType =
		NormalizeConstant(
			healthCheck.CheckType,
		)

	if !IsSupportedHealthCheckType(
		healthCheck.CheckType,
	) {
		return nil, errors.New(
			"unsupported canary health check type",
		)
	}

	healthCheck.ExpectedFilePath =
		strings.TrimSpace(
			healthCheck.ExpectedFilePath,
		)

	if healthCheck.ExpectedFilePath == "" {
		return nil, errors.New(
			"expected canary file path is required",
		)
	}

	healthCheck.ExpectedHash =
		strings.ToLower(
			strings.TrimSpace(
				healthCheck.ExpectedHash,
			),
		)

	if healthCheck.ExpectedHash == "" {
		return nil, errors.New(
			"expected canary file hash is required",
		)
	}

	healthCheck.HashAlgorithm =
		NormalizeConstant(
			healthCheck.HashAlgorithm,
		)

	if !IsSupportedHashAlgorithm(
		healthCheck.HashAlgorithm,
	) {
		return nil, errors.New(
			"unsupported canary hash algorithm",
		)
	}

	healthCheck.HealthStatus =
		NormalizeConstant(
			healthCheck.HealthStatus,
		)

	if !IsSupportedCanaryHealthStatus(
		healthCheck.HealthStatus,
	) {
		return nil, errors.New(
			"unsupported canary health status",
		)
	}

	if !IsValidScore(
		healthCheck.HealthScore,
	) {
		return nil, errors.New(
			"canary health score must be between 0 and 100",
		)
	}

	if healthCheck.ExpectedSizeBytes != nil &&
		*healthCheck.ExpectedSizeBytes < 0 {
		return nil, errors.New(
			"expected file size cannot be negative",
		)
	}

	if healthCheck.ObservedSizeBytes != nil &&
		*healthCheck.ObservedSizeBytes < 0 {
		return nil, errors.New(
			"observed file size cannot be negative",
		)
	}

	if healthCheck.CheckedAt.IsZero() {
		healthCheck.CheckedAt =
			time.Now().UTC()
	} else {
		healthCheck.CheckedAt =
			healthCheck.CheckedAt.UTC()
	}

	healthCheck.NextCheckAt =
		utcTimePointer(
			healthCheck.NextCheckAt,
		)

	if healthCheck.NextCheckAt != nil &&
		!healthCheck.NextCheckAt.After(
			healthCheck.CheckedAt,
		) {
		return nil, errors.New(
			"next health check must be after checked time",
		)
	}

	if healthCheck.ObservedFilePath != nil {
		value := strings.TrimSpace(
			*healthCheck.ObservedFilePath,
		)

		if value == "" {
			healthCheck.ObservedFilePath = nil
		} else {
			healthCheck.ObservedFilePath = &value
		}
	}

	if healthCheck.ObservedHash != nil {
		value := strings.ToLower(
			strings.TrimSpace(
				*healthCheck.ObservedHash,
			),
		)

		if value == "" {
			healthCheck.ObservedHash = nil
		} else {
			healthCheck.ObservedHash = &value
		}
	}

	if healthCheck.FailureReason != nil {
		value := strings.TrimSpace(
			*healthCheck.FailureReason,
		)

		if value == "" {
			healthCheck.FailureReason = nil
		} else {
			healthCheck.FailureReason = &value
		}
	}

	if healthCheck.Metadata == nil {
		healthCheck.Metadata =
			make(map[string]any)
	}

	metadataJSON, err := json.Marshal(
		healthCheck.Metadata,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode canary health metadata: %w",
			err,
		)
	}

	const query = `
		INSERT INTO canary_health_checks (
			id,
			organization_id,
			canary_file_id,
			policy_id,
			check_type,
			expected_file_path,
			observed_file_path,
			expected_hash,
			observed_hash,
			hash_algorithm,
			expected_size_bytes,
			observed_size_bytes,
			file_exists,
			path_matches,
			hash_matches,
			size_matches,
			permissions_valid,
			is_healthy,
			health_score,
			health_status,
			failure_reason,
			check_metadata,
			checked_at,
			next_check_at
		)
		VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17, $18,
			$19, $20, $21, $22, $23, $24
		)
		RETURNING ` + canaryHealthCheckSelectColumns + `;
	`

	result, err := scanCanaryHealthCheck(
		r.db.QueryRow(
			ctx,
			query,
			healthCheck.ID,
			healthCheck.OrganizationID,
			healthCheck.CanaryFileID,
			healthCheck.PolicyID,
			healthCheck.CheckType,
			healthCheck.ExpectedFilePath,
			healthCheck.ObservedFilePath,
			healthCheck.ExpectedHash,
			healthCheck.ObservedHash,
			healthCheck.HashAlgorithm,
			healthCheck.ExpectedSizeBytes,
			healthCheck.ObservedSizeBytes,
			healthCheck.FileExists,
			healthCheck.PathMatches,
			healthCheck.HashMatches,
			healthCheck.SizeMatches,
			healthCheck.PermissionsValid,
			healthCheck.IsHealthy,
			healthCheck.HealthScore,
			healthCheck.HealthStatus,
			healthCheck.FailureReason,
			metadataJSON,
			healthCheck.CheckedAt,
			healthCheck.NextCheckAt,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create canary health check: %w",
			err,
		)
	}

	return result, nil
}

func (r *Repository) GetLatestHealthCheck(
	ctx context.Context,
	organizationID uuid.UUID,
	canaryFileID uuid.UUID,
) (*CanaryHealthCheck, error) {
	if r == nil || r.db == nil {
		return nil,
			ErrAdaptiveDeceptionRepositoryUnavailable
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if canaryFileID == uuid.Nil {
		return nil, errors.New(
			"canary file ID is required",
		)
	}

	const query = `
		SELECT ` + canaryHealthCheckSelectColumns + `
		FROM canary_health_checks
		WHERE
			organization_id = $1
			AND canary_file_id = $2
		ORDER BY
			checked_at DESC,
			health_check_sequence DESC
		LIMIT 1;
	`

	healthCheck, err := scanCanaryHealthCheck(
		r.db.QueryRow(
			ctx,
			query,
			organizationID,
			canaryFileID,
		),
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil,
				ErrCanaryHealthCheckNotFound
		}

		return nil, fmt.Errorf(
			"get latest canary health check: %w",
			err,
		)
	}

	return healthCheck, nil
}

func scanCanaryHealthCheck(
	scanner healthCheckRowScanner,
) (*CanaryHealthCheck, error) {
	var healthCheck CanaryHealthCheck
	var metadataJSON []byte

	err := scanner.Scan(
		&healthCheck.ID,
		&healthCheck.HealthCheckSequence,
		&healthCheck.OrganizationID,
		&healthCheck.CanaryFileID,
		&healthCheck.PolicyID,
		&healthCheck.CheckType,
		&healthCheck.ExpectedFilePath,
		&healthCheck.ObservedFilePath,
		&healthCheck.ExpectedHash,
		&healthCheck.ObservedHash,
		&healthCheck.HashAlgorithm,
		&healthCheck.ExpectedSizeBytes,
		&healthCheck.ObservedSizeBytes,
		&healthCheck.FileExists,
		&healthCheck.PathMatches,
		&healthCheck.HashMatches,
		&healthCheck.SizeMatches,
		&healthCheck.PermissionsValid,
		&healthCheck.IsHealthy,
		&healthCheck.HealthScore,
		&healthCheck.HealthStatus,
		&healthCheck.FailureReason,
		&metadataJSON,
		&healthCheck.CheckedAt,
		&healthCheck.NextCheckAt,
		&healthCheck.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	healthCheck.Metadata =
		make(map[string]any)

	if len(metadataJSON) > 0 {
		if err = json.Unmarshal(
			metadataJSON,
			&healthCheck.Metadata,
		); err != nil {
			return nil, fmt.Errorf(
				"decode canary health metadata: %w",
				err,
			)
		}
	}

	healthCheck.CheckType =
		NormalizeConstant(
			healthCheck.CheckType,
		)

	healthCheck.HashAlgorithm =
		NormalizeConstant(
			healthCheck.HashAlgorithm,
		)

	healthCheck.HealthStatus =
		NormalizeConstant(
			healthCheck.HealthStatus,
		)

	healthCheck.CheckedAt =
		healthCheck.CheckedAt.UTC()

	healthCheck.NextCheckAt =
		utcTimePointer(
			healthCheck.NextCheckAt,
		)

	healthCheck.CreatedAt =
		healthCheck.CreatedAt.UTC()

	return &healthCheck, nil
}
