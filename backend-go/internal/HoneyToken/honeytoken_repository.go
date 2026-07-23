package honeytoken

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrHoneytokenNotFound = errors.New(
		"honeytoken not found",
	)
	ErrHoneytokenCodeExists = errors.New(
		"honeytoken code already exists",
	)
)

// HoneytokenListFilter contains normalized repository filters.
type HoneytokenListFilter struct {
	Page  int
	Limit int

	Search         string
	HoneytokenType string
	Classification string
	Status         string

	DepartmentID *uuid.UUID
}

// CreateHoneytoken stores one organization-owned honeytoken.
func (r *Repository) CreateHoneytoken(
	ctx context.Context,
	token *Honeytoken,
) error {
	if r == nil || r.db == nil {
		return fmt.Errorf(
			"honeytoken repository is unavailable",
		)
	}

	if ctx == nil {
		return fmt.Errorf(
			"context is required",
		)
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"request context is not active: %w",
			err,
		)
	}

	if token == nil {
		return fmt.Errorf(
			"honeytoken is required",
		)
	}

	if token.ID == uuid.Nil {
		return fmt.Errorf(
			"honeytoken ID is required",
		)
	}

	if token.OrganizationID == uuid.Nil {
		return fmt.Errorf(
			"organization ID is required",
		)
	}

	if strings.TrimSpace(token.HoneytokenCode) == "" {
		return fmt.Errorf(
			"honeytoken code is required",
		)
	}

	if strings.TrimSpace(token.HoneytokenName) == "" {
		return fmt.Errorf(
			"honeytoken name is required",
		)
	}

	if strings.TrimSpace(token.HoneytokenType) == "" {
		return fmt.Errorf(
			"honeytoken type is required",
		)
	}

	if strings.TrimSpace(token.Classification) == "" {
		return fmt.Errorf(
			"honeytoken classification is required",
		)
	}

	if strings.TrimSpace(token.Status) == "" {
		return fmt.Errorf(
			"honeytoken status is required",
		)
	}

	const query = `
	INSERT INTO honeytokens (
		id,
		organization_id,
		department_id,
		policy_id,
		honeytoken_code,
		honeytoken_name,
		honeytoken_type,
		description,
		decoy_username,
		decoy_email,
		decoy_value_encrypted,
		decoy_value_hash,
		value_prefix,
		target_system,
		classification,
		owner_user_id,
		created_by,
		expires_at,
		status
	)
	VALUES (
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
		$11,$12,$13,$14,$15,$16,$17,$18,$19
	)
	RETURNING
		created_at,
		updated_at;
	`

	err := r.db.QueryRow(
		ctx,
		query,
		token.ID,
		token.OrganizationID,
		token.DepartmentID,
		token.PolicyID,
		token.HoneytokenCode,
		token.HoneytokenName,
		token.HoneytokenType,
		token.Description,
		token.DecoyUsername,
		token.DecoyEmail,
		token.DecoyValueEncrypted,
		token.DecoyValueHash,
		token.ValuePrefix,
		token.TargetSystem,
		token.Classification,
		token.OwnerUserID,
		token.CreatedBy,
		token.ExpiresAt,
		token.Status,
	).Scan(
		&token.CreatedAt,
		&token.UpdatedAt,
	)
	if err != nil {
		var databaseError *pgconn.PgError

		if errors.As(err, &databaseError) &&
			databaseError.Code == "23505" &&
			databaseError.ConstraintName == "uq_honeytoken_code" {
			return ErrHoneytokenCodeExists
		}

		return fmt.Errorf(
			"failed to create honeytoken: %w",
			err,
		)
	}

	return nil
}

// FindHoneytokenByID returns one non-deleted honeytoken belonging
// to the authenticated organization.
func (r *Repository) FindHoneytokenByID(
	ctx context.Context,
	organizationID uuid.UUID,
	honeytokenID uuid.UUID,
) (*Honeytoken, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf(
			"honeytoken repository is unavailable",
		)
	}

	if ctx == nil {
		return nil, fmt.Errorf(
			"context is required",
		)
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf(
			"request context is not active: %w",
			err,
		)
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"organization ID is required",
		)
	}

	if honeytokenID == uuid.Nil {
		return nil, fmt.Errorf(
			"honeytoken ID is required",
		)
	}

	const query = `
	SELECT
		id,
		organization_id,
		department_id,
		policy_id,
		honeytoken_code,
		honeytoken_name,
		honeytoken_type,
		description,
		decoy_username,
		decoy_email,
		decoy_value_encrypted,
		decoy_value_hash,
		value_prefix,
		target_system,
		deployment_location,
		classification,
		access_count,
		last_triggered_at,
		owner_user_id,
		created_by,
		deployed_at,
		expires_at,
		status,
		created_at,
		updated_at,
		deleted_at
	FROM honeytokens
	WHERE
		id = $1
		AND organization_id = $2
		AND deleted_at IS NULL
	LIMIT 1;
	`

	token, err := scanHoneytoken(
		r.db.QueryRow(
			ctx,
			query,
			honeytokenID,
			organizationID,
		),
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrHoneytokenNotFound
		}

		return nil, fmt.Errorf(
			"failed to find honeytoken: %w",
			err,
		)
	}

	return token, nil
}

// ListHoneytokens returns paginated organization-owned honeytokens.
func (r *Repository) ListHoneytokens(
	ctx context.Context,
	organizationID uuid.UUID,
	filter HoneytokenListFilter,
) ([]*Honeytoken, int, error) {
	if r == nil || r.db == nil {
		return nil, 0, fmt.Errorf(
			"honeytoken repository is unavailable",
		)
	}

	if ctx == nil {
		return nil, 0, fmt.Errorf(
			"context is required",
		)
	}

	if err := ctx.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"request context is not active: %w",
			err,
		)
	}

	if organizationID == uuid.Nil {
		return nil, 0, fmt.Errorf(
			"organization ID is required",
		)
	}

	filter = normalizeHoneytokenListFilter(
		filter,
	)

	const countQuery = `
	SELECT COUNT(*)
	FROM honeytokens
	WHERE
		organization_id = $1
		AND deleted_at IS NULL
		AND ($2 = '' OR UPPER(honeytoken_type) = $2)
		AND ($3 = '' OR UPPER(classification) = $3)
		AND ($4 = '' OR UPPER(status) = $4)
		AND ($5::uuid IS NULL OR department_id = $5)
		AND (
			$6 = ''
			OR honeytoken_name ILIKE '%' || $6 || '%'
			OR honeytoken_code ILIKE '%' || $6 || '%'
			OR COALESCE(target_system, '') ILIKE '%' || $6 || '%'
		);
	`

	var total int

	if err := r.db.QueryRow(
		ctx,
		countQuery,
		organizationID,
		filter.HoneytokenType,
		filter.Classification,
		filter.Status,
		filter.DepartmentID,
		filter.Search,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf(
			"failed to count honeytokens: %w",
			err,
		)
	}

	const listQuery = `
	SELECT
		id,
		organization_id,
		department_id,
		policy_id,
		honeytoken_code,
		honeytoken_name,
		honeytoken_type,
		description,
		decoy_username,
		decoy_email,
		decoy_value_encrypted,
		decoy_value_hash,
		value_prefix,
		target_system,
		deployment_location,
		classification,
		access_count,
		last_triggered_at,
		owner_user_id,
		created_by,
		deployed_at,
		expires_at,
		status,
		created_at,
		updated_at,
		deleted_at
	FROM honeytokens
	WHERE
		organization_id = $1
		AND deleted_at IS NULL
		AND ($2 = '' OR UPPER(honeytoken_type) = $2)
		AND ($3 = '' OR UPPER(classification) = $3)
		AND ($4 = '' OR UPPER(status) = $4)
		AND ($5::uuid IS NULL OR department_id = $5)
		AND (
			$6 = ''
			OR honeytoken_name ILIKE '%' || $6 || '%'
			OR honeytoken_code ILIKE '%' || $6 || '%'
			OR COALESCE(target_system, '') ILIKE '%' || $6 || '%'
		)
	ORDER BY created_at DESC, id DESC
	LIMIT $7
	OFFSET $8;
	`

	offset := (filter.Page - 1) * filter.Limit

	rows, err := r.db.Query(
		ctx,
		listQuery,
		organizationID,
		filter.HoneytokenType,
		filter.Classification,
		filter.Status,
		filter.DepartmentID,
		filter.Search,
		filter.Limit,
		offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"failed to list honeytokens: %w",
			err,
		)
	}
	defer rows.Close()

	tokens := make(
		[]*Honeytoken,
		0,
		filter.Limit,
	)

	for rows.Next() {
		token, scanError := scanHoneytoken(rows)
		if scanError != nil {
			return nil, 0, fmt.Errorf(
				"failed to scan honeytoken: %w",
				scanError,
			)
		}

		tokens = append(
			tokens,
			token,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"failed while reading honeytokens: %w",
			err,
		)
	}

	return tokens, total, nil
}

func normalizeHoneytokenListFilter(
	filter HoneytokenListFilter,
) HoneytokenListFilter {
	if filter.Page < 1 {
		filter.Page = 1
	}

	if filter.Limit < 1 {
		filter.Limit = 20
	}

	if filter.Limit > 100 {
		filter.Limit = 100
	}

	filter.Search = strings.TrimSpace(
		filter.Search,
	)
	filter.HoneytokenType = strings.ToUpper(
		strings.TrimSpace(filter.HoneytokenType),
	)
	filter.Classification = strings.ToUpper(
		strings.TrimSpace(filter.Classification),
	)
	filter.Status = strings.ToUpper(
		strings.TrimSpace(filter.Status),
	)

	return filter
}

type honeytokenScanner interface {
	Scan(destinations ...any) error
}

func scanHoneytoken(
	scanner honeytokenScanner,
) (*Honeytoken, error) {
	if scanner == nil {
		return nil, fmt.Errorf(
			"honeytoken scanner is required",
		)
	}

	var token Honeytoken

	if err := scanner.Scan(
		&token.ID,
		&token.OrganizationID,
		&token.DepartmentID,
		&token.PolicyID,
		&token.HoneytokenCode,
		&token.HoneytokenName,
		&token.HoneytokenType,
		&token.Description,
		&token.DecoyUsername,
		&token.DecoyEmail,
		&token.DecoyValueEncrypted,
		&token.DecoyValueHash,
		&token.ValuePrefix,
		&token.TargetSystem,
		&token.DeploymentLocation,
		&token.Classification,
		&token.AccessCount,
		&token.LastTriggeredAt,
		&token.OwnerUserID,
		&token.CreatedBy,
		&token.DeployedAt,
		&token.ExpiresAt,
		&token.Status,
		&token.CreatedAt,
		&token.UpdatedAt,
		&token.DeletedAt,
	); err != nil {
		return nil, err
	}

	return &token, nil
}

var (
	ErrHoneytokenDepartmentNotFound = errors.New(
		"honeytoken department was not found in the organization",
	)
	ErrHoneytokenPolicyNotFound = errors.New(
		"honeytoken policy was not found in the organization",
	)
	ErrHoneytokenOwnerNotFound = errors.New(
		"honeytoken owner was not found in the organization",
	)
	ErrHoneytokenCreatorNotFound = errors.New(
		"honeytoken creator was not found in the organization",
	)
)

// ValidateHoneytokenRelations prevents cross-organization foreign-key
// assignments for departments, policies, owners and creators.
func (r *Repository) ValidateHoneytokenRelations(
	ctx context.Context,
	organizationID uuid.UUID,
	createdBy uuid.UUID,
	departmentID *uuid.UUID,
	policyID *uuid.UUID,
	ownerUserID *uuid.UUID,
) error {
	if r == nil || r.db == nil {
		return fmt.Errorf(
			"honeytoken repository is unavailable",
		)
	}

	if ctx == nil {
		return fmt.Errorf(
			"context is required",
		)
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"request context is not active: %w",
			err,
		)
	}

	if organizationID == uuid.Nil {
		return fmt.Errorf(
			"organization ID is required",
		)
	}

	if createdBy == uuid.Nil {
		return fmt.Errorf(
			"creator user ID is required",
		)
	}

	const query = `
	SELECT
		EXISTS (
			SELECT 1
			FROM users
			WHERE
				id = $2
				AND organization_id = $1
		),
		(
			$3::uuid IS NULL
			OR EXISTS (
				SELECT 1
				FROM departments
				WHERE
					id = $3
					AND organization_id = $1
			)
		),
		(
			$4::uuid IS NULL
			OR EXISTS (
				SELECT 1
				FROM deception_policies
				WHERE
					id = $4
					AND organization_id = $1
			)
		),
		(
			$5::uuid IS NULL
			OR EXISTS (
				SELECT 1
				FROM users
				WHERE
					id = $5
					AND organization_id = $1
			)
		);
	`

	var (
		creatorExists    bool
		departmentExists bool
		policyExists     bool
		ownerExists      bool
	)

	if err := r.db.QueryRow(
		ctx,
		query,
		organizationID,
		createdBy,
		departmentID,
		policyID,
		ownerUserID,
	).Scan(
		&creatorExists,
		&departmentExists,
		&policyExists,
		&ownerExists,
	); err != nil {
		return fmt.Errorf(
			"failed to validate honeytoken relations: %w",
			err,
		)
	}

	if !creatorExists {
		return ErrHoneytokenCreatorNotFound
	}

	if !departmentExists {
		return ErrHoneytokenDepartmentNotFound
	}

	if !policyExists {
		return ErrHoneytokenPolicyNotFound
	}

	if !ownerExists {
		return ErrHoneytokenOwnerNotFound
	}

	return nil
}

var (
	ErrHoneytokenNotDeployable = errors.New(
		"honeytoken cannot be deployed in its current state",
	)
	ErrHoneytokenNotActive = errors.New(
		"honeytoken is not active",
	)
)

// DeployHoneytoken atomically changes a DRAFT or INACTIVE honeytoken
// into ACTIVE state and stores its deployment metadata.
func (r *Repository) DeployHoneytoken(
	ctx context.Context,
	organizationID uuid.UUID,
	honeytokenID uuid.UUID,
	deploymentLocation string,
	targetSystem string,
) (*Honeytoken, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf(
			"honeytoken repository is unavailable",
		)
	}

	if ctx == nil {
		return nil, fmt.Errorf(
			"context is required",
		)
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf(
			"request context is not active: %w",
			err,
		)
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"organization ID is required",
		)
	}

	if honeytokenID == uuid.Nil {
		return nil, fmt.Errorf(
			"honeytoken ID is required",
		)
	}

	deploymentLocation = strings.TrimSpace(
		deploymentLocation,
	)
	if deploymentLocation == "" {
		return nil, fmt.Errorf(
			"deployment location is required",
		)
	}

	targetSystem = strings.TrimSpace(
		targetSystem,
	)

	const query = `
	UPDATE honeytokens
	SET
		deployment_location = $3,
		target_system = COALESCE(
			NULLIF($4, ''),
			target_system
		),
		status = 'ACTIVE',
		deployed_at = CURRENT_TIMESTAMP,
		updated_at = CURRENT_TIMESTAMP
	WHERE
		id = $1
		AND organization_id = $2
		AND deleted_at IS NULL
		AND status IN ('DRAFT', 'INACTIVE')
	RETURNING
		id,
		organization_id,
		department_id,
		policy_id,
		honeytoken_code,
		honeytoken_name,
		honeytoken_type,
		description,
		decoy_username,
		decoy_email,
		decoy_value_encrypted,
		decoy_value_hash,
		value_prefix,
		target_system,
		deployment_location,
		classification,
		access_count,
		last_triggered_at,
		owner_user_id,
		created_by,
		deployed_at,
		expires_at,
		status,
		created_at,
		updated_at,
		deleted_at;
	`

	token, err := scanHoneytoken(
		r.db.QueryRow(
			ctx,
			query,
			honeytokenID,
			organizationID,
			deploymentLocation,
			targetSystem,
		),
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrHoneytokenNotDeployable
		}

		return nil, fmt.Errorf(
			"failed to deploy honeytoken: %w",
			err,
		)
	}

	return token, nil
}

// RecordHoneytokenTrigger atomically records one confirmed access.
//
// ACTIVE changes to TRIGGERED. Subsequent confirmed accesses continue
// incrementing access_count while the status remains TRIGGERED.
func (r *Repository) RecordHoneytokenTrigger(
	ctx context.Context,
	organizationID uuid.UUID,
	honeytokenID uuid.UUID,
) (*Honeytoken, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf(
			"honeytoken repository is unavailable",
		)
	}

	if ctx == nil {
		return nil, fmt.Errorf(
			"context is required",
		)
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf(
			"request context is not active: %w",
			err,
		)
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"organization ID is required",
		)
	}

	if honeytokenID == uuid.Nil {
		return nil, fmt.Errorf(
			"honeytoken ID is required",
		)
	}

	const query = `
	UPDATE honeytokens
	SET
		access_count = access_count + 1,
		last_triggered_at = CURRENT_TIMESTAMP,
		status = 'TRIGGERED',
		updated_at = CURRENT_TIMESTAMP
	WHERE
		id = $1
		AND organization_id = $2
		AND deleted_at IS NULL
		AND status IN ('ACTIVE', 'TRIGGERED')
		AND (
			expires_at IS NULL
			OR expires_at > CURRENT_TIMESTAMP
		)
	RETURNING
		id,
		organization_id,
		department_id,
		policy_id,
		honeytoken_code,
		honeytoken_name,
		honeytoken_type,
		description,
		decoy_username,
		decoy_email,
		decoy_value_encrypted,
		decoy_value_hash,
		value_prefix,
		target_system,
		deployment_location,
		classification,
		access_count,
		last_triggered_at,
		owner_user_id,
		created_by,
		deployed_at,
		expires_at,
		status,
		created_at,
		updated_at,
		deleted_at;
	`

	token, err := scanHoneytoken(
		r.db.QueryRow(
			ctx,
			query,
			honeytokenID,
			organizationID,
		),
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrHoneytokenNotActive
		}

		return nil, fmt.Errorf(
			"failed to record honeytoken trigger: %w",
			err,
		)
	}

	return token, nil
}
