package honeytoken

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var (
	ErrIncidentDepartmentNotFound = errors.New(
		"incident department not found",
	)
	ErrIncidentAffectedUserNotFound = errors.New(
		"incident affected user not found",
	)
	ErrIncidentReporterNotFound = errors.New(
		"incident reporter not found",
	)
)

// ValidateIncidentRelations verifies that every referenced department and
// user belongs to the same organization as the incident.
func (r *IncidentRepository) ValidateIncidentRelations(
	ctx context.Context,
	organizationID uuid.UUID,
	departmentID *uuid.UUID,
	affectedUserID *uuid.UUID,
	leadInvestigatorID *uuid.UUID,
	reportedBy *uuid.UUID,
) error {
	if r == nil || r.db == nil {
		return errors.New(
			"incident repository is unavailable",
		)
	}

	var (
		departmentValid       bool
		affectedUserValid     bool
		leadInvestigatorValid bool
		reporterValid         bool
	)

	const query = `
		SELECT
			(
				$1::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM departments
					WHERE id = $1
					  AND organization_id = $5
					  AND deleted_at IS NULL
				)
			),
			(
				$2::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM users
					WHERE id = $2
					  AND organization_id = $5
					  AND deleted_at IS NULL
				)
			),
			(
				$3::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM users
					WHERE id = $3
					  AND organization_id = $5
					  AND deleted_at IS NULL
				)
			),
			(
				$4::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM users
					WHERE id = $4
					  AND organization_id = $5
					  AND deleted_at IS NULL
				)
			);
	`

	err := r.db.QueryRow(
		ctx,
		query,
		departmentID,
		affectedUserID,
		leadInvestigatorID,
		reportedBy,
		organizationID,
	).Scan(
		&departmentValid,
		&affectedUserValid,
		&leadInvestigatorValid,
		&reporterValid,
	)
	if err != nil {
		return fmt.Errorf(
			"validate incident relations: %w",
			err,
		)
	}

	if !departmentValid {
		return ErrIncidentDepartmentNotFound
	}

	if !affectedUserValid {
		return ErrIncidentAffectedUserNotFound
	}

	if !leadInvestigatorValid {
		return ErrIncidentInvestigatorNotFound
	}

	if !reporterValid {
		return ErrIncidentReporterNotFound
	}

	return nil
}
