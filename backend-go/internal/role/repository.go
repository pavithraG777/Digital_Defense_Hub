package role

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrRoleNotFound          = errors.New("role not found")
	ErrRoleCodeAlreadyExists = errors.New("role code already exists")
	ErrRoleNameAlreadyExists = errors.New("role name already exists")
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		db: db,
	}
}

func (r *Repository) CreateRole(
	ctx context.Context,
	organizationID uuid.UUID,
	req CreateRoleRequest,
) (*CreateRoleResponse, error) {
	var roleCodeExists bool

	err := r.db.QueryRow(
		ctx,
		`
		SELECT EXISTS (
			SELECT 1
			FROM roles
			WHERE organization_id = $1
			  AND LOWER(role_code) = LOWER($2)
			  AND deleted_at IS NULL
		)
		`,
		organizationID,
		req.RoleCode,
	).Scan(&roleCodeExists)
	if err != nil {
		return nil, err
	}

	if roleCodeExists {
		return nil, ErrRoleCodeAlreadyExists
	}

	var roleNameExists bool

	err = r.db.QueryRow(
		ctx,
		`
		SELECT EXISTS (
			SELECT 1
			FROM roles
			WHERE organization_id = $1
			  AND LOWER(role_name) = LOWER($2)
			  AND deleted_at IS NULL
		)
		`,
		organizationID,
		req.RoleName,
	).Scan(&roleNameExists)
	if err != nil {
		return nil, err
	}

	if roleNameExists {
		return nil, ErrRoleNameAlreadyExists
	}

	roleScope := "ORGANIZATION"
	if req.RoleScope != "" {
		roleScope = req.RoleScope
	}

	priorityLevel := 100
	if req.PriorityLevel != nil {
		priorityLevel = *req.PriorityLevel
	}

	var role CreateRoleResponse

	err = r.db.QueryRow(
		ctx,
		`
		INSERT INTO roles (
			organization_id,
			role_code,
			role_name,
			description,
			role_scope,
			department_id,
			is_system_role,
			priority_level,
			status
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			FALSE,
			$7,
			'ACTIVE'
		)
		RETURNING
			id,
			organization_id,
			role_code,
			role_name,
			description,
			role_scope,
			department_id,
			is_system_role,
			priority_level,
			status
		`,
		organizationID,
		req.RoleCode,
		req.RoleName,
		req.Description,
		roleScope,
		req.DepartmentID,
		priorityLevel,
	).Scan(
		&role.ID,
		&role.OrganizationID,
		&role.RoleCode,
		&role.RoleName,
		&role.Description,
		&role.RoleScope,
		&role.DepartmentID,
		&role.IsSystemRole,
		&role.PriorityLevel,
		&role.Status,
	)
	if err != nil {
		return nil, err
	}

	return &role, nil
}

func (r *Repository) ListRoles(
	ctx context.Context,
	organizationID uuid.UUID,
	req ListRolesRequest,
) ([]RoleListItem, int64, error) {
	offset := (req.Page - 1) * req.PageSize

	var totalCount int64

	err := r.db.QueryRow(
		ctx,
		`
		SELECT COUNT(*)
		FROM roles
		WHERE organization_id = $1
		  AND deleted_at IS NULL
		  AND (
				$2 = ''
				OR role_code ILIKE '%' || $2 || '%'
				OR role_name ILIKE '%' || $2 || '%'
				OR COALESCE(description, '') ILIKE '%' || $2 || '%'
		  )
		  AND (
				$3 = ''
				OR status = $3
		  )
		`,
		organizationID,
		req.Search,
		req.Status,
	).Scan(&totalCount)
	if err != nil {
		return nil, 0, err
	}

	rows, err := r.db.Query(
		ctx,
		`
		SELECT
			id,
			organization_id,
			role_code,
			role_name,
			description,
			role_scope,
			department_id,
			is_system_role,
			priority_level,
			status
		FROM roles
		WHERE organization_id = $1
		  AND deleted_at IS NULL
		  AND (
				$2 = ''
				OR role_code ILIKE '%' || $2 || '%'
				OR role_name ILIKE '%' || $2 || '%'
				OR COALESCE(description, '') ILIKE '%' || $2 || '%'
		  )
		  AND (
				$3 = ''
				OR status = $3
		  )
		ORDER BY
			priority_level ASC,
			role_name ASC
		LIMIT $4
		OFFSET $5
		`,
		organizationID,
		req.Search,
		req.Status,
		req.PageSize,
		offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	roles := make([]RoleListItem, 0)

	for rows.Next() {
		var role RoleListItem

		err = rows.Scan(
			&role.ID,
			&role.OrganizationID,
			&role.RoleCode,
			&role.RoleName,
			&role.Description,
			&role.RoleScope,
			&role.DepartmentID,
			&role.IsSystemRole,
			&role.PriorityLevel,
			&role.Status,
		)
		if err != nil {
			return nil, 0, err
		}

		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return roles, totalCount, nil
}

func (r *Repository) GetRoleByID(
	ctx context.Context,
	organizationID uuid.UUID,
	roleID uuid.UUID,
) (*GetRoleResponse, error) {
	var role GetRoleResponse

	err := r.db.QueryRow(
		ctx,
		`
		SELECT
			id,
			organization_id,
			role_code,
			role_name,
			description,
			role_scope,
			department_id,
			is_system_role,
			priority_level,
			status
		FROM roles
		WHERE id = $1
		  AND organization_id = $2
		  AND deleted_at IS NULL
		`,
		roleID,
		organizationID,
	).Scan(
		&role.ID,
		&role.OrganizationID,
		&role.RoleCode,
		&role.RoleName,
		&role.Description,
		&role.RoleScope,
		&role.DepartmentID,
		&role.IsSystemRole,
		&role.PriorityLevel,
		&role.Status,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRoleNotFound
		}

		return nil, err
	}

	return &role, nil
}

func (r *Repository) UpdateRole(
	ctx context.Context,
	organizationID uuid.UUID,
	roleID uuid.UUID,
	req UpdateRoleRequest,
) (*GetRoleResponse, error) {

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var exists bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM roles
			WHERE id=$1
			AND organization_id=$2
			AND deleted_at IS NULL
		)
		`,
		roleID,
		organizationID,
	).Scan(&exists)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, ErrRoleNotFound
	}

	if req.RoleName != nil {

		var duplicate bool

		err = tx.QueryRow(
			ctx,
			`
			SELECT EXISTS(
				SELECT 1
				FROM roles
				WHERE organization_id=$1
				AND LOWER(role_name)=LOWER($2)
				AND id<>$3
				AND deleted_at IS NULL
			)
			`,
			organizationID,
			*req.RoleName,
			roleID,
		).Scan(&duplicate)
		if err != nil {
			return nil, err
		}

		if duplicate {
			return nil, ErrRoleNameAlreadyExists
		}
	}

	_, err = tx.Exec(
		ctx,
		`
		UPDATE roles
		SET
			role_name = COALESCE($1, role_name),
			description = COALESCE($2, description),
			role_scope = COALESCE($3, role_scope),
			department_id = COALESCE($4, department_id),
			priority_level = COALESCE($5, priority_level),
			status = COALESCE($6, status),
			updated_at = CURRENT_TIMESTAMP
		WHERE id=$7
		`,
		req.RoleName,
		req.Description,
		req.RoleScope,
		req.DepartmentID,
		req.PriorityLevel,
		req.Status,
		roleID,
	)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return r.GetRoleByID(
		ctx,
		organizationID,
		roleID,
	)
}

func (r *Repository) DeleteRole(
	ctx context.Context,
	organizationID uuid.UUID,
	roleID uuid.UUID,
) error {

	commandTag, err := r.db.Exec(
		ctx,
		`
		UPDATE roles
		SET
			status = 'INACTIVE',
			deleted_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND organization_id = $2
			AND deleted_at IS NULL
		`,
		roleID,
		organizationID,
	)
	if err != nil {
		return err
	}

	if commandTag.RowsAffected() == 0 {
		return ErrRoleNotFound
	}

	return nil
}
