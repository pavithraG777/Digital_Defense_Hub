package permission

import (
	"context"
	"errors"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrPermissionNotFound            = errors.New("permission not found")
	ErrPermissionCodeAlreadyExists   = errors.New("permission code already exists")
	ErrPermissionActionAlreadyExists = errors.New("permission action already exists")
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		db: db,
	}
}

func (r *Repository) CreatePermission(
	ctx context.Context,
	req CreatePermissionRequest,
) (*CreatePermissionResponse, error) {

	var exists bool

	err := r.db.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM permissions
			WHERE permission_code = $1
		)
		`,
		req.PermissionCode,
	).Scan(&exists)
	if err != nil {
		return nil, err
	}

	if exists {
		return nil, ErrPermissionCodeAlreadyExists
	}

	err = r.db.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM permissions
			WHERE module_name = $1
			AND action_name = $2
		)
		`,
		req.ModuleName,
		req.ActionName,
	).Scan(&exists)
	if err != nil {
		return nil, err
	}

	if exists {
		return nil, ErrPermissionActionAlreadyExists
	}

	var permission CreatePermissionResponse

	err = r.db.QueryRow(
		ctx,
		`
		INSERT INTO permissions
		(
			permission_code,
			permission_name,
			module_name,
			action_name,
			description,
			risk_level,
			requires_approval,
			status
		)
		VALUES
		(
			$1,$2,$3,$4,$5,$6,$7,$8
		)
		RETURNING
			id,
			permission_code,
			permission_name,
			module_name,
			action_name,
			description,
			risk_level,
			requires_approval,
			status
		`,
		req.PermissionCode,
		req.PermissionName,
		req.ModuleName,
		req.ActionName,
		req.Description,
		req.RiskLevel,
		req.IsSystem,
		req.Status,
	).Scan(
		&permission.ID,
		&permission.PermissionCode,
		&permission.PermissionName,
		&permission.ModuleName,
		&permission.ActionName,
		&permission.Description,
		&permission.RiskLevel,
		&permission.IsSystem,
		&permission.Status,
	)
	if err != nil {
		return nil, err
	}

	return &permission, nil
}
func (r *Repository) ListPermissions(
	ctx context.Context,
	req ListPermissionsRequest,
) (*ListPermissionsResponse, error) {

	var total int

	countQuery := `
		SELECT COUNT(*)
		FROM permissions
		
	`

	var args []interface{}
	argIndex := 1

	if req.Search != "" {
		countQuery += `
			AND (
				LOWER(permission_name) LIKE LOWER($` + strconv.Itoa(argIndex) + `)
				OR LOWER(permission_code) LIKE LOWER($` + strconv.Itoa(argIndex) + `)
			)
		`
		args = append(args, "%"+req.Search+"%")
		argIndex++
	}

	if req.Module != "" {
		countQuery += `
			AND module_name = $` + strconv.Itoa(argIndex)
		args = append(args, req.Module)
		argIndex++
	}

	if req.Status != "" {
		countQuery += `
			AND status = $` + strconv.Itoa(argIndex)
		args = append(args, req.Status)
		argIndex++
	}

	err := r.db.QueryRow(
		ctx,
		countQuery,
		args...,
	).Scan(&total)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT
			id,
			permission_code,
			permission_name,
			module_name,
			action_name,
			risk_level,
			requires_approval,
			status
		FROM permissions
		
	`

	args = []interface{}{}
	argIndex = 1

	if req.Search != "" {
		query += `
			AND (
				LOWER(permission_name) LIKE LOWER($` + strconv.Itoa(argIndex) + `)
				OR LOWER(permission_code) LIKE LOWER($` + strconv.Itoa(argIndex) + `)
			)
		`
		args = append(args, "%"+req.Search+"%")
		argIndex++
	}

	if req.Module != "" {
		query += `
			AND module_name = $` + strconv.Itoa(argIndex)
		args = append(args, req.Module)
		argIndex++
	}

	if req.Status != "" {
		query += `
			AND status = $` + strconv.Itoa(argIndex)
		args = append(args, req.Status)
		argIndex++
	}

	query += `
		ORDER BY module_name, permission_name
		LIMIT $` + strconv.Itoa(argIndex) + `
		OFFSET $` + strconv.Itoa(argIndex+1)

	args = append(
		args,
		req.PageSize,
		(req.Page-1)*req.PageSize,
	)

	rows, err := r.db.Query(
		ctx,
		query,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []PermissionListItem

	for rows.Next() {
		var permission PermissionListItem

		err := rows.Scan(
			&permission.ID,
			&permission.PermissionCode,
			&permission.PermissionName,
			&permission.ModuleName,
			&permission.ActionName,
			&permission.RiskLevel,
			&permission.IsSystem,
			&permission.Status,
		)
		if err != nil {
			return nil, err
		}

		permissions = append(
			permissions,
			permission,
		)
	}

	return &ListPermissionsResponse{
		Permissions: permissions,
		Total:       total,
		Page:        req.Page,
		PageSize:    req.PageSize,
	}, nil
}

func (r *Repository) GetPermissionByID(
	ctx context.Context,
	permissionID uuid.UUID,
) (*GetPermissionResponse, error) {

	var permission GetPermissionResponse

	err := r.db.QueryRow(
		ctx,
		`
		SELECT
			id,
			permission_code,
			permission_name,
			module_name,
			action_name,
			description,
			risk_level,
			requires_approval,
			status
		FROM permissions
		WHERE id = $1
		
		`,
		permissionID,
	).Scan(
		&permission.ID,
		&permission.PermissionCode,
		&permission.PermissionName,
		&permission.ModuleName,
		&permission.ActionName,
		&permission.Description,
		&permission.RiskLevel,
		&permission.RequiresApproval,
		&permission.Status,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPermissionNotFound
		}

		return nil, err
	}

	return &permission, nil
}

func (r *Repository) UpdatePermission(
	ctx context.Context,
	permissionID uuid.UUID,
	req UpdatePermissionRequest,
) (*GetPermissionResponse, error) {

	var exists bool

	err := r.db.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM permissions
			WHERE id = $1
		)
		`,
		permissionID,
	).Scan(&exists)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, ErrPermissionNotFound
	}

	_, err = r.db.Exec(
		ctx,
		`
		UPDATE permissions
		SET
			permission_name = COALESCE($1, permission_name),
			module_name = COALESCE($2, module_name),
			action_name = COALESCE($3, action_name),
			description = COALESCE($4, description),
			risk_level = COALESCE($5, risk_level),
			status = COALESCE($6, status),
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $7
		`,
		req.PermissionName,
		req.ModuleName,
		req.ActionName,
		req.Description,
		req.RiskLevel,
		req.Status,
		permissionID,
	)
	if err != nil {
		return nil, err
	}

	return r.GetPermissionByID(
		ctx,
		permissionID,
	)
}

func (r *Repository) DeletePermission(
	ctx context.Context,
	permissionID uuid.UUID,
) error {

	commandTag, err := r.db.Exec(
		ctx,
		`
		UPDATE permissions
		SET
			status = 'INACTIVE',
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
		AND status <> 'INACTIVE'
		`,
		permissionID,
	)
	if err != nil {
		return err
	}

	if commandTag.RowsAffected() == 0 {
		var exists bool

		err = r.db.QueryRow(
			ctx,
			`
			SELECT EXISTS(
				SELECT 1
				FROM permissions
				WHERE id = $1
			)
			`,
			permissionID,
		).Scan(&exists)
		if err != nil {
			return err
		}

		if !exists {
			return ErrPermissionNotFound
		}

		return errors.New("permission is already inactive")
	}

	return nil
}
