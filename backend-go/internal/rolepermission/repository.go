package rolepermission

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrRoleNotFound       = errors.New("role not found")
	ErrPermissionNotFound = errors.New("permission not found")
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		db: db,
	}
}

func (r *Repository) AssignPermissions(
	ctx context.Context,
	roleID uuid.UUID,
	grantedBy *uuid.UUID,
	req AssignPermissionsRequest,
) (*AssignPermissionsResponse, error) {

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var roleExists bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM roles
			WHERE id = $1
			AND deleted_at IS NULL
		)
		`,
		roleID,
	).Scan(&roleExists)
	if err != nil {
		return nil, err
	}

	if !roleExists {
		return nil, ErrRoleNotFound
	}

	response := &AssignPermissionsResponse{
		RoleID:              roleID,
		AssignedPermissions: []AssignedPermissionItem{},
	}

	for _, permissionID := range req.PermissionIDs {
		var permissionExists bool

		err = tx.QueryRow(
			ctx,
			`
			SELECT EXISTS(
				SELECT 1
				FROM permissions
				WHERE id = $1
				AND status = 'ACTIVE'
			)
			`,
			permissionID,
		).Scan(&permissionExists)
		if err != nil {
			return nil, err
		}

		if !permissionExists {
			return nil, ErrPermissionNotFound
		}

		var existingID uuid.UUID
		var existingActive bool

		err = tx.QueryRow(
			ctx,
			`
			SELECT id, is_active
			FROM role_permissions
			WHERE role_id = $1
			AND permission_id = $2
			`,
			roleID,
			permissionID,
		).Scan(
			&existingID,
			&existingActive,
		)

		if err == nil {
			if existingActive {
				response.SkippedCount++
				continue
			}

			var item AssignedPermissionItem

			err = tx.QueryRow(
				ctx,
				`
				UPDATE role_permissions
				SET
					granted_by = $1,
					granted_at = CURRENT_TIMESTAMP,
					expires_at = $2,
					is_active = TRUE
				WHERE id = $3
				RETURNING
					id,
					role_id,
					permission_id,
					granted_by,
					granted_at,
					expires_at,
					is_active
				`,
				grantedBy,
				req.ExpiresAt,
				existingID,
			).Scan(
				&item.ID,
				&item.RoleID,
				&item.PermissionID,
				&item.GrantedBy,
				&item.GrantedAt,
				&item.ExpiresAt,
				&item.IsActive,
			)
			if err != nil {
				return nil, err
			}

			response.AssignedPermissions = append(
				response.AssignedPermissions,
				item,
			)
			response.AssignedCount++

			continue
		}

		var item AssignedPermissionItem

		err = tx.QueryRow(
			ctx,
			`
			INSERT INTO role_permissions
			(
				role_id,
				permission_id,
				granted_by,
				granted_at,
				expires_at,
				is_active
			)
			VALUES
			(
				$1,
				$2,
				$3,
				CURRENT_TIMESTAMP,
				$4,
				TRUE
			)
			RETURNING
				id,
				role_id,
				permission_id,
				granted_by,
				granted_at,
				expires_at,
				is_active
			`,
			roleID,
			permissionID,
			grantedBy,
			req.ExpiresAt,
		).Scan(
			&item.ID,
			&item.RoleID,
			&item.PermissionID,
			&item.GrantedBy,
			&item.GrantedAt,
			&item.ExpiresAt,
			&item.IsActive,
		)
		if err != nil {
			return nil, err
		}

		response.AssignedPermissions = append(
			response.AssignedPermissions,
			item,
		)
		response.AssignedCount++
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return response, nil
}

func (r *Repository) ListRolePermissions(
	ctx context.Context,
	roleID uuid.UUID,
) (*ListRolePermissionsResponse, error) {

	var roleExists bool

	err := r.db.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM roles
			WHERE id = $1
			AND deleted_at IS NULL
		)
		`,
		roleID,
	).Scan(&roleExists)
	if err != nil {
		return nil, err
	}

	if !roleExists {
		return nil, ErrRoleNotFound
	}

	rows, err := r.db.Query(
		ctx,
		`
		SELECT
			rp.id,
			p.id,
			p.permission_code,
			p.permission_name,
			p.module_name,
			p.action_name,
			p.description,
			p.risk_level,
			rp.granted_by,
			rp.granted_at,
			rp.expires_at,
			rp.is_active
		FROM role_permissions rp
		INNER JOIN permissions p
			ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		AND rp.is_active = TRUE
		AND p.status = 'ACTIVE'
		AND (
			rp.expires_at IS NULL
			OR rp.expires_at > CURRENT_TIMESTAMP
		)
		ORDER BY
			p.module_name,
			p.permission_name
		`,
		roleID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	permissions := make([]RolePermissionListItem, 0)

	for rows.Next() {
		var permission RolePermissionListItem

		err := rows.Scan(
			&permission.MappingID,
			&permission.PermissionID,
			&permission.PermissionCode,
			&permission.PermissionName,
			&permission.ModuleName,
			&permission.ActionName,
			&permission.Description,
			&permission.RiskLevel,
			&permission.GrantedBy,
			&permission.GrantedAt,
			&permission.ExpiresAt,
			&permission.IsActive,
		)
		if err != nil {
			return nil, err
		}

		permissions = append(
			permissions,
			permission,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &ListRolePermissionsResponse{
		RoleID:      roleID,
		Permissions: permissions,
		Total:       len(permissions),
	}, nil
}

func (r *Repository) RemovePermission(
	ctx context.Context,
	roleID uuid.UUID,
	permissionID uuid.UUID,
) error {

	query := `
		UPDATE role_permissions
		SET
			is_active = FALSE
		WHERE
			role_id = $1
			AND permission_id = $2
			AND is_active = TRUE
	`

	result, err := r.db.Exec(
		ctx,
		query,
		roleID,
		permissionID,
	)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return errors.New("role permission not found")
	}

	return nil
}

func (r *Repository) ReplacePermissions(
	ctx context.Context,
	roleID uuid.UUID,
	grantedBy *uuid.UUID,
	req ReplacePermissionsRequest,
) (*AssignPermissionsResponse, error) {

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var roleExists bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM roles
			WHERE id = $1
			AND deleted_at IS NULL
		)
		`,
		roleID,
	).Scan(&roleExists)
	if err != nil {
		return nil, err
	}

	if !roleExists {
		return nil, ErrRoleNotFound
	}

	for _, permissionID := range req.PermissionIDs {
		var permissionExists bool

		err = tx.QueryRow(
			ctx,
			`
			SELECT EXISTS(
				SELECT 1
				FROM permissions
				WHERE id = $1
				AND status = 'ACTIVE'
			)
			`,
			permissionID,
		).Scan(&permissionExists)
		if err != nil {
			return nil, err
		}

		if !permissionExists {
			return nil, ErrPermissionNotFound
		}
	}

	_, err = tx.Exec(
		ctx,
		`
		UPDATE role_permissions
		SET
			is_active = FALSE
		WHERE role_id = $1
		AND is_active = TRUE
		`,
		roleID,
	)
	if err != nil {
		return nil, err
	}

	response := &AssignPermissionsResponse{
		RoleID:              roleID,
		AssignedPermissions: []AssignedPermissionItem{},
	}

	for _, permissionID := range req.PermissionIDs {
		var existingID uuid.UUID

		err = tx.QueryRow(
			ctx,
			`
			SELECT id
			FROM role_permissions
			WHERE role_id = $1
			AND permission_id = $2
			`,
			roleID,
			permissionID,
		).Scan(&existingID)

		var item AssignedPermissionItem

		if err == nil {
			err = tx.QueryRow(
				ctx,
				`
				UPDATE role_permissions
				SET
					granted_by = $1,
					granted_at = CURRENT_TIMESTAMP,
					expires_at = $2,
					is_active = TRUE
				WHERE id = $3
				RETURNING
					id,
					role_id,
					permission_id,
					granted_by,
					granted_at,
					expires_at,
					is_active
				`,
				grantedBy,
				req.ExpiresAt,
				existingID,
			).Scan(
				&item.ID,
				&item.RoleID,
				&item.PermissionID,
				&item.GrantedBy,
				&item.GrantedAt,
				&item.ExpiresAt,
				&item.IsActive,
			)
			if err != nil {
				return nil, err
			}
		} else {
			err = tx.QueryRow(
				ctx,
				`
				INSERT INTO role_permissions
				(
					role_id,
					permission_id,
					granted_by,
					granted_at,
					expires_at,
					is_active
				)
				VALUES
				(
					$1,
					$2,
					$3,
					CURRENT_TIMESTAMP,
					$4,
					TRUE
				)
				RETURNING
					id,
					role_id,
					permission_id,
					granted_by,
					granted_at,
					expires_at,
					is_active
				`,
				roleID,
				permissionID,
				grantedBy,
				req.ExpiresAt,
			).Scan(
				&item.ID,
				&item.RoleID,
				&item.PermissionID,
				&item.GrantedBy,
				&item.GrantedAt,
				&item.ExpiresAt,
				&item.IsActive,
			)
			if err != nil {
				return nil, err
			}
		}

		response.AssignedPermissions = append(
			response.AssignedPermissions,
			item,
		)
		response.AssignedCount++
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return response, nil
}
