package userrole

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrRoleNotFound = errors.New("role not found")
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		db: db,
	}
}

func (r *Repository) AssignRoles(
	ctx context.Context,
	userID uuid.UUID,
	grantedBy *uuid.UUID,
	req AssignRolesRequest,
) (*AssignRolesResponse, error) {

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var userExists bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM users
			WHERE id = $1
			AND deleted_at IS NULL
		)
		`,
		userID,
	).Scan(&userExists)
	if err != nil {
		return nil, err
	}

	if !userExists {
		return nil, ErrUserNotFound
	}

	response := &AssignRolesResponse{
		UserID:        userID,
		AssignedRoles: []AssignedRoleItem{},
	}

	for _, roleID := range req.RoleIDs {
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

		var existingID uuid.UUID
		var existingActive bool

		err = tx.QueryRow(
			ctx,
			`
			SELECT
				id,
				is_active
			FROM user_roles
			WHERE user_id = $1
			AND role_id = $2
			`,
			userID,
			roleID,
		).Scan(
			&existingID,
			&existingActive,
		)

		if err == nil {
			if existingActive {
				response.SkippedCount++
				continue
			}

			var item AssignedRoleItem

			err = tx.QueryRow(
				ctx,
				`
				UPDATE user_roles
				SET
					granted_by = $1,
					granted_at = CURRENT_TIMESTAMP,
					expires_at = $2,
					is_active = TRUE
				WHERE id = $3
				RETURNING
					id,
					user_id,
					role_id,
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
				&item.UserID,
				&item.RoleID,
				&item.GrantedBy,
				&item.GrantedAt,
				&item.ExpiresAt,
				&item.IsActive,
			)
			if err != nil {
				return nil, err
			}

			response.AssignedRoles = append(
				response.AssignedRoles,
				item,
			)
			response.AssignedCount++

			continue
		}

		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}

		var item AssignedRoleItem

		err = tx.QueryRow(
			ctx,
			`
			INSERT INTO user_roles
			(
				user_id,
				role_id,
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
				user_id,
				role_id,
				granted_by,
				granted_at,
				expires_at,
				is_active
			`,
			userID,
			roleID,
			grantedBy,
			req.ExpiresAt,
		).Scan(
			&item.ID,
			&item.UserID,
			&item.RoleID,
			&item.GrantedBy,
			&item.GrantedAt,
			&item.ExpiresAt,
			&item.IsActive,
		)
		if err != nil {
			return nil, err
		}

		response.AssignedRoles = append(
			response.AssignedRoles,
			item,
		)
		response.AssignedCount++
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return response, nil
}

func (r *Repository) ListUserRoles(
	ctx context.Context,
	userID uuid.UUID,
) (*ListUserRolesResponse, error) {

	var userExists bool

	err := r.db.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM users
			WHERE id = $1
			AND deleted_at IS NULL
		)
		`,
		userID,
	).Scan(&userExists)
	if err != nil {
		return nil, err
	}

	if !userExists {
		return nil, ErrUserNotFound
	}

	rows, err := r.db.Query(
		ctx,
		`
		SELECT
			ur.id,
			r.id,
			r.role_code,
			r.role_name,
			r.description,
			ur.granted_by,
			ur.granted_at,
			ur.expires_at,
			ur.is_active
		FROM user_roles ur
		INNER JOIN roles r
			ON r.id = ur.role_id
		WHERE ur.user_id = $1
		AND ur.is_active = TRUE
		AND r.deleted_at IS NULL
		AND (
			ur.expires_at IS NULL
			OR ur.expires_at > CURRENT_TIMESTAMP
		)
		ORDER BY r.role_name
		`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]UserRoleListItem, 0)

	for rows.Next() {
		var role UserRoleListItem

		err := rows.Scan(
			&role.MappingID,
			&role.RoleID,
			&role.RoleCode,
			&role.RoleName,
			&role.Description,
			&role.GrantedBy,
			&role.GrantedAt,
			&role.ExpiresAt,
			&role.IsActive,
		)
		if err != nil {
			return nil, err
		}

		roles = append(
			roles,
			role,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &ListUserRolesResponse{
		UserID: userID,
		Roles:  roles,
		Total:  len(roles),
	}, nil
}

func (r *Repository) RemoveRole(
	ctx context.Context,
	userID uuid.UUID,
	roleID uuid.UUID,
) error {

	result, err := r.db.Exec(
		ctx,
		`
		UPDATE user_roles
		SET
			is_active = FALSE
		WHERE user_id = $1
		AND role_id = $2
		AND is_active = TRUE
		`,
		userID,
		roleID,
	)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return errors.New("user role not found")
	}

	return nil
}

func (r *Repository) ReplaceRoles(
	ctx context.Context,
	userID uuid.UUID,
	grantedBy *uuid.UUID,
	req ReplaceRolesRequest,
) (*AssignRolesResponse, error) {

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var userExists bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM users
			WHERE id = $1
			AND deleted_at IS NULL
		)
		`,
		userID,
	).Scan(&userExists)
	if err != nil {
		return nil, err
	}

	if !userExists {
		return nil, ErrUserNotFound
	}

	for _, roleID := range req.RoleIDs {
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
	}

	_, err = tx.Exec(
		ctx,
		`
		UPDATE user_roles
		SET
			is_active = FALSE
		WHERE user_id = $1
		AND is_active = TRUE
		`,
		userID,
	)
	if err != nil {
		return nil, err
	}

	response := &AssignRolesResponse{
		UserID:        userID,
		AssignedRoles: []AssignedRoleItem{},
	}

	for _, roleID := range req.RoleIDs {
		var existingID uuid.UUID

		err = tx.QueryRow(
			ctx,
			`
			SELECT id
			FROM user_roles
			WHERE user_id = $1
			AND role_id = $2
			`,
			userID,
			roleID,
		).Scan(&existingID)

		var item AssignedRoleItem

		if err == nil {
			err = tx.QueryRow(
				ctx,
				`
				UPDATE user_roles
				SET
					granted_by = $1,
					granted_at = CURRENT_TIMESTAMP,
					expires_at = $2,
					is_active = TRUE
				WHERE id = $3
				RETURNING
					id,
					user_id,
					role_id,
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
				&item.UserID,
				&item.RoleID,
				&item.GrantedBy,
				&item.GrantedAt,
				&item.ExpiresAt,
				&item.IsActive,
			)
			if err != nil {
				return nil, err
			}
		} else {
			if !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}

			err = tx.QueryRow(
				ctx,
				`
				INSERT INTO user_roles
				(
					user_id,
					role_id,
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
					user_id,
					role_id,
					granted_by,
					granted_at,
					expires_at,
					is_active
				`,
				userID,
				roleID,
				grantedBy,
				req.ExpiresAt,
			).Scan(
				&item.ID,
				&item.UserID,
				&item.RoleID,
				&item.GrantedBy,
				&item.GrantedAt,
				&item.ExpiresAt,
				&item.IsActive,
			)
			if err != nil {
				return nil, err
			}
		}

		response.AssignedRoles = append(
			response.AssignedRoles,
			item,
		)
		response.AssignedCount++
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return response, nil
}
