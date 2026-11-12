package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUsernameAlreadyExists = errors.New("username already exists")
	ErrEmailAlreadyExists    = errors.New("official email already exists")
	ErrRoleNotFound          = errors.New("role not found")
	ErrUserNotFound          = errors.New("user not found")
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{
		pool: pool,
	}
}

func (r *Repository) CreateUser(
	ctx context.Context,
	organizationID uuid.UUID,
	assignedBy uuid.UUID,
	request CreateUserRequest,
	passwordHash string,
) (*CreateUserResponse, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to begin transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Validate the selected role.
	if err := r.validateRole(
		ctx,
		tx,
		request.RoleID,
		organizationID,
	); err != nil {
		return nil, err
	}

	// Check whether the username already exists.
	var usernameExists bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE LOWER(username) = LOWER($1)
			  AND deleted_at IS NULL
		)
		`,
		request.Username,
	).Scan(&usernameExists)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to check username availability: %w",
			err,
		)
	}

	if usernameExists {
		return nil, ErrUsernameAlreadyExists
	}

	// Check whether the official email already exists.
	var emailExists bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE LOWER(official_email) = LOWER($1)
			  AND deleted_at IS NULL
		)
		`,
		request.OfficialEmail,
	).Scan(&emailExists)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to check email availability: %w",
			err,
		)
	}

	if emailExists {
		return nil, ErrEmailAlreadyExists
	}

	userID := uuid.New()

	// Step 1: Create the user account first.
	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO users (
			id,
			organization_id,
			username,
			official_email,
			password_hash,
			user_type,
			account_status,
			email_verified,
			must_change_password
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			'ACTIVE',
			TRUE,
			TRUE
		)
		`,
		userID,
		organizationID,
		request.Username,
		request.OfficialEmail,
		passwordHash,
		request.UserType,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to create user: %w",
			err,
		)
	}

	// Prepare the display name.
	displayName := request.FirstName

	if request.DisplayName != nil &&
		*request.DisplayName != "" {
		displayName = *request.DisplayName
	} else if request.LastName != nil &&
		*request.LastName != "" {
		displayName = request.FirstName + " " + *request.LastName
	}

	// Step 2: Create the user profile.
	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO user_profiles (
			user_id,
			employee_code,
			first_name,
			middle_name,
			last_name,
			display_name,
			designation,
			official_phone
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			$8
		)
		`,
		userID,
		request.EmployeeCode,
		request.FirstName,
		request.MiddleName,
		request.LastName,
		displayName,
		request.Designation,
		request.OfficialPhone,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to create user profile: %w",
			err,
		)
	}

	// Step 3: Assign the selected role to the created user.
	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO user_roles (
			user_id,
			role_id,
			granted_by,
			assignment_reason,
			granted_at,
			valid_from,
			expires_at,
			is_primary,
			status,
			is_active
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			CURRENT_TIMESTAMP,
			CURRENT_TIMESTAMP,
			NULL,
			TRUE,
			'ACTIVE',
			TRUE
		)
		`,
		userID,
		request.RoleID,
		assignedBy,
		"Assigned during user creation",
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to assign role to user: %w",
			err,
		)
	}

	// Save all database operations.
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"failed to commit user transaction: %w",
			err,
		)
	}

	return &CreateUserResponse{
		ID:             userID,
		OrganizationID: organizationID,
		Username:       request.Username,
		OfficialEmail:  request.OfficialEmail,
		DisplayName:    displayName,
		AccountStatus:  "ACTIVE",
		RoleID:         request.RoleID,
	}, nil
}
func (r *Repository) validateRole(
	ctx context.Context,
	tx pgx.Tx,
	roleID uuid.UUID,
	organizationID uuid.UUID,
) error {
	var exists bool

	err := tx.QueryRow(
		ctx,
		`
		SELECT EXISTS (
			SELECT 1
			FROM roles
			WHERE id = $1
			  AND organization_id = $2
			  AND status = 'ACTIVE'
			  AND deleted_at IS NULL
		)
		`,
		roleID,
		organizationID,
	).Scan(&exists)

	if err != nil {
		return fmt.Errorf(
			"failed to validate role: %w",
			err,
		)
	}

	if !exists {
		return ErrRoleNotFound
	}

	return nil
}

func (r *Repository) ListUsers(
	ctx context.Context,
	organizationID uuid.UUID,
	includePlatformCreated bool,
	req ListUsersRequest,
) (*ListUsersResponse, error) {
	if req.Page <= 0 {
		req.Page = 1
	}

	if req.Limit <= 0 {
		req.Limit = 10
	}

	if req.Limit > 100 {
		req.Limit = 100
	}

	offset := (req.Page - 1) * req.Limit

	sortColumn := "u.created_at"

	switch req.SortBy {
	case "username":
		sortColumn = "u.username"

	case "official_email":
		sortColumn = "u.official_email"

	case "display_name":
		sortColumn = "up.display_name"

	case "created_at":
		sortColumn = "u.created_at"
	}

	sortOrder := "DESC"

	if req.SortOrder == "ASC" ||
		req.SortOrder == "asc" {
		sortOrder = "ASC"
	}

	query := `
		SELECT
			u.id,
			u.username,
			u.official_email,
			COALESCE(up.display_name, up.first_name),
			up.designation,
			u.account_status,
			u.user_type,
			COALESCE(r.role_name, ''),
			u.created_at
		FROM users u
		JOIN user_profiles up
			ON up.user_id = u.id
		LEFT JOIN user_roles ur
			ON ur.user_id = u.id
			AND ur.status = 'ACTIVE'
			AND ur.is_primary = TRUE
		LEFT JOIN roles r
			ON r.id = ur.role_id
			AND r.deleted_at IS NULL
		WHERE ($2::boolean OR u.organization_id = $1)
		  AND u.deleted_at IS NULL
		  AND ($2::boolean OR NOT EXISTS (
			SELECT 1
			FROM user_roles created_assignment
			JOIN user_roles grantor_assignment
			  ON grantor_assignment.user_id = created_assignment.granted_by
			  AND grantor_assignment.is_active = TRUE
			  AND UPPER(grantor_assignment.status) = 'ACTIVE'
			JOIN roles grantor_role
			  ON grantor_role.id = grantor_assignment.role_id
			  AND grantor_role.deleted_at IS NULL
			WHERE created_assignment.user_id = u.id
			  AND UPPER(grantor_role.role_code) = 'SUPER_ADMIN'
		  ))
	`

	countQuery := `
		SELECT COUNT(*)
		FROM users u
		JOIN user_profiles up
			ON up.user_id = u.id
		WHERE ($2::boolean OR u.organization_id = $1)
		  AND u.deleted_at IS NULL
		  AND ($2::boolean OR NOT EXISTS (
			SELECT 1
			FROM user_roles created_assignment
			JOIN user_roles grantor_assignment
			  ON grantor_assignment.user_id = created_assignment.granted_by
			  AND grantor_assignment.is_active = TRUE
			  AND UPPER(grantor_assignment.status) = 'ACTIVE'
			JOIN roles grantor_role
			  ON grantor_role.id = grantor_assignment.role_id
			  AND grantor_role.deleted_at IS NULL
			WHERE created_assignment.user_id = u.id
			  AND UPPER(grantor_role.role_code) = 'SUPER_ADMIN'
		  ))
	`

	args := []interface{}{
		organizationID,
		includePlatformCreated,
	}

	countArgs := []interface{}{
		organizationID,
		includePlatformCreated,
	}

	argPosition := 3

	if req.Search != "" {
		searchCondition := fmt.Sprintf(
			`
			AND (
				LOWER(u.username) LIKE LOWER($%d)
				OR LOWER(u.official_email) LIKE LOWER($%d)
				OR LOWER(up.first_name) LIKE LOWER($%d)
				OR LOWER(COALESCE(up.display_name, '')) LIKE LOWER($%d)
			)
			`,
			argPosition,
			argPosition,
			argPosition,
			argPosition,
		)

		query += searchCondition
		countQuery += searchCondition

		searchValue := "%" + req.Search + "%"

		args = append(
			args,
			searchValue,
		)

		countArgs = append(
			countArgs,
			searchValue,
		)

		argPosition++
	}

	if req.AccountStatus != "" {
		condition := fmt.Sprintf(
			" AND u.account_status = $%d",
			argPosition,
		)

		query += condition
		countQuery += condition

		args = append(
			args,
			req.AccountStatus,
		)

		countArgs = append(
			countArgs,
			req.AccountStatus,
		)

		argPosition++
	}

	if req.UserType != "" {
		condition := fmt.Sprintf(
			" AND u.user_type = $%d",
			argPosition,
		)

		query += condition
		countQuery += condition

		args = append(
			args,
			req.UserType,
		)

		countArgs = append(
			countArgs,
			req.UserType,
		)
	}

	query += fmt.Sprintf(
		" ORDER BY %s %s LIMIT %d OFFSET %d",
		sortColumn,
		sortOrder,
		req.Limit,
		offset,
	)

	rows, err := r.pool.Query(
		ctx,
		query,
		args...,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to retrieve users: %w",
			err,
		)
	}

	defer rows.Close()

	users := make([]UserListItem, 0)

	for rows.Next() {
		var item UserListItem

		if err := rows.Scan(
			&item.ID,
			&item.Username,
			&item.OfficialEmail,
			&item.DisplayName,
			&item.Designation,
			&item.AccountStatus,
			&item.UserType,
			&item.Role,
			&item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf(
				"failed to scan user row: %w",
				err,
			)
		}

		users = append(
			users,
			item,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"failed while reading user rows: %w",
			err,
		)
	}

	var total int

	if err := r.pool.QueryRow(
		ctx,
		countQuery,
		countArgs...,
	).Scan(&total); err != nil {
		return nil, fmt.Errorf(
			"failed to count users: %w",
			err,
		)
	}

	totalPages := 0

	if total > 0 {
		totalPages =
			(total + req.Limit - 1) / req.Limit
	}

	return &ListUsersResponse{
		Users:      users,
		Total:      total,
		Page:       req.Page,
		Limit:      req.Limit,
		TotalPages: totalPages,
	}, nil
}

func (r *Repository) GetUserByID(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
) (*GetUserResponse, error) {
	query := `
		SELECT
			u.id,
			u.organization_id,
			u.username,
			u.official_email,
			u.user_type,
			u.account_status,
			up.employee_code,
			up.first_name,
			up.middle_name,
			up.last_name,
			up.display_name,
			up.designation,
			up.official_phone,
			r.id,
			r.role_code,
			r.role_name,
			u.created_at,
			u.updated_at
		FROM users u
		JOIN user_profiles up
			ON up.user_id = u.id
		LEFT JOIN user_roles ur
			ON ur.user_id = u.id
			AND ur.status = 'ACTIVE'
			AND ur.is_primary = TRUE
		LEFT JOIN roles r
			ON r.id = ur.role_id
			AND r.deleted_at IS NULL
		WHERE u.id = $1
		  AND u.organization_id = $2
		  AND u.deleted_at IS NULL
	`

	var user GetUserResponse

	err := r.pool.QueryRow(
		ctx,
		query,
		userID,
		organizationID,
	).Scan(
		&user.ID,
		&user.OrganizationID,
		&user.Username,
		&user.OfficialEmail,
		&user.UserType,
		&user.AccountStatus,
		&user.EmployeeCode,
		&user.FirstName,
		&user.MiddleName,
		&user.LastName,
		&user.DisplayName,
		&user.Designation,
		&user.OfficialPhone,
		&user.RoleID,
		&user.RoleCode,
		&user.RoleName,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"failed to retrieve user: %w",
			err,
		)
	}

	return &user, nil
}

func (r *Repository) UpdateUser(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
	req UpdateUserRequest,
) (*GetUserResponse, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to begin update user transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	var userExists bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE id = $1
			  AND organization_id = $2
			  AND deleted_at IS NULL
		)
		`,
		userID,
		organizationID,
	).Scan(&userExists)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to check user existence: %w",
			err,
		)
	}

	if !userExists {
		return nil, ErrUserNotFound
	}

	if req.OfficialEmail != nil {
		var emailExists bool

		err = tx.QueryRow(
			ctx,
			`
			SELECT EXISTS (
				SELECT 1
				FROM users
				WHERE LOWER(official_email) = LOWER($1)
				  AND id <> $2
				  AND deleted_at IS NULL
			)
			`,
			*req.OfficialEmail,
			userID,
		).Scan(&emailExists)

		if err != nil {
			return nil, fmt.Errorf(
				"failed to check email availability: %w",
				err,
			)
		}

		if emailExists {
			return nil, ErrEmailAlreadyExists
		}
	}

	_, err = tx.Exec(
		ctx,
		`
		UPDATE users
		SET
			official_email = COALESCE(
				$1,
				official_email
			),
			updated_at = NOW()
		WHERE id = $2
		  AND organization_id = $3
		  AND deleted_at IS NULL
		`,
		req.OfficialEmail,
		userID,
		organizationID,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to update user account: %w",
			err,
		)
	}

	commandTag, err := tx.Exec(
		ctx,
		`
		UPDATE user_profiles
		SET
			employee_code = COALESCE(
				$1,
				employee_code
			),
			first_name = COALESCE(
				$2,
				first_name
			),
			middle_name = COALESCE(
				$3,
				middle_name
			),
			last_name = COALESCE(
				$4,
				last_name
			),
			display_name = COALESCE(
				$5,
				display_name
			),
			designation = COALESCE(
				$6,
				designation
			),
			official_phone = COALESCE(
				$7,
				official_phone
			),
			updated_at = NOW()
		WHERE user_id = $8
		`,
		req.EmployeeCode,
		req.FirstName,
		req.MiddleName,
		req.LastName,
		req.DisplayName,
		req.Designation,
		req.OfficialPhone,
		userID,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to update user profile: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return nil, ErrUserNotFound
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"failed to commit update user transaction: %w",
			err,
		)
	}

	return r.GetUserByID(
		ctx,
		organizationID,
		userID,
	)
}

func (r *Repository) ChangeAccountStatus(ctx context.Context, organizationID, userID uuid.UUID, status string) (*GetUserResponse, error) {
	tag, err := r.pool.Exec(ctx, `UPDATE users SET account_status=$1, updated_at=NOW() WHERE id=$2 AND organization_id=$3 AND deleted_at IS NULL`, status, userID, organizationID)
	if err != nil {
		return nil, fmt.Errorf("change user account status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrUserNotFound
	}
	return r.GetUserByID(ctx, organizationID, userID)
}
