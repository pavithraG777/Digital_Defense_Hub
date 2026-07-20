package user

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/auditlog"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/auth"
)

var (
	ErrInvalidUserType = errors.New("invalid user type")
)

type Service struct {
	repository *Repository
	audit      *auditlog.Service
}

func NewService(
	repository *Repository,
	audit *auditlog.Service,
) *Service {
	return &Service{
		repository: repository,
		audit:      audit,
	}
}

func (s *Service) CreateUser(
	ctx context.Context,
	organizationID uuid.UUID,
	assignedBy uuid.UUID,
	request CreateUserRequest,
) (*CreateUserResponse, error) {
	request.Username = strings.TrimSpace(
		request.Username,
	)

	request.OfficialEmail = strings.ToLower(
		strings.TrimSpace(
			request.OfficialEmail,
		),
	)

	request.FirstName = strings.TrimSpace(
		request.FirstName,
	)

	request.UserType = strings.ToUpper(
		strings.TrimSpace(
			request.UserType,
		),
	)

	if !isValidUserType(request.UserType) {
		return nil, ErrInvalidUserType
	}

	passwordHash, err := auth.HashPassword(
		request.Password,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to hash user password: %w",
			err,
		)
	}

	response, err := s.repository.CreateUser(
		ctx,
		organizationID,
		assignedBy,
		request,
		passwordHash,
	)
	if err != nil {
		s.audit.LogFailure(
			ctx,
			auditlog.LogRequest{
				OrganizationID: &organizationID,
				UserID:         &assignedBy,

				ModuleName: "USER",
				ActionName: "CREATE",

				EntityType: "USER",

				Description: "User creation failed",

				OldValues: map[string]any{},
				NewValues: map[string]any{
					"username":       request.Username,
					"official_email": request.OfficialEmail,
					"user_type":      request.UserType,
					"first_name":     request.FirstName,
					"role_id":        request.RoleID,
					"employee_code":  request.EmployeeCode,
				},

				Metadata: map[string]any{
					"assigned_by": assignedBy,
				},

				RiskLevel: auditlog.RiskLevelMedium,

				FailureReason: err.Error(),
			},
		)

		return nil, err
	}

	entityID := response.ID

	s.audit.LogSuccess(
		ctx,
		auditlog.LogRequest{
			OrganizationID: &organizationID,
			UserID:         &assignedBy,

			ModuleName: "USER",
			ActionName: "CREATE",

			EntityType: "USER",
			EntityID:   &entityID,

			Description: "User created successfully",

			OldValues: map[string]any{},
			NewValues: map[string]any{
				"id":              response.ID,
				"organization_id": response.OrganizationID,
				"username":        response.Username,
				"official_email":  response.OfficialEmail,
				"display_name":    response.DisplayName,
				"account_status":  response.AccountStatus,
				"role_id":         response.RoleID,
				"user_type":       request.UserType,
			},

			Metadata: map[string]any{
				"assigned_by": assignedBy,
			},

			RiskLevel: auditlog.RiskLevelMedium,
		},
	)

	return response, nil
}

func isValidUserType(
	userType string,
) bool {
	switch userType {
	case "INTERNAL",
		"EXTERNAL",
		"SERVICE_ACCOUNT":
		return true

	default:
		return false
	}
}

func (s *Service) ListUsers(
	ctx context.Context,
	organizationID uuid.UUID,
	req ListUsersRequest,
) (*ListUsersResponse, error) {
	req.Search = strings.TrimSpace(
		req.Search,
	)

	req.AccountStatus = strings.ToUpper(
		strings.TrimSpace(
			req.AccountStatus,
		),
	)

	req.UserType = strings.ToUpper(
		strings.TrimSpace(
			req.UserType,
		),
	)

	return s.repository.ListUsers(
		ctx,
		organizationID,
		req,
	)
}

func (s *Service) GetUserByID(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
) (*GetUserResponse, error) {
	return s.repository.GetUserByID(
		ctx,
		organizationID,
		userID,
	)
}

func (s *Service) UpdateUser(
	ctx context.Context,
	organizationID uuid.UUID,
	updatedBy uuid.UUID,
	userID uuid.UUID,
	req UpdateUserRequest,
) (*GetUserResponse, error) {
	if req.OfficialEmail != nil {
		email := strings.ToLower(
			strings.TrimSpace(
				*req.OfficialEmail,
			),
		)

		if email == "" {
			return nil, errors.New(
				"official email cannot be empty",
			)
		}

		req.OfficialEmail = &email
	}

	if req.EmployeeCode != nil {
		value := strings.TrimSpace(
			*req.EmployeeCode,
		)

		req.EmployeeCode = &value
	}

	if req.FirstName != nil {
		value := strings.TrimSpace(
			*req.FirstName,
		)

		if value == "" {
			return nil, errors.New(
				"first name cannot be empty",
			)
		}

		req.FirstName = &value
	}

	if req.MiddleName != nil {
		value := strings.TrimSpace(
			*req.MiddleName,
		)

		req.MiddleName = &value
	}

	if req.LastName != nil {
		value := strings.TrimSpace(
			*req.LastName,
		)

		req.LastName = &value
	}

	if req.DisplayName != nil {
		value := strings.TrimSpace(
			*req.DisplayName,
		)

		if value == "" {
			return nil, errors.New(
				"display name cannot be empty",
			)
		}

		req.DisplayName = &value
	}

	if req.Designation != nil {
		value := strings.TrimSpace(
			*req.Designation,
		)

		req.Designation = &value
	}

	if req.OfficialPhone != nil {
		value := strings.TrimSpace(
			*req.OfficialPhone,
		)

		req.OfficialPhone = &value
	}

	if req.OfficialEmail == nil &&
		req.EmployeeCode == nil &&
		req.FirstName == nil &&
		req.MiddleName == nil &&
		req.LastName == nil &&
		req.DisplayName == nil &&
		req.Designation == nil &&
		req.OfficialPhone == nil {
		return nil, errors.New(
			"at least one field is required for update",
		)
	}

	return s.repository.UpdateUser(
		ctx,
		organizationID,
		userID,
		req,
	)
}
