package user

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/auditlog"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{
		service: service,
	}
}

func (h *Handler) CreateUser(c *gin.Context) {
	var request CreateUserRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	organizationID, ok := getUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	assignedBy, ok := getUUIDFromContext(
		c,
		"user_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"User information is missing",
			nil,
		)
		return
	}

	requestContext := buildAuditRequestContext(c)

	createdUser, err := h.service.CreateUser(
		requestContext,
		organizationID,
		assignedBy,
		request,
	)

	if err != nil {
		switch {
		case errors.Is(err, ErrUsernameAlreadyExists),
			errors.Is(err, ErrEmailAlreadyExists),
			errors.Is(err, ErrInvalidUserType):

			response.BadRequest(
				c,
				err.Error(),
				nil,
			)

		case errors.Is(err, ErrRoleNotFound):
			response.Error(
				c,
				http.StatusNotFound,
				err.Error(),
				nil,
			)

		default:
			response.InternalServerError(
				c,
				"Failed to create user",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusCreated,
		"User created successfully",
		createdUser,
	)
}

func getUUIDFromContext(
	c *gin.Context,
	key string,
) (uuid.UUID, bool) {
	value, exists := c.Get(key)
	if !exists {
		return uuid.Nil, false
	}

	switch typedValue := value.(type) {
	case uuid.UUID:
		if typedValue == uuid.Nil {
			return uuid.Nil, false
		}

		return typedValue, true

	case *uuid.UUID:
		if typedValue == nil || *typedValue == uuid.Nil {
			return uuid.Nil, false
		}

		return *typedValue, true

	case string:
		parsedValue, err := uuid.Parse(
			strings.TrimSpace(typedValue),
		)
		if err != nil {
			return uuid.Nil, false
		}

		return parsedValue, true

	default:
		return uuid.Nil, false
	}
}

func buildAuditRequestContext(
	c *gin.Context,
) context.Context {
	deviceName := strings.TrimSpace(
		c.GetHeader("X-Device-Name"),
	)

	userAgent := strings.TrimSpace(
		c.Request.UserAgent(),
	)

	if deviceName == "" {
		deviceName = detectDeviceName(userAgent)
	}

	var sessionID *uuid.UUID

	if tokenID, ok := getUUIDFromContext(
		c,
		"token_id",
	); ok {
		sessionID = &tokenID
	} else if value, ok := getUUIDFromContext(
		c,
		"session_id",
	); ok {
		sessionID = &value
	} else if value, ok := getUUIDFromContext(
		c,
		"jti",
	); ok {
		sessionID = &value
	}

	return auditlog.WithRequestDetails(
		c.Request.Context(),
		strings.TrimSpace(c.ClientIP()),
		deviceName,
		userAgent,
		sessionID,
	)
}

func detectDeviceName(
	userAgent string,
) string {
	normalizedUserAgent := strings.ToLower(
		strings.TrimSpace(userAgent),
	)

	switch {
	case strings.Contains(
		normalizedUserAgent,
		"postmanruntime",
	):
		return "Postman"

	case strings.Contains(
		normalizedUserAgent,
		"insomnia",
	):
		return "Insomnia"

	case strings.Contains(
		normalizedUserAgent,
		"android",
	):
		return "Android Device"

	case strings.Contains(
		normalizedUserAgent,
		"iphone",
	):
		return "iPhone"

	case strings.Contains(
		normalizedUserAgent,
		"ipad",
	):
		return "iPad"

	case strings.Contains(
		normalizedUserAgent,
		"windows",
	):
		return "Windows Device"

	case strings.Contains(
		normalizedUserAgent,
		"macintosh",
	):
		return "Mac Device"

	case strings.Contains(
		normalizedUserAgent,
		"linux",
	):
		return "Linux Device"

	default:
		return "Unknown Device"
	}
}

func (h *Handler) ListUsers(c *gin.Context) {
	var req ListUsersRequest

	if err := c.ShouldBindQuery(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid query parameters",
			err.Error(),
		)
		return
	}

	organizationID, ok := getUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	users, err := h.service.ListUsers(
		c.Request.Context(),
		organizationID,
		req,
	)
	if err != nil {
		response.InternalServerError(
			c,
			"Failed to retrieve users",
			err.Error(),
		)
		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Users retrieved successfully",
		users,
	)
}

func (h *Handler) GetUserByID(c *gin.Context) {
	organizationID, ok := getUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid user ID",
			err.Error(),
		)
		return
	}

	userDetails, err := h.service.GetUserByID(
		c.Request.Context(),
		organizationID,
		userID,
	)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			response.NotFound(
				c,
				"User not found",
				nil,
			)
			return
		}

		response.InternalServerError(
			c,
			"Failed to retrieve user",
			err.Error(),
		)
		return
	}

	response.Success(
		c,
		http.StatusOK,
		"User retrieved successfully",
		userDetails,
	)
}

func (s *Service) logUserUpdateFailure(
	ctx context.Context,
	organizationID uuid.UUID,
	updatedBy uuid.UUID,
	userID uuid.UUID,
	req UpdateUserRequest,
	updateErr error,
) {
	entityID := userID

	s.audit.LogFailure(
		ctx,
		auditlog.LogRequest{
			OrganizationID: &organizationID,
			UserID:         &updatedBy,

			ModuleName: "USER",
			ActionName: "UPDATE",

			EntityType: "USER",
			EntityID:   &entityID,

			Description: "User update failed",

			NewValues: map[string]any{
				"official_email": req.OfficialEmail,
				"employee_code":  req.EmployeeCode,
				"first_name":     req.FirstName,
				"middle_name":    req.MiddleName,
				"last_name":      req.LastName,
				"display_name":   req.DisplayName,
				"designation":    req.Designation,
				"official_phone": req.OfficialPhone,
			},

			Metadata: map[string]any{
				"updated_by":      updatedBy,
				"updated_user_id": userID,
			},

			RiskLevel: auditlog.RiskLevelMedium,

			FailureReason: updateErr.Error(),
		},
	)
}

func userResponseToAuditValues(
	user *GetUserResponse,
) map[string]any {
	if user == nil {
		return map[string]any{}
	}

	return map[string]any{
		"id":              user.ID,
		"organization_id": user.OrganizationID,
		"username":        user.Username,
		"official_email":  user.OfficialEmail,
		"user_type":       user.UserType,
		"account_status":  user.AccountStatus,
		"employee_code":   user.EmployeeCode,
		"first_name":      user.FirstName,
		"middle_name":     user.MiddleName,
		"last_name":       user.LastName,
		"display_name":    user.DisplayName,
		"designation":     user.Designation,
		"official_phone":  user.OfficialPhone,
		"role_id":         user.RoleID,
		"role_code":       user.RoleCode,
		"role_name":       user.RoleName,
	}
}

func (h *Handler) UpdateUser(c *gin.Context) {
	organizationID, ok := getUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	updatedBy, ok := getUUIDFromContext(
		c,
		"user_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"User information is missing",
			nil,
		)
		return
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid user ID",
			err.Error(),
		)
		return
	}

	var req UpdateUserRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	requestContext := buildAuditRequestContext(c)

	updatedUser, err := h.service.UpdateUser(
		requestContext,
		organizationID,
		updatedBy,
		userID,
		req,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			response.NotFound(
				c,
				"User not found",
				nil,
			)

		case errors.Is(err, ErrEmailAlreadyExists):
			response.BadRequest(
				c,
				"Official email already exists",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to update user",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusOK,
		"User updated successfully",
		updatedUser,
	)
}

func (h *Handler) ChangeAccountStatus(c *gin.Context) {
	organizationID, ok := getUUIDFromContext(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Organization information is missing", nil)
		return
	}
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "Invalid user ID", nil)
		return
	}
	var req ChangeAccountStatusRequest
	if err = c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid status request", err.Error())
		return
	}
	updated, err := h.service.ChangeAccountStatus(c.Request.Context(), organizationID, userID, req.Status)
	if errors.Is(err, ErrUserNotFound) {
		response.NotFound(c, "User not found", nil)
		return
	}
	if err != nil {
		response.BadRequest(c, "Unable to change account status", err.Error())
		return
	}
	response.Success(c, http.StatusOK, "User account status updated", updated)
}
