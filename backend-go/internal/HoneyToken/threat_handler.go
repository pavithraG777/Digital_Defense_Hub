package honeytoken

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

// ThreatHandler handles organization-scoped threat API requests.
type ThreatHandler struct {
	service *ThreatService
}

func NewThreatHandler(
	service *ThreatService,
) *ThreatHandler {
	return &ThreatHandler{
		service: service,
	}
}

// ListThreats returns paginated threats belonging to the authenticated
// organization.
func (h *ThreatHandler) ListThreats(c *gin.Context) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Threat handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := threatContextUUID(
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

	var query ThreatListQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		response.BadRequest(
			c,
			"Invalid threat query",
			err.Error(),
		)
		return
	}

	result, err := h.service.ListThreats(
		c.Request.Context(),
		organizationID.String(),
		query,
	)
	if err != nil {
		handleThreatError(c, err)
		return
	}

	response.OK(
		c,
		"Threats retrieved successfully",
		result,
	)
}

// GetThreat returns one threat and its correlated file events.
func (h *ThreatHandler) GetThreat(c *gin.Context) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Threat handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := threatContextUUID(
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

	threatID := strings.TrimSpace(c.Param("id"))
	if _, err := uuid.Parse(threatID); err != nil {
		response.BadRequest(
			c,
			"Invalid threat ID",
			err.Error(),
		)
		return
	}

	result, err := h.service.GetThreat(
		c.Request.Context(),
		organizationID.String(),
		threatID,
	)
	if err != nil {
		handleThreatError(c, err)
		return
	}

	response.OK(
		c,
		"Threat retrieved successfully",
		result,
	)
}

// UpdateThreatStatus updates a threat investigation lifecycle status.
func (h *ThreatHandler) UpdateThreatStatus(c *gin.Context) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Threat handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := threatContextUUID(
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

	actorID, ok := threatContextUUID(c, "user_id")
	if !ok {
		response.Unauthorized(
			c,
			"User information is missing",
			nil,
		)
		return
	}

	threatID := strings.TrimSpace(c.Param("id"))
	if _, err := uuid.Parse(threatID); err != nil {
		response.BadRequest(
			c,
			"Invalid threat ID",
			err.Error(),
		)
		return
	}

	var request UpdateThreatStatusRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid threat status request",
			err.Error(),
		)
		return
	}

	result, err := h.service.UpdateThreatStatus(
		c.Request.Context(),
		organizationID.String(),
		threatID,
		actorID.String(),
		request,
	)
	if err != nil {
		handleThreatError(c, err)
		return
	}

	response.OK(
		c,
		"Threat status updated successfully",
		result,
	)
}

// AssignThreat assigns a threat to an investigator.
func (h *ThreatHandler) AssignThreat(c *gin.Context) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Threat handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := threatContextUUID(
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

	threatID := strings.TrimSpace(c.Param("id"))
	if _, err := uuid.Parse(threatID); err != nil {
		response.BadRequest(
			c,
			"Invalid threat ID",
			err.Error(),
		)
		return
	}

	var request AssignThreatRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid threat assignment request",
			err.Error(),
		)
		return
	}

	result, err := h.service.AssignThreat(
		c.Request.Context(),
		organizationID.String(),
		threatID,
		request,
	)
	if err != nil {
		handleThreatError(c, err)
		return
	}

	response.OK(
		c,
		"Threat assigned successfully",
		result,
	)
}

func (h *ThreatHandler) isAvailable() bool {
	return h != nil && h.service != nil
}

func threatContextUUID(
	c *gin.Context,
	key string,
) (uuid.UUID, bool) {
	if c == nil {
		return uuid.Nil, false
	}

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
		parsed, err := uuid.Parse(
			strings.TrimSpace(typedValue),
		)
		if err != nil || parsed == uuid.Nil {
			return uuid.Nil, false
		}

		return parsed, true

	default:
		return uuid.Nil, false
	}
}

func handleThreatError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrThreatNotFound):
		response.NotFound(
			c,
			"Threat not found",
			nil,
		)

	case errors.Is(err, ErrInvalidThreatTransition):
		response.Error(
			c,
			http.StatusConflict,
			"Invalid threat status transition",
			err.Error(),
		)

	case errors.Is(err, ErrInvalidThreatRequest):
		response.BadRequest(
			c,
			"Invalid threat request",
			err.Error(),
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Threat operation failed",
			nil,
		)
	}
}
