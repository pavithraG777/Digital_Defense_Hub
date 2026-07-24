package honeytoken

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

// IncidentHandler handles organization-scoped incident API requests.
type IncidentHandler struct {
	service *IncidentService
}

func NewIncidentHandler(
	service *IncidentService,
) *IncidentHandler {
	return &IncidentHandler{
		service: service,
	}
}

// CreateIncident creates a manually reported incident.
func (h *IncidentHandler) CreateIncident(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Incident handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := incidentContextUUID(
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

	userID, ok := incidentContextUUID(
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

	var request CreateIncidentRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid incident request",
			err.Error(),
		)
		return
	}

	incident, err := h.service.CreateIncident(
		c.Request.Context(),
		organizationID,
		userID,
		request,
	)
	if err != nil {
		handleIncidentError(c, err)
		return
	}

	response.Created(
		c,
		"Incident created successfully",
		incident,
	)
}

// GetIncident returns one organization incident.
func (h *IncidentHandler) GetIncident(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Incident handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := incidentContextUUID(
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

	incidentID := strings.TrimSpace(
		c.Param("id"),
	)

	incident, err := h.service.GetIncident(
		c.Request.Context(),
		organizationID,
		incidentID,
	)
	if err != nil {
		handleIncidentError(c, err)
		return
	}

	response.OK(
		c,
		"Incident retrieved successfully",
		incident,
	)
}

// ListIncidents returns paginated organization incidents.
func (h *IncidentHandler) ListIncidents(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Incident handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := incidentContextUUID(
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

	var query IncidentListQuery

	if err := c.ShouldBindQuery(&query); err != nil {
		response.BadRequest(
			c,
			"Invalid incident query",
			err.Error(),
		)
		return
	}

	incidents, err := h.service.ListIncidents(
		c.Request.Context(),
		organizationID,
		query,
	)
	if err != nil {
		handleIncidentError(c, err)
		return
	}

	response.OK(
		c,
		"Incidents retrieved successfully",
		incidents,
	)
}

// AssignIncident assigns an incident investigator.
func (h *IncidentHandler) AssignIncident(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Incident handler is unavailable",
			nil,
		)
		return
	}

	organizationID, userID, ok :=
		incidentContextIdentity(c)
	if !ok {
		response.Unauthorized(
			c,
			"Authentication information is missing",
			nil,
		)
		return
	}

	var request AssignIncidentRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid incident assignment request",
			err.Error(),
		)
		return
	}

	incident, err := h.service.AssignIncident(
		c.Request.Context(),
		organizationID,
		strings.TrimSpace(c.Param("id")),
		userID,
		request,
	)
	if err != nil {
		handleIncidentError(c, err)
		return
	}

	response.OK(
		c,
		"Incident assigned successfully",
		incident,
	)
}

// UpdateIncidentStatus updates the incident lifecycle.
func (h *IncidentHandler) UpdateIncidentStatus(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Incident handler is unavailable",
			nil,
		)
		return
	}

	organizationID, userID, ok :=
		incidentContextIdentity(c)
	if !ok {
		response.Unauthorized(
			c,
			"Authentication information is missing",
			nil,
		)
		return
	}

	var request UpdateIncidentStatusRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid incident status request",
			err.Error(),
		)
		return
	}

	incident, err := h.service.UpdateIncidentStatus(
		c.Request.Context(),
		organizationID,
		strings.TrimSpace(c.Param("id")),
		userID,
		request,
	)
	if err != nil {
		handleIncidentError(c, err)
		return
	}

	response.OK(
		c,
		"Incident status updated successfully",
		incident,
	)
}

// UpdateIncidentInvestigation updates incident findings and impact.
func (h *IncidentHandler) UpdateIncidentInvestigation(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Incident handler is unavailable",
			nil,
		)
		return
	}

	organizationID, userID, ok :=
		incidentContextIdentity(c)
	if !ok {
		response.Unauthorized(
			c,
			"Authentication information is missing",
			nil,
		)
		return
	}

	var request UpdateIncidentInvestigationRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid investigation update request",
			err.Error(),
		)
		return
	}

	incident, err :=
		h.service.UpdateIncidentInvestigation(
			c.Request.Context(),
			organizationID,
			strings.TrimSpace(c.Param("id")),
			userID,
			request,
		)
	if err != nil {
		handleIncidentError(c, err)
		return
	}

	response.OK(
		c,
		"Incident investigation updated successfully",
		incident,
	)
}

func (h *IncidentHandler) isAvailable() bool {
	return h != nil && h.service != nil
}

func incidentContextIdentity(
	c *gin.Context,
) (uuid.UUID, uuid.UUID, bool) {
	organizationID, organizationOK :=
		incidentContextUUID(
			c,
			"organization_id",
		)

	userID, userOK := incidentContextUUID(
		c,
		"user_id",
	)

	return organizationID,
		userID,
		organizationOK && userOK
}

func incidentContextUUID(
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
		if typedValue == nil ||
			*typedValue == uuid.Nil {
			return uuid.Nil, false
		}

		return *typedValue, true

	case string:
		parsedValue, err := uuid.Parse(
			strings.TrimSpace(typedValue),
		)
		if err != nil ||
			parsedValue == uuid.Nil {
			return uuid.Nil, false
		}

		return parsedValue, true

	default:
		return uuid.Nil, false
	}
}

func handleIncidentError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrIncidentNotFound):
		response.NotFound(
			c,
			"Incident not found",
			nil,
		)

	case errors.Is(
		err,
		ErrIncidentEvidenceNotFound,
	):
		response.NotFound(
			c,
			"Incident evidence not found",
			nil,
		)

	case errors.Is(err, ErrThreatNotFound):
		response.NotFound(
			c,
			"Threat not found",
			nil,
		)

	case errors.Is(
		err,
		ErrIncidentDepartmentNotFound,
	):
		response.NotFound(
			c,
			"Department not found",
			nil,
		)

	case errors.Is(
		err,
		ErrIncidentAffectedUserNotFound,
	):
		response.NotFound(
			c,
			"Affected user not found",
			nil,
		)

	case errors.Is(
		err,
		ErrIncidentInvestigatorNotFound,
	):
		response.NotFound(
			c,
			"Incident investigator not found",
			nil,
		)

	case errors.Is(
		err,
		ErrIncidentReporterNotFound,
	):
		response.NotFound(
			c,
			"Incident reporter not found",
			nil,
		)

	case errors.Is(
		err,
		ErrInvalidIncidentStatusTransition,
	):
		response.Error(
			c,
			http.StatusConflict,
			"Invalid incident status transition",
			err.Error(),
		)

	case errors.Is(
		err,
		ErrIncidentNumberExists,
	),
		errors.Is(
			err,
			ErrIncidentThreatAlreadyLinked,
		),
		errors.Is(
			err,
			ErrIncidentEvidenceCodeExists,
		):
		response.Error(
			c,
			http.StatusConflict,
			"Incident resource conflict",
			err.Error(),
		)

	case errors.Is(
		err,
		ErrIncidentInvestigatorRequired,
	),
		errors.Is(
			err,
			ErrIncidentContainmentSummaryRequired,
		),
		errors.Is(
			err,
			ErrIncidentResolutionSummaryRequired,
		),
		errors.Is(
			err,
			ErrNoIncidentInvestigationChanges,
		),
		errors.Is(
			err,
			ErrInvalidIncidentRequest,
		),
		errors.Is(
			err,
			ErrIncidentFutureDetectionTime,
		),
		errors.Is(
			err,
			ErrInvalidIncidentMetadata,
		),
		errors.Is(
			err,
			ErrInvalidIncidentEvidence,
		),
		errors.Is(
			err,
			ErrIncidentEvidenceHashUnavailable,
		),
		errors.Is(
			err,
			ErrIncidentEvidenceReferenceNotFound,
		):
		response.BadRequest(
			c,
			"Invalid incident operation",
			err.Error(),
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Incident operation failed",
			nil,
		)
	}
}
