package honeytoken

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

type InvestigationCaseHandler struct{ service *InvestigationCaseService }

func NewInvestigationCaseHandler(service *InvestigationCaseService) *InvestigationCaseHandler {
	return &InvestigationCaseHandler{service: service}
}
func (h *InvestigationCaseHandler) available() bool { return h != nil && h.service != nil }

func (h *InvestigationCaseHandler) Create(c *gin.Context) {
	if !h.available() {
		response.InternalServerError(c, "Investigation case handler is unavailable", nil)
		return
	}
	orgID, actorID, ok := incidentContextIdentity(c)
	if !ok {
		response.Unauthorized(c, "Authentication information is missing", nil)
		return
	}
	var request CreateInvestigationCaseRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid investigation case request", err.Error())
		return
	}
	item, err := h.service.Create(c.Request.Context(), orgID, actorID, request)
	if err != nil {
		handleCaseError(c, err)
		return
	}
	response.Created(c, "Investigation case created successfully", item)
}
func (h *InvestigationCaseHandler) Get(c *gin.Context) {
	if !h.available() {
		response.InternalServerError(c, "Investigation case handler is unavailable", nil)
		return
	}
	orgID, ok := incidentContextUUID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Organization information is missing", nil)
		return
	}
	item, err := h.service.Get(c.Request.Context(), orgID, strings.TrimSpace(c.Param("id")))
	if err != nil {
		handleCaseError(c, err)
		return
	}
	response.OK(c, "Investigation case retrieved successfully", item)
}
func (h *InvestigationCaseHandler) List(c *gin.Context) {
	if !h.available() {
		response.InternalServerError(c, "Investigation case handler is unavailable", nil)
		return
	}
	orgID, ok := incidentContextUUID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Organization information is missing", nil)
		return
	}
	items, err := h.service.List(c.Request.Context(), orgID)
	if err != nil {
		handleCaseError(c, err)
		return
	}
	response.OK(c, "Investigation cases retrieved successfully", items)
}
func (h *InvestigationCaseHandler) Update(c *gin.Context) {
	if !h.available() {
		response.InternalServerError(c, "Investigation case handler is unavailable", nil)
		return
	}
	orgID, ok := incidentContextUUID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Organization information is missing", nil)
		return
	}
	var request UpdateInvestigationCaseRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid investigation case update", err.Error())
		return
	}
	item, err := h.service.Update(c.Request.Context(), orgID, strings.TrimSpace(c.Param("id")), request)
	if err != nil {
		handleCaseError(c, err)
		return
	}
	response.OK(c, "Investigation case updated successfully", item)
}
func (h *InvestigationCaseHandler) LinkIncident(c *gin.Context) {
	if !h.available() {
		response.InternalServerError(c, "Investigation case handler is unavailable", nil)
		return
	}
	orgID, actorID, ok := incidentContextIdentity(c)
	if !ok {
		response.Unauthorized(c, "Authentication information is missing", nil)
		return
	}
	var request LinkCaseIncidentRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid case incident request", err.Error())
		return
	}
	err := h.service.LinkIncident(c.Request.Context(), orgID, actorID, strings.TrimSpace(c.Param("id")), request)
	if err != nil {
		handleCaseError(c, err)
		return
	}
	response.Created(c, "Incident linked to investigation case successfully", nil)
}
func (h *InvestigationCaseHandler) ListIncidents(c *gin.Context) {
	if !h.available() {
		response.InternalServerError(c, "Investigation case handler is unavailable", nil)
		return
	}
	orgID, ok := incidentContextUUID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Organization information is missing", nil)
		return
	}
	items, err := h.service.ListIncidents(c.Request.Context(), orgID, strings.TrimSpace(c.Param("id")))
	if err != nil {
		handleCaseError(c, err)
		return
	}
	response.OK(c, "Case incidents retrieved successfully", items)
}
func handleCaseError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrInvestigationCaseNotFound):
		response.NotFound(c, "Investigation case not found", nil)
	case errors.Is(err, ErrIncidentNotFound):
		response.NotFound(c, "Incident not found", nil)
	case errors.Is(err, ErrCaseIncidentAlreadyLinked):
		response.Error(c, http.StatusConflict, "Incident is already linked to a case", nil)
	case errors.Is(err, ErrInvalidIncidentRequest):
		response.BadRequest(c, "Invalid investigation case operation", err.Error())
	default:
		_ = c.Error(err)
		response.InternalServerError(c, "Investigation case operation failed", nil)
	}
}
