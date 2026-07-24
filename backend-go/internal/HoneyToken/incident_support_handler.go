package honeytoken

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

// LinkIncidentThreat links a threat to an incident.
func (h *IncidentHandler) LinkIncidentThreat(
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

	var request LinkIncidentThreatRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid incident threat request",
			err.Error(),
		)
		return
	}

	err := h.service.LinkIncidentThreat(
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
		"Threat linked to incident successfully",
		nil,
	)
}

// ListIncidentThreats returns threats linked to an incident.
func (h *IncidentHandler) ListIncidentThreats(
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

	threats, err := h.service.ListIncidentThreats(
		c.Request.Context(),
		organizationID,
		strings.TrimSpace(c.Param("id")),
	)
	if err != nil {
		handleIncidentError(c, err)
		return
	}

	response.OK(
		c,
		"Incident threats retrieved successfully",
		threats,
	)
}

// AddIncidentTimelineNote adds an investigator note.
func (h *IncidentHandler) AddIncidentTimelineNote(
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

	var request AddIncidentTimelineNoteRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid timeline note request",
			err.Error(),
		)
		return
	}

	entry, err := h.service.AddIncidentTimelineNote(
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

	response.Created(
		c,
		"Incident timeline note added successfully",
		entry,
	)
}

// ListIncidentTimeline returns paginated incident timeline entries.
func (h *IncidentHandler) ListIncidentTimeline(
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

	var query IncidentTimelineListQuery

	if err := c.ShouldBindQuery(&query); err != nil {
		response.BadRequest(
			c,
			"Invalid timeline query",
			err.Error(),
		)
		return
	}

	timeline, err := h.service.ListIncidentTimeline(
		c.Request.Context(),
		organizationID,
		strings.TrimSpace(c.Param("id")),
		query,
	)
	if err != nil {
		handleIncidentError(c, err)
		return
	}

	response.OK(
		c,
		"Incident timeline retrieved successfully",
		timeline,
	)
}

// AddIncidentEvidence registers incident evidence.
func (h *IncidentHandler) AddIncidentEvidence(
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

	var request AddIncidentEvidenceRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid incident evidence request",
			err.Error(),
		)
		return
	}

	evidence, err := h.service.AddIncidentEvidence(
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

	response.Created(
		c,
		"Incident evidence added successfully",
		evidence,
	)
}

// GetIncidentEvidence returns one evidence record.
func (h *IncidentHandler) GetIncidentEvidence(
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

	evidence, err := h.service.GetIncidentEvidence(
		c.Request.Context(),
		organizationID,
		strings.TrimSpace(c.Param("id")),
		strings.TrimSpace(c.Param("evidenceId")),
	)
	if err != nil {
		handleIncidentError(c, err)
		return
	}

	response.OK(
		c,
		"Incident evidence retrieved successfully",
		evidence,
	)
}

// ListIncidentEvidence returns paginated evidence.
func (h *IncidentHandler) ListIncidentEvidence(
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

	var query IncidentEvidenceListQuery

	if err := c.ShouldBindQuery(&query); err != nil {
		response.BadRequest(
			c,
			"Invalid incident evidence query",
			err.Error(),
		)
		return
	}

	evidence, err := h.service.ListIncidentEvidence(
		c.Request.Context(),
		organizationID,
		strings.TrimSpace(c.Param("id")),
		query,
	)
	if err != nil {
		handleIncidentError(c, err)
		return
	}

	response.OK(
		c,
		"Incident evidence retrieved successfully",
		evidence,
	)
}

// VerifyIncidentEvidence verifies stored evidence integrity.
func (h *IncidentHandler) VerifyIncidentEvidence(
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

	var request VerifyIncidentEvidenceRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid evidence verification request",
			err.Error(),
		)
		return
	}

	evidence, err :=
		h.service.VerifyIncidentEvidence(
			c.Request.Context(),
			organizationID,
			strings.TrimSpace(c.Param("id")),
			strings.TrimSpace(
				c.Param("evidenceId"),
			),
			userID,
			request,
		)
	if err != nil {
		handleIncidentError(c, err)
		return
	}

	response.OK(
		c,
		"Incident evidence verification completed",
		evidence,
	)
}
