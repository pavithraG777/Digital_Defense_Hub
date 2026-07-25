package airisk

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

type RiskScoreHandler struct {
	service *Service
}

func NewRiskScoreHandler(
	service *Service,
) *RiskScoreHandler {
	return &RiskScoreHandler{
		service: service,
	}
}

func (h *RiskScoreHandler) CalculateIncidentRisk(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"AI risk score handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := riskContextUUID(
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
		c.Param("incident_id"),
	)

	var request CalculateIncidentRiskRequest

	if err := c.ShouldBindJSON(
		&request,
	); err != nil &&
		!errors.Is(err, io.EOF) {
		response.BadRequest(
			c,
			"Invalid AI risk calculation request",
			err.Error(),
		)
		return
	}

	result, err :=
		h.service.CalculateIncidentRisk(
			c.Request.Context(),
			organizationID,
			incidentID,
			request,
		)
	if err != nil {
		handleRiskScoreError(c, err)
		return
	}

	response.OK(
		c,
		"Incident AI risk score calculated successfully",
		result,
	)
}

func (h *RiskScoreHandler) GetRiskScore(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"AI risk score handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := riskContextUUID(
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

	riskScoreID := strings.TrimSpace(
		c.Param("risk_score_id"),
	)

	riskScore, err :=
		h.service.GetRiskScore(
			c.Request.Context(),
			organizationID,
			riskScoreID,
		)
	if err != nil {
		handleRiskScoreError(c, err)
		return
	}

	response.OK(
		c,
		"AI risk score retrieved successfully",
		riskScore,
	)
}

func (h *RiskScoreHandler) ListRiskScores(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"AI risk score handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := riskContextUUID(
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

	var query ListRiskScoresRequest

	if err := c.ShouldBindQuery(
		&query,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid AI risk score query",
			err.Error(),
		)
		return
	}

	riskScores, err :=
		h.service.ListRiskScores(
			c.Request.Context(),
			organizationID,
			query,
		)
	if err != nil {
		handleRiskScoreError(c, err)
		return
	}

	response.OK(
		c,
		"AI risk scores retrieved successfully",
		riskScores,
	)
}

func (h *RiskScoreHandler) GetActiveIncidentRiskScore(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"AI risk score handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := riskContextUUID(
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
		c.Param("incident_id"),
	)

	riskScore, err :=
		h.service.GetActiveIncidentRiskScore(
			c.Request.Context(),
			organizationID,
			incidentID,
		)
	if err != nil {
		handleRiskScoreError(c, err)
		return
	}

	response.OK(
		c,
		"Active incident AI risk score retrieved successfully",
		riskScore,
	)
}

func (h *RiskScoreHandler) CheckRiskEngineHealth(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"AI risk score handler is unavailable",
			nil,
		)
		return
	}

	if err := h.service.CheckRiskEngineHealth(
		c.Request.Context(),
	); err != nil {
		handleRiskScoreError(c, err)
		return
	}

	response.OK(
		c,
		"AI Risk Scoring Engine is healthy",
		gin.H{
			"status": "HEALTHY",
		},
	)
}

func (h *RiskScoreHandler) isAvailable() bool {
	return h != nil &&
		h.service != nil
}

func riskContextUUID(
	c *gin.Context,
	key string,
) (uuid.UUID, bool) {
	if c == nil {
		return uuid.Nil, false
	}

	value, exists := c.Get(key)
	if !exists || value == nil {
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

func handleRiskScoreError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(
		err,
		ErrRiskScoreNotFound,
	):
		response.NotFound(
			c,
			"AI risk score not found",
			nil,
		)

	case errors.Is(
		err,
		ErrRiskSubjectNotFound,
	):
		response.NotFound(
			c,
			"AI risk subject not found",
			nil,
		)

	case errors.Is(
		err,
		ErrInvalidRiskScoreRequest,
	):
		response.BadRequest(
			c,
			"Invalid AI risk score operation",
			err.Error(),
		)

	case errors.Is(
		err,
		ErrRiskEngineUnavailable,
	):
		response.Error(
			c,
			http.StatusServiceUnavailable,
			"AI Risk Scoring Engine is unavailable",
			nil,
		)

	case errors.Is(
		err,
		ErrInvalidRiskEngineResponse,
	):
		response.Error(
			c,
			http.StatusBadGateway,
			"AI Risk Scoring Engine returned an invalid response",
			nil,
		)

	case errors.Is(
		err,
		context.DeadlineExceeded,
	):
		response.Error(
			c,
			http.StatusGatewayTimeout,
			"AI risk calculation timed out",
			nil,
		)

	case errors.Is(
		err,
		context.Canceled,
	):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"AI risk calculation was cancelled",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"AI risk score operation failed",
			nil,
		)
	}
}
