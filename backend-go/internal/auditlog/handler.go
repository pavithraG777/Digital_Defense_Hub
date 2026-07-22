package auditlog

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(
	service *Service,
) *Handler {
	return &Handler{
		service: service,
	}
}

func (h *Handler) ListAuditLogs(
	c *gin.Context,
) {
	auditLogs, err := h.service.ListAuditLogs(
		c.Request.Context(),
	)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"success": false,
				"message": "Failed to list audit logs",
				"error":   err.Error(),
			},
		)
		return
	}

	c.JSON(
		http.StatusOK,
		gin.H{
			"success": true,
			"message": "Audit logs retrieved successfully",
			"data":    auditLogs,
		},
	)
}

func (h *Handler) GetAuditLogByID(
	c *gin.Context,
) {
	id := c.Param("id")

	auditLog, err := h.service.GetAuditLogByID(
		c.Request.Context(),
		id,
	)
	if err != nil {
		if errors.Is(err, ErrInvalidAuditLog) {
			c.JSON(
				http.StatusBadRequest,
				gin.H{
					"success": false,
					"message": "Invalid audit log ID",
					"error":   err.Error(),
				},
			)
			return
		}

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"success": false,
				"message": "Failed to get audit log",
				"error":   err.Error(),
			},
		)
		return
	}

	c.JSON(
		http.StatusOK,
		gin.H{
			"success": true,
			"message": "Audit log retrieved successfully",
			"data":    auditLog,
		},
	)
}
