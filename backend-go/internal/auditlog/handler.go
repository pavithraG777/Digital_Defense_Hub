package auditlog

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
	organizationRaw, exists := c.Get("organization_id")
	organizationID, parseErr := uuid.Parse(strings.TrimSpace(toString(organizationRaw)))
	if !exists || parseErr != nil || organizationID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Organization information is missing"})
		return
	}
	auditLogs, err := h.service.ListAuditLogsForOrganization(c.Request.Context(), organizationID)
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

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 100 {
		pageSize = 100
	}
	query := strings.ToLower(strings.TrimSpace(c.Query("search")))
	risk := strings.ToUpper(strings.TrimSpace(c.Query("risk_level")))
	module := strings.ToUpper(strings.TrimSpace(c.Query("module")))
	filtered := make([]AuditLog, 0, len(auditLogs))
	for _, entry := range auditLogs {
		if risk != "" && entry.RiskLevel != risk {
			continue
		}
		if module != "" && entry.ModuleName != module {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(strings.Join([]string{entry.ModuleName, entry.ActionName, entry.EntityType, entry.Description, entry.DeviceName, entry.ResultStatus}, " ")), query) {
			continue
		}
		filtered = append(filtered, entry)
	}
	total := len(filtered)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	c.JSON(
		http.StatusOK,
		gin.H{
			"success": true,
			"message": "Audit logs retrieved successfully",
			"data":    gin.H{"items": filtered[start:end], "total": total, "page": page, "page_size": pageSize, "total_pages": (total + pageSize - 1) / pageSize},
		},
	)
}

// ListTimeline serves the organization-scoped, database-paginated central
// activity stream.  It unifies administrative, endpoint/deception, threat,
// incident and forensic-review events on the server.
func (h *Handler) ListTimeline(c *gin.Context) {
	organizationRaw, exists := c.Get("organization_id")
	organizationID, err := uuid.Parse(strings.TrimSpace(toString(organizationRaw)))
	if !exists || err != nil || organizationID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Organization information is missing"})
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 100 {
		pageSize = 100
	}
	filter := TimelineFilter{Search: strings.TrimSpace(c.Query("search")), SourceType: strings.ToUpper(strings.TrimSpace(c.Query("source_type"))), RiskLevel: strings.ToUpper(strings.TrimSpace(c.Query("risk_level"))), Suspicious: strings.EqualFold(c.Query("suspicious"), "true"), Limit: pageSize, Offset: (page - 1) * pageSize}
	for _, pair := range []struct {
		name   string
		target **time.Time
	}{{"from", &filter.From}, {"to", &filter.To}} {
		if raw := strings.TrimSpace(c.Query(pair.name)); raw != "" {
			value, parseErr := time.Parse(time.RFC3339, raw)
			if parseErr != nil {
				c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": pair.name + " must use RFC3339 format"})
				return
			}
			*pair.target = &value
		}
	}
	result, err := h.service.ListTimeline(c.Request.Context(), organizationID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to list audit activity", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Audit activity retrieved successfully", "data": gin.H{"items": result.Items, "total": result.Total, "page": page, "page_size": pageSize, "total_pages": (result.Total + pageSize - 1) / pageSize}})
}

func toString(value any) string {
	if value == nil {
		return ""
	}
	if id, ok := value.(uuid.UUID); ok {
		return id.String()
	}
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func (h *Handler) GetAuditLogByID(
	c *gin.Context,
) {
	id := c.Param("id")
	organizationRaw, exists := c.Get("organization_id")
	organizationID, parseErr := uuid.Parse(strings.TrimSpace(toString(organizationRaw)))
	if !exists || parseErr != nil || organizationID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Organization information is missing"})
		return
	}

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
	if auditLog.OrganizationID == nil || *auditLog.OrganizationID != organizationID {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "Audit log not found"})
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
