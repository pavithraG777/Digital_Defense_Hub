package auditlog

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const auditLogTimeout = 3 * time.Second

func Middleware(
	service *Service,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		if service == nil {
			c.Next()
			return
		}

		startedAt := time.Now().UTC()

		c.Next()

		routePath := c.FullPath()
		if strings.TrimSpace(routePath) == "" {
			routePath = c.Request.URL.Path
		}

		statusCode := c.Writer.Status()

		resultStatus := ResultStatusSuccess
		failureReason := ""

		if statusCode >= http.StatusBadRequest {
			resultStatus = ResultStatusFailed
			failureReason = buildFailureReason(
				statusCode,
				c.Errors.String(),
			)
		}

		moduleName := extractModuleName(routePath)

		actionName := extractActionName(
			c.Request.Method,
		)

		entityType := extractEntityType(routePath)
		entityID := extractEntityID(c)

		metadata := map[string]any{
			"http_method":     c.Request.Method,
			"request_path":    c.Request.URL.Path,
			"route_path":      routePath,
			"query_string":    c.Request.URL.RawQuery,
			"response_status": statusCode,
			"duration_ms": time.Since(
				startedAt,
			).Milliseconds(),
			"request_id": getContextString(
				c,
				"request_id",
			),
		}

		auditEntry := &AuditLog{
			OrganizationID: getContextUUID(
				c,
				"organization_id",
			),
			UserID: getContextUUID(
				c,
				"user_id",
			),
			SessionID: getContextUUID(
				c,
				"token_id",
			),
			ModuleName: moduleName,
			ActionName: actionName,
			EntityType: entityType,
			EntityID:   entityID,
			Description: buildDescription(
				c.Request.Method,
				routePath,
				statusCode,
			),
			OldValues: map[string]any{},
			NewValues: map[string]any{},
			Metadata:  metadata,
			IPAddress: c.ClientIP(),
			DeviceName: strings.TrimSpace(
				c.GetHeader("X-Device-Name"),
			),
			UserAgent: strings.TrimSpace(
				c.Request.UserAgent(),
			),
			ResultStatus: resultStatus,
			RiskLevel: determineRiskLevel(
				c.Request.Method,
				statusCode,
			),
			FailureReason: failureReason,
			OccurredAt:    startedAt,
		}

		logContext, cancel := context.WithTimeout(
			context.Background(),
			auditLogTimeout,
		)
		defer cancel()

		_ = service.Log(
			logContext,
			auditEntry,
		)
	}
}

func getContextUUID(
	c *gin.Context,
	key string,
) *uuid.UUID {
	value, exists := c.Get(key)
	if !exists || value == nil {
		return nil
	}

	switch typedValue := value.(type) {
	case uuid.UUID:
		id := typedValue
		return &id

	case *uuid.UUID:
		return typedValue

	case string:
		parsedID, err := uuid.Parse(
			strings.TrimSpace(typedValue),
		)
		if err != nil {
			return nil
		}

		return &parsedID

	default:
		parsedID, err := uuid.Parse(
			fmt.Sprint(typedValue),
		)
		if err != nil {
			return nil
		}

		return &parsedID
	}
}

func getContextString(
	c *gin.Context,
	key string,
) string {
	value, exists := c.Get(key)
	if !exists || value == nil {
		return ""
	}

	return strings.TrimSpace(
		fmt.Sprint(value),
	)
}

func extractModuleName(
	routePath string,
) string {
	segments := splitRoutePath(routePath)

	ignoredSegments := map[string]struct{}{
		"api":   {},
		"v1":    {},
		"v2":    {},
		"admin": {},
	}

	for _, segment := range segments {
		normalizedSegment := strings.ToLower(
			strings.TrimSpace(segment),
		)

		if normalizedSegment == "" {
			continue
		}

		if strings.HasPrefix(normalizedSegment, ":") {
			continue
		}

		if strings.HasPrefix(normalizedSegment, "{") {
			continue
		}

		if _, ignored := ignoredSegments[normalizedSegment]; ignored {
			continue
		}

		return strings.ToUpper(
			strings.ReplaceAll(
				normalizedSegment,
				"-",
				"_",
			),
		)
	}

	return "SYSTEM"
}

func extractEntityType(
	routePath string,
) string {
	return extractModuleName(routePath)
}

func extractActionName(
	method string,
) string {
	switch strings.ToUpper(
		strings.TrimSpace(method),
	) {
	case http.MethodPost:
		return "CREATE"

	case http.MethodGet:
		return "VIEW"

	case http.MethodPut:
		return "UPDATE"

	case http.MethodPatch:
		return "UPDATE"

	case http.MethodDelete:
		return "DELETE"

	default:
		return strings.ToUpper(
			strings.TrimSpace(method),
		)
	}
}

func extractEntityID(
	c *gin.Context,
) *uuid.UUID {
	parameterNames := []string{
		"id",
		"user_id",
		"userId",
		"role_id",
		"roleId",
		"permission_id",
		"permissionId",
		"entity_id",
		"entityId",
	}

	for _, parameterName := range parameterNames {
		value := strings.TrimSpace(
			c.Param(parameterName),
		)

		if value == "" {
			continue
		}

		parsedID, err := uuid.Parse(value)
		if err == nil {
			return &parsedID
		}
	}

	return nil
}

func determineRiskLevel(
	method string,
	statusCode int,
) string {
	if statusCode >= http.StatusInternalServerError {
		return RiskLevelHigh
	}

	if statusCode == http.StatusUnauthorized ||
		statusCode == http.StatusForbidden {
		return RiskLevelMedium
	}

	switch strings.ToUpper(
		strings.TrimSpace(method),
	) {
	case http.MethodDelete:
		return RiskLevelHigh

	case http.MethodPost,
		http.MethodPut,
		http.MethodPatch:
		return RiskLevelMedium

	default:
		return RiskLevelLow
	}
}

func buildFailureReason(
	statusCode int,
	errorMessage string,
) string {
	trimmedErrorMessage := strings.TrimSpace(
		errorMessage,
	)

	if trimmedErrorMessage != "" {
		return trimmedErrorMessage
	}

	statusText := http.StatusText(statusCode)
	if strings.TrimSpace(statusText) == "" {
		statusText = "Request failed"
	}

	return fmt.Sprintf(
		"HTTP %d: %s",
		statusCode,
		statusText,
	)
}

func buildDescription(
	method string,
	routePath string,
	statusCode int,
) string {
	return fmt.Sprintf(
		"%s request to %s completed with HTTP status %d",
		strings.ToUpper(
			strings.TrimSpace(method),
		),
		routePath,
		statusCode,
	)
}

func splitRoutePath(
	routePath string,
) []string {
	trimmedPath := strings.Trim(
		strings.TrimSpace(routePath),
		"/",
	)

	if trimmedPath == "" {
		return []string{}
	}

	return strings.Split(
		trimmedPath,
		"/",
	)
}
