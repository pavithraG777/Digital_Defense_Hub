package auditlog

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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

		/*
			Request information-ஐ request context-ல் store செய்கிறது.

			User service-ல் LogSuccess அல்லது LogFailure call செய்யும்போது,
			இந்த context மூலமாக IP address, device name, user agent மற்றும்
			session ID கிடைக்கும்.
		*/
		deviceName := strings.TrimSpace(
			c.GetHeader("X-Device-Name"),
		)

		if deviceName == "" {
			deviceName = detectDeviceName(
				c.Request.UserAgent(),
			)
		}

		requestContext := WithRequestDetails(
			c.Request.Context(),
			c.ClientIP(),
			deviceName,
			c.Request.UserAgent(),
			getContextUUID(
				c,
				"token_id",
			),
		)

		c.Request = c.Request.WithContext(
			requestContext,
		)

		c.Next()

		if !shouldAuditRequest(c) {
			return
		}

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

		moduleName := extractModuleName(
			routePath,
		)

		actionName := extractActionName(
			c.Request.Method,
		)

		entityType := extractEntityType(
			routePath,
		)

		entityID := extractEntityID(c)

		/*
			token_id, organization_id மற்றும் user_id சில நேரங்களில்
			authentication middleware-ல் c.Next()க்கு முன்பு set ஆகும்.

			அதனால் audit entry உருவாக்கும்போது மீண்டும் Gin context-ல் இருந்து
			எடுக்கப்படுகிறது.
		*/
		sessionID := getContextUUID(
			c,
			"token_id",
		)

		organizationID := getContextUUID(
			c,
			"organization_id",
		)

		userID := getContextUUID(
			c,
			"user_id",
		)

		metadata := map[string]any{
			"http_method":  c.Request.Method,
			"request_path": c.Request.URL.Path,
			"route_path":   routePath,
			"query_string": sanitizeQueryString(
				c.Request.URL.Query(),
			),
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
			OrganizationID: organizationID,
			UserID:         userID,
			SessionID:      sessionID,

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

			DeviceName: deviceName,

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

		/*
			Request முடிந்த பிறகும் audit log database-ல் save ஆக வேண்டும்.
			அதனால் original request context பயன்படுத்தாமல் தனி timeout
			context பயன்படுத்தப்படுகிறது.
		*/
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

func shouldAuditRequest(c *gin.Context) bool {
	if c == nil || c.Request == nil || c.Request.URL == nil {
		return false
	}

	// Health probes can run every few seconds and do not represent a user or
	// security action. Excluding only these exact endpoints prevents audit-log
	// amplification while every public and protected business route remains
	// covered.
	switch strings.TrimSuffix(c.Request.URL.Path, "/") {
	case "/api/v1/health", "/api/v1/ready", "/api/v1/metrics":
		return false
	default:
		return true
	}
}

func sanitizeQueryString(values url.Values) string {
	if len(values) == 0 {
		return ""
	}

	sanitized := make(url.Values, len(values))
	for key, items := range values {
		if isSensitiveKey(key) {
			sanitized.Set(key, "[REDACTED]")
			continue
		}

		for _, item := range items {
			sanitized.Add(key, item)
		}
	}

	return sanitized.Encode()
}

func getContextUUID(
	c *gin.Context,
	key string,
) *uuid.UUID {
	if c == nil {
		return nil
	}

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
			strings.TrimSpace(
				typedValue,
			),
		)

		if err != nil {
			return nil
		}

		return &parsedID

	default:
		parsedID, err := uuid.Parse(
			strings.TrimSpace(
				fmt.Sprint(typedValue),
			),
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
	if c == nil {
		return ""
	}

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
	segments := splitRoutePath(
		routePath,
	)

	ignoredSegments := map[string]struct{}{
		"api":   {},
		"v1":    {},
		"v2":    {},
		"admin": {},
	}

	for _, segment := range segments {
		normalizedSegment := strings.ToLower(
			strings.TrimSpace(
				segment,
			),
		)

		if normalizedSegment == "" {
			continue
		}

		if strings.HasPrefix(
			normalizedSegment,
			":",
		) {
			continue
		}

		if strings.HasPrefix(
			normalizedSegment,
			"{",
		) {
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
	return extractModuleName(
		routePath,
	)
}

func extractActionName(
	method string,
) string {
	switch strings.ToUpper(
		strings.TrimSpace(
			method,
		),
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
			strings.TrimSpace(
				method,
			),
		)
	}
}

func extractEntityID(
	c *gin.Context,
) *uuid.UUID {
	if c == nil {
		return nil
	}

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
		strings.TrimSpace(
			method,
		),
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

	statusText := http.StatusText(
		statusCode,
	)

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
			strings.TrimSpace(
				method,
			),
		),
		routePath,
		statusCode,
	)
}

func splitRoutePath(
	routePath string,
) []string {
	trimmedPath := strings.Trim(
		strings.TrimSpace(
			routePath,
		),
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

func detectDeviceName(
	userAgent string,
) string {
	normalizedUserAgent := strings.ToLower(
		strings.TrimSpace(
			userAgent,
		),
	)

	switch {
	case normalizedUserAgent == "":
		return "Unknown Device"

	case strings.Contains(
		normalizedUserAgent,
		"postman",
	):
		return "Postman"

	case strings.Contains(
		normalizedUserAgent,
		"insomnia",
	):
		return "Insomnia"

	case strings.Contains(
		normalizedUserAgent,
		"curl",
	):
		return "cURL"

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
