package preencryption

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

const permissionManagePreEncryptionDetections = "ORGANIZATION_MANAGE_SECURITY"

func RegisterRoutes(
	protected *gin.RouterGroup,
	handler *Handler,
	databasePool *pgxpool.Pool,
) {
	if protected == nil ||
		handler == nil ||
		databasePool == nil {
		return
	}

	detectionGroup := protected.Group(
		"/pre-encryption-detections",
	)

	detectionGroup.GET(
		"/engine/health",
		middleware.RequirePermission(
			databasePool,
			"THREAT_VIEW",
		),
		handler.CheckEngineHealth,
	)

	detectionGroup.GET(
		"",
		middleware.RequirePermission(
			databasePool,
			"THREAT_VIEW",
		),
		handler.ListDetections,
	)

	detectionGroup.GET(
		"/:detection_id",
		middleware.RequirePermission(
			databasePool,
			"THREAT_VIEW",
		),
		handler.GetDetection,
	)

	detectionGroup.GET(
		"/:detection_id/details",
		middleware.RequirePermission(
			databasePool,
			"THREAT_VIEW",
		),
		handler.GetDetectionDetails,
	)

	detectionGroup.PATCH(
		"/:detection_id/status",
		middleware.RequirePermission(
			databasePool,
			permissionManagePreEncryptionDetections,
		),
		handler.UpdateDetectionStatus,
	)
}
