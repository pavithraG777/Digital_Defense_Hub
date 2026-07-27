package deepfakeforensics

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

const (
	deepfakeForensicsRoute = "/deepfake-forensics"

	permissionViewDeepfakeForensics = "THREAT_VIEW"

	permissionManageDeepfakeForensics = "ORGANIZATION_MANAGE_SECURITY"
)

// RegisterRoutes adds authenticated, organization-scoped
// deepfake detection, media forensics and OCR endpoints.
func RegisterRoutes(
	protectedRouter *gin.RouterGroup,
	handler *Handler,
	databasePool *pgxpool.Pool,
) {
	validateRouteDependencies(
		protectedRouter,
		handler,
		databasePool,
	)

	forensicsGroup := protectedRouter.Group(
		deepfakeForensicsRoute,
	)

	assetGroup := forensicsGroup.Group(
		"/media-assets",
	)

	assetGroup.POST(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.UploadMediaAsset,
	)

	assetGroup.GET(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionViewDeepfakeForensics,
		),
		handler.ListMediaAssets,
	)

	assetGroup.GET(
		"/:media_asset_id",
		middleware.RequirePermission(
			databasePool,
			permissionViewDeepfakeForensics,
		),
		handler.GetMediaAsset,
	)

	assetGroup.POST(
		"/:media_asset_id/analyze",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.StartMediaAnalysis,
	)

	jobGroup := forensicsGroup.Group(
		"/analysis-jobs",
	)

	jobGroup.GET(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionViewDeepfakeForensics,
		),
		handler.ListAnalysisJobs,
	)

	jobGroup.GET(
		"/:analysis_job_id",
		middleware.RequirePermission(
			databasePool,
			permissionViewDeepfakeForensics,
		),
		handler.GetAnalysisJob,
	)

	jobGroup.GET(
		"/:analysis_job_id/result",
		middleware.RequirePermission(
			databasePool,
			permissionViewDeepfakeForensics,
		),
		handler.GetAnalysisResult,
	)

	jobGroup.POST(
		"/:analysis_job_id/cancel",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.CancelAnalysisJob,
	)
}

func validateRouteDependencies(
	protectedRouter *gin.RouterGroup,
	handler *Handler,
	databasePool *pgxpool.Pool,
) {
	if protectedRouter == nil {
		panic(
			"protected router group is required",
		)
	}

	if handler == nil ||
		handler.assetService == nil ||
		handler.analysisService == nil ||
		handler.queryService == nil {
		panic(
			"deepfake forensics handler is required",
		)
	}

	if databasePool == nil {
		panic(
			"database pool is required for deepfake forensics routes",
		)
	}
}
