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

	forensicsGroup.GET(
		"/health",
		middleware.RequirePermission(databasePool, permissionViewDeepfakeForensics),
		handler.GetEngineHealth,
	)

	policyGroup := forensicsGroup.Group("/organization-policy")
	policyGroup.GET("", middleware.RequirePermission(databasePool, permissionViewDeepfakeForensics), handler.GetOrganizationMediaPolicy)
	policyGroup.PUT("", middleware.RequirePermission(databasePool, permissionManageDeepfakeForensics), handler.UpdateOrganizationMediaPolicy)

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

	assetGroup.GET(
		"/:media_asset_id/preview",
		middleware.RequirePermission(
			databasePool,
			permissionViewDeepfakeForensics,
		),
		handler.PreviewMediaAsset,
	)

	assetGroup.POST(
		"/:media_asset_id/analyze",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.StartMediaAnalysis,
	)

	assetGroup.POST(
		"/:media_asset_id/forensic-reports",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.CreateMediaForensicReport,
	)

	assetGroup.POST(
		"/:media_asset_id/quarantine",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.QuarantineMediaAsset,
	)

	assetGroup.POST(
		"/:media_asset_id/release",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.ReleaseMediaAsset,
	)

	assetGroup.GET(
		"/:media_asset_id/security-events",
		middleware.RequirePermission(
			databasePool,
			permissionViewDeepfakeForensics,
		),
		handler.ListMediaAssetSecurityEvents,
	)

	assetGroup.GET(
		"/:media_asset_id/trust-assessment",
		middleware.RequirePermission(
			databasePool,
			permissionViewDeepfakeForensics,
		),
		handler.GetMediaTrustAssessment,
	)

	assetGroup.POST(
		"/:media_asset_id/trust-assessment/recalculate",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.RecalculateMediaTrustAssessment,
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

	jobGroup.POST(
		"/:analysis_job_id/retry",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.RetryAnalysisJob,
	)
	jobGroup.GET("/:analysis_job_id/review-workflow", middleware.RequirePermission(databasePool, permissionViewDeepfakeForensics), handler.GetReviewWorkflow)
	jobGroup.POST("/:analysis_job_id/reviews", middleware.RequirePermission(databasePool, permissionManageDeepfakeForensics), handler.CreateReview)
	jobGroup.POST("/:analysis_job_id/annotations", middleware.RequirePermission(databasePool, permissionManageDeepfakeForensics), handler.CreateAnnotation)
	jobGroup.POST("/:analysis_job_id/case-links", middleware.RequirePermission(databasePool, permissionManageDeepfakeForensics), handler.CreateCaseLink)

	reportGroup := forensicsGroup.Group("/forensic-reports")
	reportGroup.GET("", middleware.RequirePermission(databasePool, permissionViewDeepfakeForensics), handler.ListMediaForensicReports)
	reportGroup.GET("/:report_id", middleware.RequirePermission(databasePool, permissionViewDeepfakeForensics), handler.GetMediaForensicReport)
	reportGroup.POST("/:report_id/approve", middleware.RequirePermission(databasePool, permissionManageDeepfakeForensics), handler.ApproveMediaForensicReport)
	reportGroup.POST("/:report_id/access-password", middleware.RequirePermission(databasePool, permissionManageDeepfakeForensics), handler.SetMediaForensicReportAccessPassword)
	reportGroup.POST("/:report_id/preview", middleware.RequirePermission(databasePool, permissionViewDeepfakeForensics), handler.PreviewMediaForensicReport)
	reportGroup.POST("/:report_id/download", middleware.RequirePermission(databasePool, permissionViewDeepfakeForensics), handler.DownloadMediaForensicReport)

	modelGroup := forensicsGroup.Group(
		"/models",
	)

	modelGroup.GET(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionViewDeepfakeForensics,
		),
		handler.ListManagedAIModels,
	)

	modelGroup.GET(
		"/:model_id",
		middleware.RequirePermission(
			databasePool,
			permissionViewDeepfakeForensics,
		),
		handler.GetManagedAIModel,
	)

	modelGroup.POST(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.UploadManagedAIModel,
	)

	modelGroup.POST(
		"/:model_id/versions",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.UploadManagedAIModelVersion,
	)

	modelGroup.POST(
		"/:model_id/versions/:model_version_id/activate",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.ActivateManagedAIModelVersion,
	)

	modelGroup.POST(
		"/:model_id/rollback",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.RollbackManagedAIModelVersion,
	)

	modelGroup.POST(
		"/:model_id/assignments",
		middleware.RequirePermission(
			databasePool,
			permissionManageDeepfakeForensics,
		),
		handler.AssignManagedAIModelVersion,
	)

	trainingGroup := forensicsGroup.Group("/training")
	trainingGroup.POST("/datasets", middleware.RequirePermission(databasePool, permissionManageDeepfakeForensics), handler.RegisterTrainingDataset)
	trainingGroup.GET("/datasets", middleware.RequirePermission(databasePool, permissionViewDeepfakeForensics), handler.ListTrainingDatasets)
	trainingGroup.POST("/datasets/:dataset_id/versions", middleware.RequirePermission(databasePool, permissionManageDeepfakeForensics), handler.RegisterTrainingDatasetVersion)
	trainingGroup.POST("/datasets/:dataset_id/versions/:dataset_version_id/validate", middleware.RequirePermission(databasePool, permissionManageDeepfakeForensics), handler.ValidateTrainingDatasetVersion)
	trainingGroup.POST("/jobs", middleware.RequirePermission(databasePool, permissionManageDeepfakeForensics), handler.CreateTrainingJob)
	trainingGroup.GET("/jobs", middleware.RequirePermission(databasePool, permissionViewDeepfakeForensics), handler.ListTrainingJobs)
	trainingGroup.GET("/jobs/:training_job_id", middleware.RequirePermission(databasePool, permissionViewDeepfakeForensics), handler.GetTrainingJob)
	trainingGroup.POST("/jobs/:training_job_id/cancel", middleware.RequirePermission(databasePool, permissionManageDeepfakeForensics), handler.CancelTrainingJob)
	trainingGroup.POST("/jobs/:training_job_id/approval", middleware.RequirePermission(databasePool, permissionManageDeepfakeForensics), handler.DecideTrainingApproval)
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
		handler.queryService == nil ||
		handler.trustService == nil ||
		handler.modelService == nil ||
		handler.trainingService == nil ||
		handler.policyService == nil {
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
