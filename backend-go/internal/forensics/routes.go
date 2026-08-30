package forensics

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

const (
	forensicsRoute            = "/forensics"
	permissionViewForensics   = "THREAT_VIEW"
	permissionManageForensics = "THREAT_MANAGE"
)

func RegisterRoutes(
	protected *gin.RouterGroup,
	handler *Handler,
	databasePool *pgxpool.Pool,
) {
	if protected == nil || handler == nil || databasePool == nil {
		return
	}

	namespace := protected.Group(forensicsRoute)

	namespace.GET(
		"/health",
		middleware.RequirePermission(databasePool, permissionViewForensics),
		handler.Health,
	)

	namespace.POST(
		"/cases",
		middleware.RequirePermission(databasePool, permissionManageForensics),
		handler.CreateCase,
	)

	namespace.GET(
		"/cases",
		middleware.RequirePermission(databasePool, permissionViewForensics),
		handler.ListCases,
	)

	namespace.GET(
		"/cases/:case_id",
		middleware.RequirePermission(databasePool, permissionViewForensics),
		handler.GetCase,
	)

	namespace.POST(
		"/cases/:case_id/evidence",
		middleware.RequirePermission(databasePool, permissionManageForensics),
		handler.AddEvidence,
	)

	namespace.GET(
		"/cases/:case_id/evidence",
		middleware.RequirePermission(databasePool, permissionViewForensics),
		handler.ListEvidence,
	)

	namespace.POST(
		"/analysis-results",
		middleware.RequirePermission(databasePool, permissionManageForensics),
		handler.CreateAnalysisResult,
	)

	namespace.GET(
		"/analysis-results/:analysis_job_id",
		middleware.RequirePermission(databasePool, permissionViewForensics),
		handler.GetAnalysisResult,
	)

	namespace.GET(
		"/analysis-results",
		middleware.RequirePermission(databasePool, permissionViewForensics),
		handler.ListAnalysisResults,
	)
}
