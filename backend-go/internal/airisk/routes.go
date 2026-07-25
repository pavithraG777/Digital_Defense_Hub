package airisk

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

func RegisterRoutes(
	protected *gin.RouterGroup,
	handler *RiskScoreHandler,
	databasePool *pgxpool.Pool,
) {
	if protected == nil ||
		handler == nil ||
		databasePool == nil {
		return
	}

	riskGroup := protected.Group(
		"/ai-risk",
	)

	riskGroup.POST(
		"/incidents/:incident_id/calculate",
		middleware.RequirePermission(
			databasePool,
			"AI_ANALYSIS_EXECUTE",
		),
		handler.CalculateIncidentRisk,
	)

	riskGroup.GET(
		"/incidents/:incident_id/active",
		middleware.RequirePermission(
			databasePool,
			"AI_ANALYSIS_VIEW",
		),
		handler.GetActiveIncidentRiskScore,
	)

	riskGroup.GET(
		"/scores",
		middleware.RequirePermission(
			databasePool,
			"AI_ANALYSIS_VIEW",
		),
		handler.ListRiskScores,
	)

	riskGroup.GET(
		"/scores/:risk_score_id",
		middleware.RequirePermission(
			databasePool,
			"AI_ANALYSIS_VIEW",
		),
		handler.GetRiskScore,
	)

	riskGroup.GET(
		"/engine/health",
		middleware.RequirePermission(
			databasePool,
			"AI_ANALYSIS_VIEW",
		),
		handler.CheckRiskEngineHealth,
	)
}
