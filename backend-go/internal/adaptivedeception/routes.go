package adaptivedeception

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

const (
	adaptiveDeceptionRoute = "/adaptive-deception"

	permissionViewAdaptiveDeception = "THREAT_VIEW"

	permissionManageAdaptiveDeception = "ORGANIZATION_MANAGE_SECURITY"
)

// RegisterHealthRoutes adds authenticated canary-health
// monitoring endpoints.
func RegisterHealthRoutes(
	protectedRouter *gin.RouterGroup,
	handler *HealthHandler,
	databasePool *pgxpool.Pool,
) {
	validateHealthRouteDependencies(
		protectedRouter,
		handler,
		databasePool,
	)

	adaptiveGroup :=
		protectedRouter.Group(
			adaptiveDeceptionRoute,
		)

	canaryGroup :=
		adaptiveGroup.Group(
			"/canaries",
		)

	canaryGroup.POST(
		"/:canary_file_id/health-check",
		middleware.RequirePermission(
			databasePool,
			permissionManageAdaptiveDeception,
		),
		handler.CheckCanaryHealth,
	)

	canaryGroup.GET(
		"/:canary_file_id/health",
		middleware.RequirePermission(
			databasePool,
			permissionViewAdaptiveDeception,
		),
		handler.GetCanaryHealth,
	)
}

func validateHealthRouteDependencies(
	protectedRouter *gin.RouterGroup,
	handler *HealthHandler,
	databasePool *pgxpool.Pool,
) {
	if protectedRouter == nil {
		panic(
			"protected router group is required",
		)
	}

	if handler == nil ||
		!handler.isAvailable() {
		panic(
			"adaptive deception health handler is required",
		)
	}

	if databasePool == nil {
		panic(
			"database pool is required for adaptive deception routes",
		)
	}
}

// RegisterRotationRoutes adds authenticated dynamic
// canary rotation endpoints.
func RegisterRotationRoutes(
	protectedRouter *gin.RouterGroup,
	handler *RotationHandler,
	databasePool *pgxpool.Pool,
) {
	validateRotationRouteDependencies(
		protectedRouter,
		handler,
		databasePool,
	)

	adaptiveGroup :=
		protectedRouter.Group(
			adaptiveDeceptionRoute,
		)

	canaryGroup :=
		adaptiveGroup.Group(
			"/canaries",
		)

	canaryGroup.POST(
		"/:canary_file_id/rotate",
		middleware.RequirePermission(
			databasePool,
			permissionManageAdaptiveDeception,
		),
		handler.RotateCanary,
	)

	rotationGroup :=
		adaptiveGroup.Group(
			"/rotations",
		)

	rotationGroup.GET(
		"/:rotation_id",
		middleware.RequirePermission(
			databasePool,
			permissionViewAdaptiveDeception,
		),
		handler.GetRotation,
	)
}

func validateRotationRouteDependencies(
	protectedRouter *gin.RouterGroup,
	handler *RotationHandler,
	databasePool *pgxpool.Pool,
) {
	if protectedRouter == nil {
		panic(
			"protected router group is required",
		)
	}

	if handler == nil ||
		!handler.isAvailable() {
		panic(
			"adaptive deception rotation handler is required",
		)
	}

	if databasePool == nil {
		panic(
			"database pool is required for adaptive deception rotation routes",
		)
	}
}

// RegisterFingerprintRoutes adds authenticated canary
// interaction fingerprint query endpoints.
func RegisterFingerprintRoutes(
	protectedRouter *gin.RouterGroup,
	handler *FingerprintHandler,
	databasePool *pgxpool.Pool,
) {
	validateFingerprintRouteDependencies(
		protectedRouter,
		handler,
		databasePool,
	)

	adaptiveGroup :=
		protectedRouter.Group(
			adaptiveDeceptionRoute,
		)

	fingerprintGroup :=
		adaptiveGroup.Group(
			"/fingerprints",
		)

	fingerprintGroup.GET(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionViewAdaptiveDeception,
		),
		handler.ListFingerprints,
	)

	fingerprintGroup.GET(
		"/:fingerprint_id",
		middleware.RequirePermission(
			databasePool,
			permissionViewAdaptiveDeception,
		),
		handler.GetFingerprint,
	)
}

func validateFingerprintRouteDependencies(
	protectedRouter *gin.RouterGroup,
	handler *FingerprintHandler,
	databasePool *pgxpool.Pool,
) {
	if protectedRouter == nil {
		panic(
			"protected router group is required",
		)
	}

	if handler == nil ||
		!handler.isAvailable() {
		panic(
			"adaptive deception fingerprint handler is required",
		)
	}

	if databasePool == nil {
		panic(
			"database pool is required for adaptive deception fingerprint routes",
		)
	}
}
