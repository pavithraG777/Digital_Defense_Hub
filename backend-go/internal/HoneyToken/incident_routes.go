package honeytoken

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

const incidentsRoutePath = "/incidents"

// RegisterIncidentRoutes registers authenticated, permission-protected
// Incident Engine endpoints.
func RegisterIncidentRoutes(
	protectedRouter *gin.RouterGroup,
	handler *IncidentHandler,
	databasePool *pgxpool.Pool,
) {
	validateIncidentRouteDependencies(
		protectedRouter,
		handler,
		databasePool,
	)

	incidents := protectedRouter.Group(
		incidentsRoutePath,
	)

	incidents.POST(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.CreateIncident,
	)

	incidents.GET(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionHoneytokenView,
		),
		handler.ListIncidents,
	)

	incidents.GET(
		"/:id",
		middleware.RequirePermission(
			databasePool,
			permissionHoneytokenView,
		),
		handler.GetIncident,
	)

	incidents.PATCH(
		"/:id/assignment",
		middleware.RequirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.AssignIncident,
	)

	incidents.PATCH(
		"/:id/status",
		middleware.RequirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.UpdateIncidentStatus,
	)

	incidents.PATCH(
		"/:id/investigation",
		middleware.RequirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.UpdateIncidentInvestigation,
	)

	incidents.POST(
		"/:id/threats",
		middleware.RequirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.LinkIncidentThreat,
	)

	incidents.GET(
		"/:id/threats",
		middleware.RequirePermission(
			databasePool,
			permissionHoneytokenView,
		),
		handler.ListIncidentThreats,
	)

	incidents.GET(
		"/:id/timeline",
		middleware.RequirePermission(
			databasePool,
			permissionHoneytokenView,
		),
		handler.ListIncidentTimeline,
	)

	incidents.POST(
		"/:id/timeline/notes",
		middleware.RequirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.AddIncidentTimelineNote,
	)

	incidents.POST(
		"/:id/evidence",
		middleware.RequirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.AddIncidentEvidence,
	)

	incidents.GET(
		"/:id/evidence",
		middleware.RequirePermission(
			databasePool,
			permissionHoneytokenView,
		),
		handler.ListIncidentEvidence,
	)

	incidents.GET(
		"/:id/evidence/:evidenceId",
		middleware.RequirePermission(
			databasePool,
			permissionHoneytokenView,
		),
		handler.GetIncidentEvidence,
	)

	incidents.POST(
		"/:id/evidence/:evidenceId/verify",
		middleware.RequirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.VerifyIncidentEvidence,
	)
}

func validateIncidentRouteDependencies(
	protectedRouter *gin.RouterGroup,
	handler *IncidentHandler,
	databasePool *pgxpool.Pool,
) {
	if protectedRouter == nil {
		panic(errors.New(
			"incident route group is required",
		))
	}

	if handler == nil ||
		!handler.isAvailable() {
		panic(errors.New(
			"incident handler is required",
		))
	}

	if databasePool == nil {
		panic(errors.New(
			"incident database pool is required",
		))
	}
}
