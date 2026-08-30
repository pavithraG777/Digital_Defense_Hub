package honeytoken

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

// RegisterInvestigationCaseRoutes registers tenant-isolated investigation workspace routes.
func RegisterInvestigationCaseRoutes(protected *gin.RouterGroup, handler *InvestigationCaseHandler, db *pgxpool.Pool) {
	if protected == nil || handler == nil || !handler.available() || db == nil {
		panic(errors.New("investigation case route dependencies are required"))
	}
	cases := protected.Group("/investigation-cases")
	manage := middleware.RequirePermission(db, permissionOrganizationManageSecurity)
	view := middleware.RequirePermission(db, permissionHoneytokenView)
	cases.POST("", manage, handler.Create)
	cases.GET("", view, handler.List)
	cases.GET("/:id", view, handler.Get)
	cases.PATCH("/:id", manage, handler.Update)
	cases.POST("/:id/incidents", manage, handler.LinkIncident)
	cases.GET("/:id/incidents", view, handler.ListIncidents)
}
