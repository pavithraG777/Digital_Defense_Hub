package notification

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

const (
	notificationsRoute   = "/notifications"
	myNotificationsRoute = "/my-notifications"

	permissionManageNotifications = "ORGANIZATION_MANAGE_SECURITY"
)

// RegisterRoutes registers organization notification management routes and
// authenticated user notification routes.
//
// The supplied protectedRouter must already contain authentication,
// session-validation and audit middleware.
func RegisterRoutes(
	protectedRouter *gin.RouterGroup,
	handler *Handler,
	databasePool *pgxpool.Pool,
) {
	validateNotificationRouteDependencies(
		protectedRouter,
		handler,
		databasePool,
	)

	registerNotificationManagementRoutes(
		protectedRouter,
		handler,
		databasePool,
	)

	registerUserNotificationRoutes(
		protectedRouter,
		handler,
	)
}

func registerNotificationManagementRoutes(
	protectedRouter *gin.RouterGroup,
	handler *Handler,
	databasePool *pgxpool.Pool,
) {
	notifications := protectedRouter.Group(
		notificationsRoute,
	)

	notifications.POST(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionManageNotifications,
		),
		handler.CreateNotification,
	)

	notifications.GET(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionManageNotifications,
		),
		handler.ListNotifications,
	)

	notifications.GET(
		"/:id",
		middleware.RequirePermission(
			databasePool,
			permissionManageNotifications,
		),
		handler.GetNotification,
	)

	notifications.PATCH(
		"/:id/cancel",
		middleware.RequirePermission(
			databasePool,
			permissionManageNotifications,
		),
		handler.CancelNotification,
	)
}

func registerUserNotificationRoutes(
	protectedRouter *gin.RouterGroup,
	handler *Handler,
) {
	myNotifications := protectedRouter.Group(
		myNotificationsRoute,
	)

	myNotifications.GET(
		"",
		handler.ListMyNotifications,
	)

	myNotifications.PATCH(
		"/read-all",
		handler.MarkAllNotificationsRead,
	)

	myNotifications.PATCH(
		"/:id/read",
		handler.MarkNotificationRead,
	)

	myNotifications.PATCH(
		"/:id/acknowledge",
		handler.AcknowledgeNotification,
	)

	myNotifications.PATCH(
		"/:id/dismiss",
		handler.DismissNotification,
	)
}

func validateNotificationRouteDependencies(
	protectedRouter *gin.RouterGroup,
	handler *Handler,
	databasePool *pgxpool.Pool,
) {
	if protectedRouter == nil {
		panic(
			"protected router group is required for notification routes",
		)
	}

	if handler == nil ||
		!handler.isAvailable() {
		panic(
			"notification handler is required",
		)
	}

	if databasePool == nil {
		panic(
			"database pool is required for notification routes",
		)
	}
}
