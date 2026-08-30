package honeytoken

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

const (
	protectedFilesRoute = "/protected-files"
	encryptionKeysRoute = "/encryption-keys"
	honeytokensRoute    = "/honeytokens"
	canaryFilesRoute    = "/canary-files"
	fileEventsRoute     = "/file-events"

	permissionHoneytokenCreate           = "HONEYTOKEN_CREATE"
	permissionHoneytokenView             = "HONEYTOKEN_VIEW"
	permissionHoneytokenViewAccessLog    = "HONEYTOKEN_VIEW_ACCESS_LOG"
	permissionCanaryFileCreate           = "CANARY_FILE_CREATE"
	permissionCanaryFileView             = "CANARY_FILE_VIEW"
	permissionCanaryFileViewEvents       = "CANARY_FILE_VIEW_EVENTS"
	permissionOrganizationManageSecurity = "ORGANIZATION_MANAGE_SECURITY"
)

type permissionMiddlewareFactory func(
	db *pgxpool.Pool,
	requiredPermission string,
) gin.HandlerFunc

type anyPermissionMiddlewareFactory func(
	db *pgxpool.Pool,
	requiredPermissions ...string,
) gin.HandlerFunc

// RegisterRoutes adds protected-file endpoints to an authenticated parent
// route group. Authentication, session validation and audit middleware must
// already be configured on the supplied parent group.
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

	protectedFiles := protectedRouter.Group(
		protectedFilesRoute,
	)

	protectedFiles.POST(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionHoneytokenCreate,
		),
		handler.RegisterProtectedFile,
	)

	protectedFiles.GET(
		"/:id",
		middleware.RequirePermission(
			databasePool,
			permissionHoneytokenView,
		),
		handler.GetProtectedFile,
	)

	protectedFiles.POST(
		"/:id/restore",
		middleware.RequirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.RestoreProtectedFile,
	)

	protectedFiles.POST(
		"/:id/restore/owner/start",
		handler.StartOwnerProtectedFileRestore,
	)

	protectedFiles.POST(
		"/:id/restore/owner",
		handler.RestoreProtectedFileOwner,
	)
}

// RegisterEncryptionKeyRoutes adds organization encryption-key endpoints to
// the authenticated security route group. Raw and encrypted key values are
// never returned by these handlers.
func RegisterEncryptionKeyRoutes(
	protectedRouter *gin.RouterGroup,
	handler *EncryptionKeyHandler,
	databasePool *pgxpool.Pool,
) {
	validateEncryptionKeyRouteDependencies(
		protectedRouter,
		handler,
		databasePool,
	)

	encryptionKeys := protectedRouter.Group(
		encryptionKeysRoute,
	)

	encryptionKeys.POST(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.CreateEncryptionKey,
	)

	encryptionKeys.GET(
		"/active",
		middleware.RequirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.GetActiveEncryptionKey,
	)
}

func validateRouteDependencies(
	protectedRouter *gin.RouterGroup,
	handler *Handler,
	databasePool *pgxpool.Pool,
) {
	if protectedRouter == nil {
		panic("protected router group is required")
	}

	if handler == nil || !handler.isAvailable() {
		panic("protected file handler is required")
	}

	if databasePool == nil {
		panic("database pool is required for protected file routes")
	}
}

func validateEncryptionKeyRouteDependencies(
	protectedRouter *gin.RouterGroup,
	handler *EncryptionKeyHandler,
	databasePool *pgxpool.Pool,
) {
	if protectedRouter == nil {
		panic("protected router group is required")
	}

	if handler == nil || !handler.isAvailable() {
		panic("encryption key handler is required")
	}

	if databasePool == nil {
		panic("database pool is required for encryption key routes")
	}
}

// RegisterHoneytokenRoutes adds organization-scoped honeytoken
// create, list and detail endpoints.
func RegisterHoneytokenRoutes(
	protectedRouter *gin.RouterGroup,
	handler *HoneytokenHandler,
	databasePool *pgxpool.Pool,
) {
	validateHoneytokenRouteDependencies(
		protectedRouter,
		handler,
		databasePool,
	)

	honeytokens := protectedRouter.Group(
		honeytokensRoute,
	)

	honeytokens.POST(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionHoneytokenCreate,
		),
		handler.CreateHoneytoken,
	)

	honeytokens.GET(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionHoneytokenView,
		),
		handler.ListHoneytokens,
	)

	honeytokens.GET(
		"/:id",
		middleware.RequirePermission(
			databasePool,
			permissionHoneytokenView,
		),
		handler.GetHoneytoken,
	)
	honeytokens.GET("/:id/investigation", middleware.RequirePermission(databasePool, permissionHoneytokenView), investigationSummary(databasePool, "honeytoken_id"))

	honeytokens.POST(
		"/:id/deploy",
		middleware.RequirePermission(databasePool, permissionOrganizationManageSecurity),
		handler.DeployHoneytoken,
	)

	honeytokens.PATCH(
		"/:id/status",
		middleware.RequirePermission(databasePool, permissionOrganizationManageSecurity),
		handler.DeactivateHoneytoken,
	)

	honeytokens.POST(
		"/:id/validate",
		middleware.RequirePermission(databasePool, permissionOrganizationManageSecurity),
		handler.ValidateHoneytoken,
	)
}

// RegisterCanaryRoutes adds canary generation, retrieval and deployment
// endpoints to the authenticated security route group.
func RegisterCanaryRoutes(
	protectedRouter *gin.RouterGroup,
	handler *CanaryHandler,
	databasePool *pgxpool.Pool,
) {
	registerCanaryRoutes(
		protectedRouter,
		handler,
		databasePool,
		middleware.RequirePermission,
	)
}

func registerCanaryRoutes(
	protectedRouter *gin.RouterGroup,
	handler *CanaryHandler,
	databasePool *pgxpool.Pool,
	requirePermission permissionMiddlewareFactory,
) {
	validateCanaryRouteDependencies(
		protectedRouter,
		handler,
		databasePool,
	)

	canaryFiles := protectedRouter.Group(
		canaryFilesRoute,
	)

	canaryFiles.POST(
		"",
		requirePermission(
			databasePool,
			permissionCanaryFileCreate,
		),
		handler.CreateCanaryFile,
	)

	canaryFiles.POST(
		"/import",
		requirePermission(
			databasePool,
			permissionCanaryFileCreate,
		),
		handler.ImportCanaryFile,
	)

	canaryFiles.GET(
		"",
		requirePermission(
			databasePool,
			permissionCanaryFileView,
		),
		handler.ListCanaryFiles,
	)

	canaryFiles.GET(
		"/:id",
		requirePermission(
			databasePool,
			permissionCanaryFileView,
		),
		handler.GetCanaryFile,
	)
	canaryFiles.GET("/:id/investigation", requirePermission(databasePool, permissionCanaryFileViewEvents), investigationSummary(databasePool, "canary_file_id"))

	canaryFiles.POST(
		"/:id/deploy",
		requirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.DeployCanaryFile,
	)

	canaryFiles.PATCH(
		"/:id/status",
		requirePermission(databasePool, permissionOrganizationManageSecurity),
		handler.DeactivateCanaryFile,
	)
}

// RegisterFileEventRoutes adds authenticated forensic event ingestion
// and timeline endpoints.
func RegisterFileEventRoutes(
	protectedRouter *gin.RouterGroup,
	handler *FileEventHandler,
	databasePool *pgxpool.Pool,
) {
	registerFileEventRoutes(
		protectedRouter,
		handler,
		databasePool,
		middleware.RequirePermission,
		middleware.RequireAnyPermission,
	)
}

func registerFileEventRoutes(
	protectedRouter *gin.RouterGroup,
	handler *FileEventHandler,
	databasePool *pgxpool.Pool,
	requirePermission permissionMiddlewareFactory,
	requireAnyPermission anyPermissionMiddlewareFactory,
) {
	validateFileEventRouteDependencies(
		protectedRouter,
		handler,
		databasePool,
	)

	fileEvents := protectedRouter.Group(
		fileEventsRoute,
	)

	fileEvents.POST(
		"",
		requirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.CreateFileEvent,
	)

	fileEvents.GET(
		"",
		requireAnyPermission(
			databasePool,
			permissionHoneytokenViewAccessLog,
			permissionCanaryFileViewEvents,
		),
		handler.ListFileEvents,
	)

	fileEvents.GET(
		"/:id",
		requireAnyPermission(
			databasePool,
			permissionHoneytokenViewAccessLog,
			permissionCanaryFileViewEvents,
		),
		handler.GetFileEvent,
	)
}

func validateHoneytokenRouteDependencies(
	protectedRouter *gin.RouterGroup,
	handler *HoneytokenHandler,
	databasePool *pgxpool.Pool,
) {
	if protectedRouter == nil {
		panic(
			"protected router group is required",
		)
	}

	if handler == nil || !handler.isAvailable() {
		panic(
			"honeytoken handler is required",
		)
	}

	if databasePool == nil {
		panic(
			"database pool is required for honeytoken routes",
		)
	}
}

func validateCanaryRouteDependencies(
	protectedRouter *gin.RouterGroup,
	handler *CanaryHandler,
	databasePool *pgxpool.Pool,
) {
	if protectedRouter == nil {
		panic("protected router group is required")
	}

	if handler == nil || !handler.isAvailable() {
		panic("canary handler is required")
	}

	if databasePool == nil {
		panic("database pool is required for canary routes")
	}
}

func validateFileEventRouteDependencies(
	protectedRouter *gin.RouterGroup,
	handler *FileEventHandler,
	databasePool *pgxpool.Pool,
) {
	if protectedRouter == nil {
		panic("protected router group is required")
	}

	if handler == nil || !handler.isAvailable() {
		panic("file event handler is required")
	}

	if databasePool == nil {
		panic("database pool is required for file event routes")
	}
}

const threatsRoute = "/threats"

// RegisterThreatRoutes adds organization-scoped Threat Engine endpoints to
// the authenticated security route group.
func RegisterThreatRoutes(
	protectedRouter *gin.RouterGroup,
	handler *ThreatHandler,
	databasePool *pgxpool.Pool,
) {
	validateThreatRouteDependencies(
		protectedRouter,
		handler,
		databasePool,
	)

	threats := protectedRouter.Group(threatsRoute)

	threats.GET(
		"",
		middleware.RequirePermission(
			databasePool,
			permissionHoneytokenView,
		),
		handler.ListThreats,
	)

	threats.GET(
		"/:id",
		middleware.RequirePermission(
			databasePool,
			permissionHoneytokenView,
		),
		handler.GetThreat,
	)

	threats.PATCH(
		"/:id/status",
		middleware.RequirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.UpdateThreatStatus,
	)

	threats.PATCH(
		"/:id/assignment",
		middleware.RequirePermission(
			databasePool,
			permissionOrganizationManageSecurity,
		),
		handler.AssignThreat,
	)
}

func validateThreatRouteDependencies(
	protectedRouter *gin.RouterGroup,
	handler *ThreatHandler,
	databasePool *pgxpool.Pool,
) {
	if protectedRouter == nil {
		panic("protected router group is required")
	}

	if handler == nil || !handler.isAvailable() {
		panic("threat handler is required")
	}

	if databasePool == nil {
		panic("database pool is required for threat routes")
	}
}
