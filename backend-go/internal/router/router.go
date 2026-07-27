package router

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"

	honeytoken "github.com/pavithraG777/cyber-security-platform/backend/internal/HoneyToken"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/adaptivedeception"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/airisk"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/auditlog"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/auth"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/database"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/deepfakeforensics"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/health"
	appLogger "github.com/pavithraG777/cyber-security-platform/backend/internal/logger"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/notification"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/permission"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/preencryption"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/role"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/rolepermission"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/user"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/userrole"
)

func SetupRouter(
	db *database.Database,
	cfg *config.Config,
) *gin.Engine {
	configuredRouter,
		fileMonitorService,
		notificationModule,
		preEncryptionWorker,
		adaptiveDeceptionHealthWorker,
		adaptiveDeceptionFingerprintWorker,
		deepfakeForensicsWorker :=
		SetupRouterWithRuntime(db, cfg)

	runtimeContext := context.Background()

	if err := notificationModule.Start(
		runtimeContext,
	); err != nil {
		panic(fmt.Errorf(
			"failed to start notification worker: %w",
			err,
		))
	}

	if preEncryptionWorker != nil {
		if err := preEncryptionWorker.Start(
			runtimeContext,
		); err != nil {
			panic(fmt.Errorf(
				"failed to start pre-encryption worker: %w",
				err,
			))
		}
	}

	if adaptiveDeceptionFingerprintWorker != nil {
		if err :=
			adaptiveDeceptionFingerprintWorker.Start(
				runtimeContext,
			); err != nil {
			panic(fmt.Errorf(
				"failed to start adaptive deception fingerprint worker: %w",
				err,
			))
		}
	}

	if adaptiveDeceptionHealthWorker != nil {
		if err :=
			adaptiveDeceptionHealthWorker.Start(
				runtimeContext,
			); err != nil {
			panic(fmt.Errorf(
				"failed to start adaptive deception health worker: %w",
				err,
			))
		}
	}

	if deepfakeForensicsWorker != nil {
		if err :=
			deepfakeForensicsWorker.Start(
				runtimeContext,
			); err != nil {
			panic(fmt.Errorf(
				"failed to start deepfake forensics worker: %w",
				err,
			))
		}
	}

	if err := fileMonitorService.Start(
		runtimeContext,
	); err != nil {
		panic(fmt.Errorf(
			"failed to start file monitor service: %w",
			err,
		))
	}

	return configuredRouter
}

func SetupRouterWithRuntime(
	db *database.Database,
	cfg *config.Config,
) (
	*gin.Engine,
	*honeytoken.FileMonitorService,
	*notification.Module,
	*preencryption.Worker,
	*adaptivedeception.HealthWorker,
	*adaptivedeception.FingerprintWorker,
	*deepfakeforensics.AnalysisWorker,
) {
	router := gin.New()

	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.RequestID())
	router.Use(middleware.CORS())

	// Authentication dependencies
	authRepository := auth.NewRepository(db.Pool)

	// Audit log dependencies
	auditRepository := auditlog.NewRepository(db.Pool)
	auditService := auditlog.NewService(auditRepository)
	auditHandler := auditlog.NewHandler(auditService)

	// Permission dependencies
	permissionRepository := permission.NewRepository(db.Pool)
	permissionService := permission.NewService(permissionRepository)
	permissionHandler := permission.NewHandler(permissionService)

	// Role permission dependencies
	rolePermissionRepository := rolepermission.NewRepository(db.Pool)
	rolePermissionService := rolepermission.NewService(
		rolePermissionRepository,
	)
	rolePermissionHandler := rolepermission.NewHandler(
		rolePermissionService,
	)

	// User role dependencies
	userRoleRepository := userrole.NewRepository(db.Pool)
	userRoleService := userrole.NewService(userRoleRepository)
	userRoleHandler := userrole.NewHandler(userRoleService)

	jwtManager, err := auth.NewJWTManager(
		cfg.JWT.Secret,
		cfg.JWT.AccessTokenDuration,
		cfg.App.Name,
	)
	if err != nil {
		panic(err)
	}

	authService := auth.NewService(
		authRepository,
		jwtManager,
	)

	authHandler := auth.NewHandler(authService)

	// User management dependencies
	userRepository := user.NewRepository(db.Pool)
	userService := user.NewService(
		userRepository,
		auditService,
	)
	userHandler := user.NewHandler(userService)

	// Role management dependencies
	roleRepository := role.NewRepository(db.Pool)
	roleService := role.NewService(roleRepository)
	roleHandler := role.NewHandler(roleService)

	// Threat Engine dependencies.
	threatRepository := honeytoken.NewThreatRepository(
		db.Pool,
	)

	threatService, err := honeytoken.NewThreatService(
		threatRepository,
	)
	if err != nil {
		panic(fmt.Errorf(
			"failed to initialize threat service: %w",
			err,
		))
	}

	threatHandler := honeytoken.NewThreatHandler(
		threatService,
	)

	// Incident Engine API dependencies.
	incidentRepository := honeytoken.NewIncidentRepository(
		db.Pool,
	)

	incidentService, incidentServiceErr :=
		honeytoken.NewIncidentService(
			incidentRepository,
		)
	if incidentServiceErr != nil {
		panic(fmt.Errorf(
			"failed to initialize incident service: %w",
			incidentServiceErr,
		))
	}

	incidentHandler := honeytoken.NewIncidentHandler(
		incidentService,
	)

	incidentAutomationService, incidentAutomationErr :=
		honeytoken.NewIncidentAutomationService(
			incidentRepository,
		)
	if incidentAutomationErr != nil {
		panic(fmt.Errorf(
			"failed to initialize incident automation service: %w",
			incidentAutomationErr,
		))
	}

	// AI Ransomware Risk Scoring dependencies.
	var riskScoreHandler *airisk.RiskScoreHandler

	if cfg.AIRisk.Enabled {
		riskScoreRepository := airisk.NewRepository(
			db.Pool,
		)

		riskEngineClient, riskEngineClientErr :=
			airisk.NewRiskEngineClient(
				cfg.AIRisk.EngineURL,
				cfg.AIRisk.ServiceToken,
				cfg.AIRisk.Timeout,
			)
		if riskEngineClientErr != nil {
			panic(fmt.Errorf(
				"failed to initialize AI Risk Engine client: %w",
				riskEngineClientErr,
			))
		}

		riskScoreService, riskScoreServiceErr :=
			airisk.NewService(
				riskScoreRepository,
				riskEngineClient,
				cfg.AIRisk.DefaultValidity,
			)
		if riskScoreServiceErr != nil {
			panic(fmt.Errorf(
				"failed to initialize AI Risk Score service: %w",
				riskScoreServiceErr,
			))
		}

		riskScoreHandler =
			airisk.NewRiskScoreHandler(
				riskScoreService,
			)
	}
	threatEngine, err := honeytoken.NewThreatEngine(
		threatRepository,
	)
	if err != nil {
		panic(fmt.Errorf(
			"failed to initialize Threat Engine: %w",
			err,
		))
	}

	threatWorker, err := honeytoken.NewThreatWorker(
		threatEngine,
		appLogger.Log,
		0,
		0,
	)
	if err != nil {
		panic(fmt.Errorf(
			"failed to initialize Threat Engine worker: %w",
			err,
		))
	}
	threatWorker.SetIncidentAutomationService(
		incidentAutomationService,
	)

	preEncryptionWorker,
		preEncryptionHandler,
		preEncryptionModuleErr :=
		initializePreEncryptionModule(
			db.Pool,
			cfg,
			appLogger.Log,
		)
	if preEncryptionModuleErr != nil {
		panic(fmt.Errorf(
			"failed to initialize pre-encryption module: %w",
			preEncryptionModuleErr,
		))
	}

	protectedFileHandler,
		encryptionKeyHandler,
		honeytokenHandler,
		canaryHandler,
		fileEventHandler,
		fileMonitorService,
		err := initializeHoneytokenModule(
		db.Pool,
		cfg.Storage.CanaryStoragePath,
		cfg.Storage.CanaryDeploymentRoot,
		threatWorker,
		preEncryptionWorker,
	)
	if err != nil {
		panic(err)
	}

	adaptiveDeceptionHealthWorker,
		adaptiveDeceptionFingerprintWorker,
		adaptiveDeceptionHealthHandler,
		adaptiveDeceptionRotationHandler,
		adaptiveDeceptionFingerprintHandler,
		adaptiveDeceptionModuleErr :=
		initializeAdaptiveDeceptionModule(
			db.Pool,
			cfg,
			appLogger.Log,
			fileMonitorService,
		)
	if adaptiveDeceptionModuleErr != nil {
		panic(fmt.Errorf(
			"failed to initialize adaptive deception module: %w",
			adaptiveDeceptionModuleErr,
		))
	}

	deepfakeForensicsHandler,
		deepfakeForensicsWorker,
		deepfakeForensicsModuleErr :=
		initializeDeepfakeForensicsModule(
			db.Pool,
			cfg,
			appLogger.Log,
		)
	if deepfakeForensicsModuleErr != nil {
		panic(fmt.Errorf(
			"failed to initialize deepfake forensics module: %w",
			deepfakeForensicsModuleErr,
		))
	}

	notificationModule, err :=
		notification.NewModule(
			db.Pool,
			cfg.Notification,
			appLogger.Log,
		)
	if err != nil {
		panic(fmt.Errorf(
			"failed to initialize notification module: %w",
			err,
		))
	}

	threatNotificationPublisher, publisherErr :=
		newSecurityNotificationPublisher(
			notificationModule.SecurityNotifications,
		)
	if publisherErr != nil {
		panic(fmt.Errorf(
			"failed to initialize Threat Engine notification publisher: %w",
			publisherErr,
		))
	}

	threatWorker.SetSecurityNotificationPublisher(
		threatNotificationPublisher,
	)

	if deepfakeForensicsWorker != nil {
		mediaTrustPublisher, mediaPublisherErr :=
			newMediaTrustEscalationPublisher(
				incidentService,
				notificationModule.SecurityNotifications,
			)
		if mediaPublisherErr != nil {
			panic(fmt.Errorf(
				"failed to initialize media trust escalation publisher: %w",
				mediaPublisherErr,
			))
		}

		deepfakeForensicsWorker.
			SetMediaTrustEscalationPublisher(
				mediaTrustPublisher,
			)
	}

	api := router.Group("/api")
	v1 := api.Group("/v1")

	// Public routes
	v1.GET("/health", health.HealthCheck)

	authGroup := v1.Group("/auth")
	{
		authGroup.POST("/login", authHandler.Login)

		authGroup.POST(
			"/refresh",
			authHandler.RefreshAccessToken,
		)

		authGroup.POST(
			"/revoke-refresh-token",
			authHandler.RevokeRefreshToken,
		)
	}

	// Protected routes
	protected := v1.Group("")

	protected.Use(
		middleware.Authenticate(jwtManager),
	)

	protected.Use(
		middleware.ValidateSession(authRepository),
	)

	protected.Use(
		auditlog.Middleware(auditService),
	)

	honeytoken.RegisterRoutes(
		protected,
		protectedFileHandler,
		db.Pool,
	)

	honeytoken.RegisterEncryptionKeyRoutes(
		protected,
		encryptionKeyHandler,
		db.Pool,
	)

	honeytoken.RegisterHoneytokenRoutes(
		protected,
		honeytokenHandler,
		db.Pool,
	)

	honeytoken.RegisterCanaryRoutes(
		protected,
		canaryHandler,
		db.Pool,
	)

	honeytoken.RegisterFileEventRoutes(
		protected,
		fileEventHandler,
		db.Pool,
	)

	honeytoken.RegisterThreatRoutes(
		protected,
		threatHandler,
		db.Pool,
	)

	honeytoken.RegisterIncidentRoutes(
		protected,
		incidentHandler,
		db.Pool,
	)

	airisk.RegisterRoutes(
		protected,
		riskScoreHandler,
		db.Pool,
	)

	preencryption.RegisterRoutes(
		protected,
		preEncryptionHandler,
		db.Pool,
	)

	if adaptiveDeceptionHealthHandler != nil {
		adaptivedeception.RegisterHealthRoutes(
			protected,
			adaptiveDeceptionHealthHandler,
			db.Pool,
		)
	}

	if adaptiveDeceptionRotationHandler != nil {
		adaptivedeception.RegisterRotationRoutes(
			protected,
			adaptiveDeceptionRotationHandler,
			db.Pool,
		)
	}

	if adaptiveDeceptionFingerprintHandler != nil {
		adaptivedeception.RegisterFingerprintRoutes(
			protected,
			adaptiveDeceptionFingerprintHandler,
			db.Pool,
		)
	}

	if deepfakeForensicsHandler != nil {
		deepfakeforensics.RegisterRoutes(
			protected,
			deepfakeForensicsHandler,
			db.Pool,
		)
	}

	notification.RegisterRoutes(
		protected,
		notificationModule.Handler,
		db.Pool,
	)

	{
		protected.GET("/profile", authHandler.Profile)

		{
			protected.POST(
				"/auth/logout",
				authHandler.Logout,
			)

			protected.POST(
				"/auth/logout-all",
				authHandler.LogoutAllSessions,
			)

			protected.POST(
				"/change-password",
				authHandler.ChangePassword,
			)

			protected.POST(
				"/auth/forgot-password",
				authHandler.ForgotPassword,
			)

			protected.POST(
				"/auth/reset-password",
				authHandler.ResetPassword,
			)

			admin := protected.Group("/admin")
			{
				admin.GET(
					"/dashboard",
					middleware.RequirePermission(
						db.Pool,
						"DASHBOARD_VIEW",
					),
					func(c *gin.Context) {
						c.JSON(http.StatusOK, gin.H{
							"success": true,
							"message": "Welcome to Security Dashboard",
						})
					},
				)

				// User management routes
				admin.POST(
					"/users",
					middleware.RequirePermission(
						db.Pool,
						"USER_CREATE",
					),
					userHandler.CreateUser,
				)

				admin.GET(
					"/users",
					middleware.RequirePermission(
						db.Pool,
						"USER_VIEW",
					),
					userHandler.ListUsers,
				)

				admin.GET(
					"/users/:id",
					middleware.RequirePermission(
						db.Pool,
						"USER_VIEW_DETAILS",
					),
					userHandler.GetUserByID,
				)

				admin.PUT(
					"/users/:id",
					middleware.RequirePermission(
						db.Pool,
						"USER_UPDATE",
					),
					userHandler.UpdateUser,
				)

				// Role management routes
				admin.POST(
					"/roles",
					middleware.RequirePermission(
						db.Pool,
						"ROLE_CREATE",
					),
					roleHandler.CreateRole,
				)

				admin.GET(
					"/roles",
					middleware.RequirePermission(
						db.Pool,
						"ROLE_VIEW",
					),
					roleHandler.ListRoles,
				)

				admin.GET(
					"/roles/:id",
					middleware.RequirePermission(
						db.Pool,
						"ROLE_VIEW",
					),
					roleHandler.GetRoleByID,
				)

				admin.PUT(
					"/roles/:id",
					middleware.RequirePermission(
						db.Pool,
						"ROLE_UPDATE",
					),
					roleHandler.UpdateRole,
				)

				admin.DELETE(
					"/roles/:id",
					middleware.RequirePermission(
						db.Pool,
						"ROLE_DELETE",
					),
					roleHandler.DeleteRole,
				)

				// Permission management routes
				admin.POST(
					"/permissions",
					middleware.RequirePermission(
						db.Pool,
						"PERMISSION_CREATE",
					),
					permissionHandler.CreatePermission,
				)

				admin.GET(
					"/permissions",
					middleware.RequirePermission(
						db.Pool,
						"PERMISSION_VIEW",
					),
					permissionHandler.ListPermissions,
				)

				admin.GET(
					"/permissions/:id",
					middleware.RequirePermission(
						db.Pool,
						"PERMISSION_VIEW",
					),
					permissionHandler.GetPermissionByID,
				)

				admin.PUT(
					"/permissions/:id",
					middleware.RequirePermission(
						db.Pool,
						"PERMISSION_UPDATE",
					),
					permissionHandler.UpdatePermission,
				)

				admin.DELETE(
					"/permissions/:id",
					middleware.RequirePermission(
						db.Pool,
						"PERMISSION_DISABLE",
					),
					permissionHandler.DeletePermission,
				)

				// Role permission management routes
				admin.POST(
					"/roles/:id/permissions",
					middleware.RequirePermission(
						db.Pool,
						"ROLE_MANAGE_PERMISSIONS",
					),
					rolePermissionHandler.AssignPermissions,
				)

				admin.GET(
					"/roles/:id/permissions",
					middleware.RequirePermission(
						db.Pool,
						"ROLE_VIEW_PERMISSIONS",
					),
					rolePermissionHandler.ListRolePermissions,
				)

				admin.DELETE(
					"/roles/:id/permissions",
					middleware.RequirePermission(
						db.Pool,
						"ROLE_MANAGE_PERMISSIONS",
					),
					rolePermissionHandler.RemovePermission,
				)

				admin.PUT(
					"/roles/:id/permissions",
					middleware.RequirePermission(
						db.Pool,
						"ROLE_MANAGE_PERMISSIONS",
					),
					rolePermissionHandler.ReplacePermissions,
				)

				// User role management routes
				admin.POST(
					"/users/:id/roles",
					middleware.RequirePermission(
						db.Pool,
						"ROLE_ASSIGN",
					),
					userRoleHandler.AssignRoles,
				)

				admin.GET(
					"/users/:id/roles",
					middleware.RequirePermission(
						db.Pool,
						"ROLE_VIEW",
					),
					userRoleHandler.ListUserRoles,
				)

				admin.DELETE(
					"/users/:id/roles",
					middleware.RequirePermission(
						db.Pool,
						"ROLE_REVOKE",
					),
					userRoleHandler.RemoveRole,
				)

				admin.PUT(
					"/users/:id/roles",
					middleware.RequirePermission(
						db.Pool,
						"ROLE_ASSIGN",
					),
					userRoleHandler.ReplaceRoles,
				)

				admin.GET(
					"/audit-logs",
					middleware.RequirePermission(
						db.Pool,
						"AUDIT_VIEW",
					),
					auditHandler.ListAuditLogs,
				)

				admin.GET(
					"/audit-logs/:id",
					middleware.RequirePermission(
						db.Pool,
						"AUDIT_VIEW",
					),
					auditHandler.GetAuditLogByID,
				)
			}
		}

		return router,
			fileMonitorService,
			notificationModule,
			preEncryptionWorker,
			adaptiveDeceptionHealthWorker,
			adaptiveDeceptionFingerprintWorker,
			deepfakeForensicsWorker
	}
}

func initializeHoneytokenModule(
	databasePool *pgxpool.Pool,
	canaryStoragePath string,
	canaryDeploymentRoot string,
	threatWorker *honeytoken.ThreatWorker,
	preEncryptionWorker *preencryption.Worker,
) (
	*honeytoken.Handler,
	*honeytoken.EncryptionKeyHandler,
	*honeytoken.HoneytokenHandler,
	*honeytoken.CanaryHandler,
	*honeytoken.FileEventHandler,
	*honeytoken.FileMonitorService,
	error,
) {
	if databasePool == nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(
			"database pool is required for honeytoken module",
		)
	}

	if threatWorker == nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(
			"Threat Engine worker is required",
		)
	}

	keyEncryptionMasterKey, err :=
		decodeRequiredAES256Key(
			"KEY_ENCRYPTION_MASTER_KEY",
		)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	defer clear(keyEncryptionMasterKey)

	honeytokenRepository := honeytoken.NewRepository(
		databasePool,
	)

	encryptionKeyService, err :=
		honeytoken.NewEncryptionKeyService(
			honeytokenRepository,
			keyEncryptionMasterKey,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(
			"failed to initialize encryption key service: %w",
			err,
		)
	}

	protectedFileService :=
		honeytoken.NewProtectedFileService(
			honeytokenRepository,
			encryptionKeyService,
		)

	protectedFileHandler := honeytoken.NewHandler(
		protectedFileService,
	)

	encryptionKeyHandler :=
		honeytoken.NewEncryptionKeyHandler(
			encryptionKeyService,
		)

	honeytokenGenerator, err :=
		honeytoken.NewHoneytokenGenerator(
			encryptionKeyService,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(
			"failed to initialize honeytoken generator: %w",
			err,
		)
	}

	honeytokenService, err :=
		honeytoken.NewHoneytokenService(
			honeytokenRepository,
			honeytokenGenerator,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(
			"failed to initialize honeytoken service: %w",
			err,
		)
	}

	honeytokenHandler := honeytoken.NewHoneytokenHandler(
		honeytokenService,
	)

	canaryGenerator, err :=
		honeytoken.NewCanaryGenerator(
			canaryStoragePath,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(
			"failed to initialize canary generator: %w",
			err,
		)
	}

	canaryService, err := honeytoken.NewCanaryService(
		honeytokenRepository,
		canaryGenerator,
		canaryDeploymentRoot,
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(
			"failed to initialize canary service: %w",
			err,
		)
	}

	canaryHandler := honeytoken.NewCanaryHandler(
		canaryService,
	)

	fileEventService, err :=
		honeytoken.NewFileEventService(
			honeytokenRepository,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(
			"failed to initialize file event service: %w",
			err,
		)
	}

	if err = fileEventService.SetThreatWorker(
		threatWorker,
	); err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(
			"failed to connect File Event Service to Threat Engine: %w",
			err,
		)
	}

	if preEncryptionWorker != nil {
		if err = fileEventService.SetPreEncryptionWorker(
			preEncryptionWorker,
		); err != nil {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf(
				"failed to connect File Event Service to Pre-Encryption Engine: %w",
				err,
			)
		}
	}

	fileEventHandler :=
		honeytoken.NewFileEventHandler(
			fileEventService,
		)

	fileMonitorService, err :=
		honeytoken.NewFileMonitorService(
			honeytokenRepository,
			fileEventService,
			appLogger.Log,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(
			"failed to initialize file monitor service: %w",
			err,
		)
	}

	if err = fileMonitorService.SetThreatWorker(
		threatWorker,
	); err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf(
			"failed to connect File Monitor Service to Threat Engine: %w",
			err,
		)
	}

	return protectedFileHandler,
		encryptionKeyHandler,
		honeytokenHandler,
		canaryHandler,
		fileEventHandler,
		fileMonitorService,
		nil
}
func decodeRequiredAES256Key(
	configName string,
) ([]byte, error) {
	encodedKey := strings.TrimSpace(
		viper.GetString(configName),
	)
	if encodedKey == "" {
		return nil, fmt.Errorf(
			"%s is required",
			configName,
		)
	}

	key, err := base64.StdEncoding.
		Strict().
		DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf(
			"%s must be valid Base64: %w",
			configName,
			err,
		)
	}

	const aes256KeySize = 32

	if len(key) != aes256KeySize {
		clear(key)

		return nil, fmt.Errorf(
			"%s must decode to exactly %d bytes",
			configName,
			aes256KeySize,
		)
	}

	return key, nil
}
