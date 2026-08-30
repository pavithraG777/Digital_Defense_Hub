package router

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"

	honeytoken "github.com/pavithraG777/cyber-security-platform/backend/internal/HoneyToken"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/accesscontrol"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/adaptivedeception"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/airisk"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/alertmanagement"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/assetinventory"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/attackstory"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/attacksurface"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/attribution"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/audio"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/auditlog"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/auth"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/baseline"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/behavior"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/cloud"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/commandanalysis"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/compliance"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/configassessment"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/copilot"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/credentialabuse"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/database"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/dataexfiltration"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/deepfakeforensics"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/dfir"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/dlp"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/document"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/email"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/endpoint"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/evidencevault"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/face"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/forensics"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/governance"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/health"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/imageanalysis"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidentafteraction"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidentanalytics"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidentclosure"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidentengine"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidentescalation"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidentlearning"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidentmanagement"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidentorchestration"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidentremediation"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidentreporting"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidentresolution"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidentresponse"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidentreview"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/incidenttriage"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/insiderthreat"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/integration"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/intelligence"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/lateralmovement"
	appLogger "github.com/pavithraG777/cyber-security-platform/backend/internal/logger"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/malware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/memoryforensics"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/metadata"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/modelsecurity"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/networksecurity"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/notification"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/organization"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/permission"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/persistence"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/policy"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/preencryption"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/privilegeescalation"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/ransomware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/recovery"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/risk"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/role"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/rolepermission"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/securityevents"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/securitygraph"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/securitymonitoring"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/securityoperations"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/securityscore"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/simulation"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/surveillance"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/syncqueue"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/threatanalysis"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/threathunting"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/threatintel"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/threatmitigation"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/threatresponse"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/ueba"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/usb"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/user"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/useractivity"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/userrole"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/vulnerability"
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
		deepfakeForensicsWorker,
		dfirWorker :=
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

	if dfirWorker != nil {
		if err := dfirWorker.Start(runtimeContext); err != nil {
			panic(fmt.Errorf("failed to start dfir worker: %w", err))
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
	*dfir.Worker,
) {
	router := gin.New()

	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.RequestID())
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.CORS())

	// Authentication dependencies
	authRepository := auth.NewRepository(db.Pool)
	notificationModule, err := notification.NewModule(db.Pool, cfg.Notification, appLogger.Log)
	if err != nil {
		panic(fmt.Errorf("failed to initialize notification module: %w", err))
	}
	var mfaDelivery auth.MFAOTPDelivery
	if cfg.MFA.LocalDeliveryEnabled {
		mfaDelivery, err = notification.NewLocalMFAOTPDelivery(cfg.MFA.LocalOutboxPath)
	} else {
		mfaDelivery, err = notification.NewMFAOTPDelivery(notificationModule.Providers)
	}
	if err != nil {
		panic(fmt.Errorf("failed to initialize MFA delivery: %w", err))
	}

	// Audit log dependencies
	auditRepository := auditlog.NewRepository(db.Pool)
	auditService := auditlog.NewService(auditRepository)
	auditHandler := auditlog.NewHandler(auditService)

	// Register the request audit middleware on the engine so public security
	// mutations (login, MFA, token refresh and tenant registration) and all
	// protected routes share the same audit guarantee. Operational probe
	// endpoints are filtered by the middleware itself.
	router.Use(auditlog.Middleware(auditService))

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

	mfaMasterKey, err := auth.DecodeMFASecretMasterKey(cfg.MFA.MasterKey)
	if err != nil {
		panic(fmt.Errorf("failed to decode MFA master key: %w", err))
	}

	authService := auth.NewService(
		authRepository,
		jwtManager,
		mfaDelivery,
		mfaMasterKey,
	)

	authHandler := auth.NewHandler(authService)
	organizationHandler := organization.NewHandler(organization.NewService(db.Pool))

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

	dfirService := dfir.NewService()
	dfirHandler := dfir.NewHandler(dfirService, cfg.DFIRML)
	dfirWorker := dfir.NewWorker(dfirService, cfg.DFIRML.EngineURL, cfg.DFIRML.ServiceToken, cfg.DFIRML.Timeout)
	dfirHandler.SetWorker(dfirWorker)

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

	// Investigation workspace dependencies. Cases group related incidents
	// without compromising the existing incident evidence chain of custody.
	investigationCaseRepository := honeytoken.NewInvestigationCaseRepository(
		db.Pool,
	)
	investigationCaseService, investigationCaseServiceErr :=
		honeytoken.NewInvestigationCaseService(
			investigationCaseRepository,
		)
	if investigationCaseServiceErr != nil {
		panic(fmt.Errorf(
			"failed to initialize investigation case service: %w",
			investigationCaseServiceErr,
		))
	}
	investigationCaseHandler := honeytoken.NewInvestigationCaseHandler(
		investigationCaseService,
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
	attackStoryRepository, attackStoryRepositoryErr := attackstory.NewRepository(db.Pool)
	if attackStoryRepositoryErr != nil {
		panic(fmt.Errorf("failed to initialize automatic attack story repository: %w", attackStoryRepositoryErr))
	}
	if err = attackStoryRepository.EnsureSchema(context.Background()); err != nil {
		panic(fmt.Errorf("failed to initialize automatic attack story schema: %w", err))
	}
	attackStoryPublisher, attackStoryPublisherErr := newAttackStoryPublisher(attackStoryRepository)
	if attackStoryPublisherErr != nil {
		panic(fmt.Errorf("failed to initialize attack story publisher: %w", attackStoryPublisherErr))
	}
	threatWorker.SetAttackStoryPublisher(attackStoryPublisher)

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
		authRepository,
		mfaDelivery,
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
	v1.GET("/ready", health.Readiness(db.Pool))
	v1.GET("/metrics", health.Metrics(db.Pool))

	// Debug: report whether deepfake forensics module initialized (public, temporary)
	v1.GET("/_dbg/deepfake-forensics/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "deepfake forensics module debug",
			"data": gin.H{
				"handler_present": deepfakeForensicsHandler != nil,
				"worker_present":  deepfakeForensicsWorker != nil,
			},
		})
	})

	authGroup := v1.Group("/auth")
	{
		authGroup.POST("/login", authHandler.Login)
		authGroup.POST("/mfa/verify", authHandler.VerifyMFA)

		authGroup.POST(
			"/refresh",
			authHandler.RefreshAccessToken,
		)

		authGroup.POST(
			"/revoke-refresh-token",
			authHandler.RevokeRefreshToken,
		)
	}

	// Public tenant onboarding. Applications remain PENDING until a super
	// administrator explicitly approves them.
	v1.POST("/organizations/register", organizationHandler.Register)

	// Protected routes
	protected := v1.Group("")

	protected.Use(
		middleware.Authenticate(jwtManager),
	)

	protected.Use(
		middleware.ValidateSession(authRepository),
	)

	protected.Use(
		middleware.EnforcePasswordChange(authRepository),
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

	honeytoken.RegisterInvestigationCaseRoutes(
		protected,
		investigationCaseHandler,
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

	dfir.RegisterRoutes(
		protected,
		dfirHandler,
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

	forensicsHandler, forensicsHandlerErr := initializeForensicsModule(db.Pool)
	if forensicsHandlerErr != nil {
		panic(fmt.Errorf("failed to initialize forensics module: %w", forensicsHandlerErr))
	}
	if forensicsHandler != nil {
		forensics.RegisterRoutes(
			protected,
			forensicsHandler,
			db.Pool,
		)
	}

	notification.RegisterRoutes(
		protected,
		notificationModule.Handler,
		db.Pool,
	)

	syncqueue.RegisterRoutes(protected, db.Pool)
	securityevents.RegisterRoutes(protected, db.Pool)

	intelligence.RegisterRoutes(protected, db.Pool)

	securityGraphHandler := securitygraph.NewHandler()
	assetInventoryHandler := assetinventory.NewHandler()
	audioHandler := audio.NewHandler()
	behaviorHandler := behavior.NewHandler()
	configAssessmentHandler := configassessment.NewHandler()
	documentHandler := document.NewHandler()
	faceHandler := face.NewHandler()
	cloudHandler := cloud.NewHandler()
	emailHandler := email.NewHandler()
	imageAnalysisHandler := imageanalysis.NewHandler()
	metadataHandler := metadata.NewHandler()
	threatIntelHandler := threatintel.NewHandler()
	complianceHandler := compliance.NewHandler()
	incidentResponseHandler := incidentresponse.NewHandler()
	responseHandler := response.NewHandler()
	accessControlHandler := accesscontrol.NewHandler()
	securityOperationsHandler := securityoperations.NewHandler()
	securityMonitoringHandler := securitymonitoring.NewHandler()
	dataExfiltrationHandler := dataexfiltration.NewHandler()
	incidentManagementHandler := incidentmanagement.NewHandler()
	threatAnalysisHandler := threatanalysis.NewHandler()
	alertManagementHandler := alertmanagement.NewHandler()
	userActivityHandler := useractivity.NewHandler()
	governanceHandler := governance.NewHandler()
	incidentAnalyticsHandler := incidentanalytics.NewHandler()
	incidentReportingHandler := incidentreporting.NewHandler()
	incidentTriageHandler := incidenttriage.NewHandler()
	incidentOrchestrationHandler := incidentorchestration.NewHandler()
	incidentReviewHandler := incidentreview.NewHandler()
	incidentEscalationHandler := incidentescalation.NewHandler()
	incidentRemediationHandler := incidentremediation.NewHandler()
	incidentResolutionHandler := incidentresolution.NewHandler()
	incidentClosureHandler := incidentclosure.NewHandler()
	incidentAfterActionHandler := incidentafteraction.NewHandler()
	incidentLearningHandler := incidentlearning.NewHandler()
	threatMitigationHandler := threatmitigation.NewHandler()
	endpointHandler := endpoint.NewHandler()
	usbHandler := usb.NewHandler()
	threatHuntingHandler := threathunting.NewHandler()
	threatResponseHandler := threatresponse.NewHandler()
	memoryForensicsHandler := memoryforensics.NewHandler()
	persistenceHandler := persistence.NewHandler()
	copilotHandler := copilot.NewHandler()
	simulationHandler := simulation.NewHandler()
	modelSecurityHandler := modelsecurity.NewHandler()
	incidentEngineHandler := incidentengine.NewHandler()
	integrationHandler := integration.NewHandler()
	attackStoryHandler := attackstory.NewHandler()
	lateralMovementHandler := lateralmovement.NewHandler()
	credentialAbuseHandler := credentialabuse.NewHandler()
	privilegeEscalationHandler := privilegeescalation.NewHandler()
	commandAnalysisHandler := commandanalysis.NewHandler()
	evidenceVaultHandler := evidencevault.NewHandler()
	attributionHandler := attribution.NewHandler()
	baselineHandler := baseline.NewHandler()
	recoveryHandler := recovery.NewHandler()
	malwareHandler := malware.NewHandler()
	networkSecurityHandler := networksecurity.NewHandler()
	attackSurfaceHandler := attacksurface.NewHandler()
	insiderThreatHandler := insiderthreat.NewHandler()
	ransomwareHandler := ransomware.NewHandler()
	riskHandler := risk.NewHandler()
	policyHandler := policy.NewHandler()
	surveillanceHandler := surveillance.NewHandler()
	dlpHandler := dlp.NewHandler()
	uebaHandler := ueba.NewHandler()
	vulnerabilityHandler := vulnerability.NewHandler()

	securitygraph.RegisterRoutes(protected, securityGraphHandler, db.Pool)
	assetinventory.RegisterRoutes(protected, assetInventoryHandler, db.Pool)
	audio.RegisterRoutes(protected, audioHandler, db.Pool)
	behavior.RegisterRoutes(protected, behaviorHandler, db.Pool)
	configassessment.RegisterRoutes(protected, configAssessmentHandler, db.Pool)
	document.RegisterRoutes(protected, documentHandler, db.Pool)
	face.RegisterRoutes(protected, faceHandler, db.Pool)
	cloud.RegisterRoutes(protected, cloudHandler, db.Pool)
	email.RegisterRoutes(protected, emailHandler, db.Pool)
	imageanalysis.RegisterRoutes(protected, imageAnalysisHandler, db.Pool)
	metadata.RegisterRoutes(protected, metadataHandler, db.Pool)
	threatintel.RegisterRoutes(protected, threatIntelHandler, db.Pool)
	compliance.RegisterRoutes(protected, complianceHandler, db.Pool)
	incidentresponse.RegisterRoutes(protected, incidentResponseHandler, db.Pool)
	response.RegisterRoutes(protected, responseHandler, db.Pool)
	accesscontrol.RegisterRoutes(protected, accessControlHandler, db.Pool)
	securityoperations.RegisterRoutes(protected, securityOperationsHandler, db.Pool)
	securitymonitoring.RegisterRoutes(protected, securityMonitoringHandler, db.Pool)
	dataexfiltration.RegisterRoutes(protected, dataExfiltrationHandler, db.Pool)
	incidentmanagement.RegisterRoutes(protected, incidentManagementHandler, db.Pool)
	threatanalysis.RegisterRoutes(protected, threatAnalysisHandler, db.Pool)
	alertmanagement.RegisterRoutes(protected, alertManagementHandler, db.Pool)
	useractivity.RegisterRoutes(protected, userActivityHandler, db.Pool)
	governance.RegisterRoutes(protected, governanceHandler, db.Pool)
	incidentreporting.RegisterRoutes(protected, incidentReportingHandler, db.Pool)
	incidentanalytics.RegisterRoutes(protected, incidentAnalyticsHandler, db.Pool)
	incidenttriage.RegisterRoutes(protected, incidentTriageHandler, db.Pool)
	incidentorchestration.RegisterRoutes(protected, incidentOrchestrationHandler, db.Pool)
	incidentreview.RegisterRoutes(protected, incidentReviewHandler, db.Pool)
	incidentescalation.RegisterRoutes(protected, incidentEscalationHandler, db.Pool)
	incidentremediation.RegisterRoutes(protected, incidentRemediationHandler, db.Pool)
	incidentresolution.RegisterRoutes(protected, incidentResolutionHandler, db.Pool)
	incidentclosure.RegisterRoutes(protected, incidentClosureHandler, db.Pool)
	incidentafteraction.RegisterRoutes(protected, incidentAfterActionHandler, db.Pool)
	incidentlearning.RegisterRoutes(protected, incidentLearningHandler, db.Pool)
	threatmitigation.RegisterRoutes(protected, threatMitigationHandler, db.Pool)
	endpoint.RegisterRoutes(protected, endpointHandler, db.Pool)
	usb.RegisterRoutes(protected, usbHandler, db.Pool)
	threathunting.RegisterRoutes(protected, threatHuntingHandler, db.Pool)
	threatresponse.RegisterRoutes(protected, threatResponseHandler, db.Pool)
	memoryforensics.RegisterRoutes(protected, memoryForensicsHandler, db.Pool)
	persistence.RegisterRoutes(protected, persistenceHandler, db.Pool)
	copilot.RegisterRoutes(protected, copilotHandler, db.Pool)
	simulation.RegisterRoutes(protected, simulationHandler, db.Pool)
	modelsecurity.RegisterRoutes(protected, modelSecurityHandler, db.Pool)
	incidentengine.RegisterRoutes(protected, incidentEngineHandler, db.Pool)
	integration.RegisterRoutes(protected, integrationHandler, db.Pool)
	attackstory.RegisterRoutes(protected, attackStoryHandler, db.Pool)
	lateralmovement.RegisterRoutes(protected, lateralMovementHandler, db.Pool)
	credentialabuse.RegisterRoutes(protected, credentialAbuseHandler, db.Pool)
	privilegeescalation.RegisterRoutes(protected, privilegeEscalationHandler, db.Pool)
	commandanalysis.RegisterRoutes(protected, commandAnalysisHandler, db.Pool)
	evidencevault.RegisterRoutes(protected, evidenceVaultHandler, db.Pool)
	attribution.RegisterRoutes(protected, attributionHandler, db.Pool)
	baseline.RegisterRoutes(protected, baselineHandler, db.Pool)
	recovery.RegisterRoutes(protected, recoveryHandler, db.Pool)
	malware.RegisterRoutes(protected, malwareHandler, db.Pool)
	networksecurity.RegisterRoutes(protected, networkSecurityHandler, db.Pool)
	attacksurface.RegisterRoutes(protected, attackSurfaceHandler, db.Pool)
	insiderthreat.RegisterRoutes(protected, insiderThreatHandler, db.Pool)
	ransomware.RegisterRoutes(protected, ransomwareHandler, db.Pool)
	risk.RegisterRoutes(protected, riskHandler, db.Pool)
	securityscore.RegisterRoutes(protected, db.Pool)
	policy.RegisterRoutes(protected, policyHandler, db.Pool)
	surveillance.RegisterRoutes(protected, surveillanceHandler, db.Pool)
	dlp.RegisterRoutes(protected, dlpHandler, db.Pool)
	ueba.RegisterRoutes(protected, uebaHandler, db.Pool)
	vulnerability.RegisterRoutes(protected, vulnerabilityHandler, db.Pool)

	{
		protected.GET("/profile", authHandler.Profile)
		protected.POST("/auth/mfa/enrollment/start", authHandler.StartMFAEnrollment)
		protected.POST("/auth/mfa/enrollment/confirm", authHandler.ConfirmMFAEnrollment)
		protected.POST("/auth/mfa/email/enrollment/start", authHandler.StartEmailMFAEnrollment)
		protected.POST("/auth/mfa/email/enrollment/confirm", authHandler.ConfirmEmailMFAEnrollment)
		protected.POST("/auth/mfa/totp/replacement/start", authHandler.StartTOTPReplacement)
		protected.POST("/auth/mfa/totp/replacement/confirm", authHandler.ConfirmTOTPReplacement)
		protected.GET("/auth/devices", authHandler.ListTrustedDevices)
		protected.POST("/auth/devices", authHandler.RegisterDevice)
		protected.PATCH("/auth/devices/:id/trust", authHandler.UpdateDeviceTrust)

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
			admin.GET("/organizations", middleware.RequirePermission(db.Pool, "ORGANIZATION_MANAGE"), organizationHandler.List)
			admin.POST("/organizations", middleware.RequirePermission(db.Pool, "ORGANIZATION_MANAGE"), organizationHandler.Create)
			admin.PUT("/organizations/:id/approve", middleware.RequirePermission(db.Pool, "ORGANIZATION_MANAGE"), organizationHandler.Approve)
			admin.PUT("/organizations/:id/reject", middleware.RequirePermission(db.Pool, "ORGANIZATION_MANAGE"), organizationHandler.Reject)
			admin.GET("/organizations/:id/history", middleware.RequirePermission(db.Pool, "ORGANIZATION_MANAGE"), organizationHandler.History)
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
				admin.PATCH("/users/:id/status", middleware.RequirePermission(db.Pool, "USER_UPDATE"), userHandler.ChangeAccountStatus)

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
				user.RegisterSecurityRoutes(admin, db.Pool, func(permission string) gin.HandlerFunc {
					return middleware.RequirePermission(db.Pool, permission)
				})

				admin.GET(
					"/audit-logs",
					middleware.RequirePermission(
						db.Pool,
						"AUDIT_VIEW",
					),
					auditHandler.ListAuditLogs,
				)

				admin.GET(
					"/audit-activity",
					middleware.RequirePermission(
						db.Pool,
						"AUDIT_VIEW",
					),
					auditHandler.ListTimeline,
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

		// Start DFIR poller to claim queued file events and enqueue them.
		StartDFIRPoller(
			context.Background(),
			db.Pool,
			threatRepository,
			dfirWorker,
			5*time.Second,
		)

		return router,
			fileMonitorService,
			notificationModule,
			preEncryptionWorker,
			adaptiveDeceptionHealthWorker,
			adaptiveDeceptionFingerprintWorker,
			deepfakeForensicsWorker,
			dfirWorker
	}
}

func initializeHoneytokenModule(
	databasePool *pgxpool.Pool,
	canaryStoragePath string,
	canaryDeploymentRoot string,
	threatWorker *honeytoken.ThreatWorker,
	preEncryptionWorker *preencryption.Worker,
	authRepository *auth.Repository,
	mfaDelivery auth.MFAOTPDelivery,
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

	protectedFileService :=
		honeytoken.NewProtectedFileService(
			honeytokenRepository,
			encryptionKeyService,
			canaryService,
		)

	protectedFileHandler := honeytoken.NewHandler(
		protectedFileService,
		authRepository,
		mfaDelivery,
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

	// DFIR worker is registered via its API endpoint; avoid direct file
	// service registration here to keep initialization order stable.

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
