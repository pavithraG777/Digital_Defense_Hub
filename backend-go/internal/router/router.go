package router

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/auth"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/database"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/health"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/user"
)

func SetupRouter(
	db *database.Database,
	cfg *config.Config,
) *gin.Engine {
	router := gin.New()

	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.RequestID())
	router.Use(middleware.CORS())

	// Authentication dependencies
	authRepository := auth.NewRepository(db.Pool)

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
	userService := user.NewService(userRepository)
	userHandler := user.NewHandler(userService)

	api := router.Group("/api")
	v1 := api.Group("/v1")

	// Public routes
	v1.GET("/health", health.HealthCheck)

	authGroup := v1.Group("/auth")
	{
		authGroup.POST("/login", authHandler.Login)
	}

	// Protected routes
	protected := v1.Group("")
	protected.Use(middleware.Authenticate(jwtManager))
	{
		protected.GET("/profile", authHandler.Profile)

		admin := protected.Group("/admin")
		admin.Use(middleware.RequireRoles("SUPER_ADMIN"))
		{
			admin.GET("/dashboard", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"success": true,
					"message": "Welcome Super Admin",
				})
			})

			admin.POST("/users", userHandler.CreateUser)
			admin.GET("/users", userHandler.ListUsers)
			admin.GET("/users/:id", userHandler.GetUserByID)
			admin.PUT("/users/:id", userHandler.UpdateUser)
		}
	}

	return router
}
