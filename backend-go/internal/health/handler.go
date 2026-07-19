package health

import (
	"github.com/gin-gonic/gin"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

func HealthCheck(c *gin.Context) {
	response.OK(
		c,
		"Digital Defense Hub API is running",
		gin.H{
			"status": "UP",
		},
	)
}
