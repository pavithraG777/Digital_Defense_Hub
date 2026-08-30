package middleware

import (
	"github.com/gin-gonic/gin"
)

func abortWithError(c *gin.Context, status int, message string, err interface{}) {
	c.JSON(status, gin.H{
		"success": false,
		"message": message,
		"error":   err,
	})
	c.Abort()
}
