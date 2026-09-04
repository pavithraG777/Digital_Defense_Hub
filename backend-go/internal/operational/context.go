package operational

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"net/http"
)

func ContextUUID(c *gin.Context, key string) (uuid.UUID, bool) {
	value, exists := c.Get(key)
	if !exists {
		Failure(c, http.StatusUnauthorized, "Authentication context is missing")
		return uuid.Nil, false
	}
	if id, ok := value.(uuid.UUID); ok && id != uuid.Nil {
		return id, true
	}
	if raw, ok := value.(string); ok {
		if id, err := uuid.Parse(raw); err == nil {
			return id, true
		}
	}
	Failure(c, http.StatusUnauthorized, "Authentication context is invalid")
	return uuid.Nil, false
}

func Failure(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"success": false, "message": message})
}
