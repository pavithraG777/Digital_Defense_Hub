package response

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func RegisterRoutes(protected *gin.RouterGroup, handler *Handler, databasePool *pgxpool.Pool) {
	if protected == nil || handler == nil || databasePool == nil {
		return
	}

	group := protected.Group("/responses")
	group.GET("", handler.ListResponses)
	group.GET(":id", handler.GetResponse)
}

func (h *Handler) ListResponses(c *gin.Context) {
	OK(c, "Responses listed", []any{})
}

func (h *Handler) GetResponse(c *gin.Context) {
	OK(c, "Response details", gin.H{"id": c.Param("id")})
}
