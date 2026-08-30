package incidentafteraction

import (
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/jackc/pgx/v5/pgxpool"
)

type Handler struct{}

func NewHandler() *Handler {
    return &Handler{}
}

func RegisterRoutes(protected *gin.RouterGroup, handler *Handler, databasePool *pgxpool.Pool) {
    group := protected.Group("/incident-after-action")
    group.GET("", handler.GetIncidentAfterAction)
}

func (h *Handler) GetIncidentAfterAction(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"message": "incident after action endpoint"})
}
