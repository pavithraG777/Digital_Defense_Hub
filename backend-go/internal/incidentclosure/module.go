package incidentclosure

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
    group := protected.Group("/incident-closure")
    group.GET("", handler.GetIncidentClosure)
}

func (h *Handler) GetIncidentClosure(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"message": "incident closure endpoint"})
}
