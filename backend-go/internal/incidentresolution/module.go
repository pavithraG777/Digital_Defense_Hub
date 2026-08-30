package incidentresolution

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
    group := protected.Group("/incident-resolution")
    group.GET("", handler.GetIncidentResolution)
}

func (h *Handler) GetIncidentResolution(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"message": "incident resolution endpoint"})
}
