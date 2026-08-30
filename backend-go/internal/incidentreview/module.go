package incidentreview

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
    group := protected.Group("/incident-review")
    group.GET("", handler.GetIncidentReview)
}

func (h *Handler) GetIncidentReview(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"message": "incident review endpoint"})
}
