package securityoperations

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
)

type Handler struct {
	actions    operational.ActionStore
	executor   operational.AnalysisExecutorStore
	connectors *operational.ConnectorWorker
}

func NewHandler() *Handler                                                { return &Handler{} }
func (h *Handler) SetConnectorWorker(worker *operational.ConnectorWorker) { h.connectors = worker }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.actions = operational.ActionStore{DB: db, Module: "SECURITY_OPERATIONS"}
	h.executor = operational.AnalysisExecutorStore{DB: db}
	g := p.Group("/security-operations")
	g.GET("/connectors/health", middleware.RequirePermission(db, "SECURITY_OPERATIONS_VIEW"), h.ConnectorHealth)
	g.POST("/analysis-jobs/claim", middleware.RequirePermission(db, "SECURITY_OPERATIONS_EXECUTE"), h.ClaimAnalysisJob)
	g.POST("/analysis-jobs/:id/heartbeat", middleware.RequirePermission(db, "SECURITY_OPERATIONS_EXECUTE"), h.HeartbeatAnalysisJob)
	g.POST("/analysis-jobs/:id/result", middleware.RequirePermission(db, "SECURITY_OPERATIONS_EXECUTE"), h.CompleteAnalysisJob)
	g.POST("/analysis-jobs/:id/retry", middleware.RequirePermission(db, "SECURITY_OPERATIONS_EXECUTE"), h.RetryAnalysisJob)
	g.POST("/analysis-jobs/:id/cancel", middleware.RequirePermission(db, "SECURITY_OPERATIONS_SUSPEND"), h.CancelAnalysisJob)
	g.GET("", middleware.RequirePermission(db, "SECURITY_OPERATIONS_VIEW"), h.ListOperations)
	g.GET("/:id", middleware.RequirePermission(db, "SECURITY_OPERATIONS_VIEW"), h.GetOperation)
	g.POST("/execute", middleware.RequirePermission(db, "SECURITY_OPERATIONS_EXECUTE"), h.ExecuteOperation)
	g.POST("/suspend", middleware.RequirePermission(db, "SECURITY_OPERATIONS_SUSPEND"), h.SuspendOperation)
}
func (h *Handler) ListOperations(c *gin.Context)       { h.actions.List(c) }
func (h *Handler) GetOperation(c *gin.Context)         { h.actions.Get(c, c.Param("id")) }
func (h *Handler) ExecuteOperation(c *gin.Context)     { h.actions.Create(c, "") }
func (h *Handler) SuspendOperation(c *gin.Context)     { h.actions.Create(c, "SUSPEND_OPERATION") }
func (h *Handler) ClaimAnalysisJob(c *gin.Context)     { h.executor.Claim(c) }
func (h *Handler) HeartbeatAnalysisJob(c *gin.Context) { h.executor.Heartbeat(c) }
func (h *Handler) CompleteAnalysisJob(c *gin.Context)  { h.executor.Complete(c) }
func (h *Handler) RetryAnalysisJob(c *gin.Context)     { h.executor.Transition(c, true) }
func (h *Handler) CancelAnalysisJob(c *gin.Context)    { h.executor.Transition(c, false) }
func (h *Handler) ConnectorHealth(c *gin.Context) {
	if h.connectors == nil {
		c.JSON(503, gin.H{"success": false, "message": "Operational connector worker is unavailable"})
		return
	}
	c.JSON(200, gin.H{"success": true, "data": h.connectors.Status()})
}
