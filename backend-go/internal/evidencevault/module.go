package evidencevault

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
	"net/http"
	"strings"
	"time"
)

type Handler struct {
	repo  *Repository
	keys  *SigningKeys
	vault *LocalVault
}

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(g *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if g == nil || h == nil || db == nil {
		return
	}
	repo, e := NewRepository(db)
	if e != nil {
		return
	}
	_ = repo.EnsureSchema(context.Background())
	h.repo = repo
	h.keys = LoadSigningKeysFromEnvironment()
	h.vault, _ = LoadLocalVaultFromEnvironment()
	r := g.Group("/evidencevault")
	r.GET("/cases", middleware.RequirePermission(db, "EVIDENCE_VAULT_VIEW"), h.ListCases)
	r.POST("/preserve", middleware.RequirePermission(db, "EVIDENCE_VAULT_MANAGE"), h.Preserve)
	r.POST("/objects", middleware.RequirePermission(db, "EVIDENCE_VAULT_MANAGE"), h.PreserveObject)
	r.GET("/objects/:id/content", middleware.RequirePermission(db, "EVIDENCE_VAULT_VIEW"), h.GetObjectContent)
	r.GET("/jobs/:id", middleware.RequirePermission(db, "EVIDENCE_VAULT_VIEW"), h.Get)
	r.PATCH("/jobs/:id/lifecycle", middleware.RequirePermission(db, "EVIDENCE_VAULT_MANAGE"), h.Lifecycle)
	r.GET("/jobs/:id/custody", middleware.RequirePermission(db, "EVIDENCE_VAULT_VIEW"), h.Custody)
	r.POST("/manifests", middleware.RequirePermission(db, "EVIDENCE_VAULT_MANAGE"), h.CreateManifest)
	r.GET("/manifests/:id", middleware.RequirePermission(db, "EVIDENCE_VAULT_VIEW"), h.GetManifest)
	r.POST("/manifests/:id/verify", middleware.RequirePermission(db, "EVIDENCE_VAULT_MANAGE"), h.VerifyStoredManifest)
	r.POST("/exports/verify", middleware.RequirePermission(db, "EVIDENCE_VAULT_VIEW"), h.VerifyExport)
	r.POST("/jobs/:id/custody/verify", middleware.RequirePermission(db, "EVIDENCE_VAULT_MANAGE"), h.VerifyCustody)
	r.POST("/manifests/:id/worm-attestation", middleware.RequirePermission(db, "EVIDENCE_VAULT_MANAGE"), h.RecordWORMAttestation)
	r.POST("/manifests/:id/destruction-certificate", middleware.RequirePermission(db, "EVIDENCE_VAULT_MANAGE"), h.CreateDestructionCertificate)
	r.GET("/integrity/health", middleware.RequirePermission(db, "EVIDENCE_VAULT_VIEW"), h.IntegrityHealth)
}
func eid(c *gin.Context, key string) (uuid.UUID, bool) {
	v, ok := c.Get(key)
	if !ok {
		return uuid.Nil, false
	}
	switch x := v.(type) {
	case uuid.UUID:
		return x, x != uuid.Nil
	case string:
		id, e := uuid.Parse(x)
		return id, e == nil
	}
	return uuid.Nil, false
}
func (h *Handler) ListCases(c *gin.Context) {
	if h.repo == nil {
		c.JSON(200, gin.H{"success": true, "cases": []any{}})
		return
	}
	org, ok := eid(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	jobs, e := h.repo.List(c, org, strings.ToUpper(strings.TrimSpace(c.Query("status"))))
	if e != nil {
		response.InternalServerError(c, "Could not list evidence jobs", e.Error())
		return
	}
	response.OK(c, "Evidence preservation jobs loaded", jobs)
}

type preserve struct {
	CaseID        uuid.UUID `json:"case_id" binding:"required"`
	Items         []string  `json:"items" binding:"required,min=1"`
	RetentionDays int       `json:"retention_days" binding:"required,min=1,max=3650"`
}

func (h *Handler) Preserve(c *gin.Context) {
	var q preserve
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid preservation request", e.Error())
		return
	}
	if h.repo == nil {
		c.JSON(http.StatusAccepted, gin.H{"success": true, "message": "evidence preservation started", "case_id": q.CaseID})
		return
	}
	org, ok := eid(c, "organization_id")
	actor, aok := eid(c, "user_id")
	if !ok || !aok {
		response.Unauthorized(c, "Invalid authentication context", nil)
		return
	}
	retention := time.Now().UTC().AddDate(0, 0, q.RetentionDays)
	job := &PreservationJob{ID: uuid.New(), OrganizationID: org, CaseID: q.CaseID, Items: q.Items, Status: "PRESERVED", RetentionUntil: &retention, CreatedBy: actor, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if e := h.repo.Create(c, job); e != nil {
		response.InternalServerError(c, "Could not preserve evidence", e.Error())
		return
	}
	_, _ = h.repo.Transition(c, org, job.ID, actor, "PRESERVED", "Initial preservation", &actor)
	response.Success(c, http.StatusCreated, "Evidence preserved", job)
}
func (h *Handler) Get(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	id, e := uuid.Parse(c.Param("id"))
	if !ok || e != nil {
		response.BadRequest(c, "Invalid evidence context", nil)
		return
	}
	job, e := h.repo.Get(c, org, id)
	if e != nil {
		response.NotFound(c, "Evidence job not found", nil)
		return
	}
	response.OK(c, "Evidence job loaded", job)
}

type transition struct {
	Status      string     `json:"status" binding:"required,oneof=VERIFIED LEGAL_HOLD ARCHIVED RELEASED DESTROYED"`
	Note        string     `json:"note" binding:"required"`
	ToCustodian *uuid.UUID `json:"to_custodian"`
}

func (h *Handler) Lifecycle(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	actor, aok := eid(c, "user_id")
	id, e := uuid.Parse(c.Param("id"))
	if !ok || !aok || e != nil {
		response.BadRequest(c, "Invalid evidence context", nil)
		return
	}
	var q transition
	if e = c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid lifecycle transition", e.Error())
		return
	}
	current, e := h.repo.Get(c, org, id)
	if e != nil {
		response.NotFound(c, "Evidence job not found", nil)
		return
	}
	if current.LegalHold && q.Status == "DESTROYED" {
		response.Error(c, http.StatusConflict, "Evidence under legal hold cannot be destroyed", nil)
		return
	}
	if q.Status == "DESTROYED" && current.RetentionUntil != nil && time.Now().UTC().Before(*current.RetentionUntil) {
		response.Error(c, http.StatusConflict, "Evidence cannot be destroyed before retention expires", nil)
		return
	}
	job, e := h.repo.Transition(c, org, id, actor, q.Status, q.Note, q.ToCustodian)
	if e != nil {
		response.InternalServerError(c, "Could not transition evidence", e.Error())
		return
	}
	response.OK(c, "Evidence lifecycle updated", job)
}
func (h *Handler) Custody(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	id, e := uuid.Parse(c.Param("id"))
	if !ok || e != nil {
		response.BadRequest(c, "Invalid evidence context", nil)
		return
	}
	events, e := h.repo.Custody(c, org, id)
	if e != nil {
		response.InternalServerError(c, "Could not load custody history", e.Error())
		return
	}
	response.OK(c, "Evidence custody history loaded", events)
}
