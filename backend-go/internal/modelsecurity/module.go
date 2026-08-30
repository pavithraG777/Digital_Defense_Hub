package modelsecurity

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

type ModelSecurityAssessment struct {
	RiskScore      int      `json:"risk_score"`
	RiskLevel      string   `json:"risk_level"`
	RequiresReview bool     `json:"requires_review"`
	RiskFlags      []string `json:"risk_flags"`
	Summary        string   `json:"summary"`
}

// ScoreModelSecurityRisk is deterministic and deliberately explainable. A
// fully verified and attested artifact starts at zero risk; every score is
// traceable to a returned flag.
func ScoreModelSecurityRisk(modelID string, integrityVerified, attested, validationFailed bool) ModelSecurityAssessment {
	flags := make([]string, 0, 4)
	score := 0
	if strings.TrimSpace(modelID) == "" {
		flags = append(flags, "model_identifier_missing")
		score += 20
	}
	if !integrityVerified {
		flags = append(flags, "integrity_not_verified")
		score += 40
	}
	if !attested {
		flags = append(flags, "model_not_attested")
		score += 25
	}
	if validationFailed {
		flags = append(flags, "validation_failed")
		score += 35
	}
	if score > 100 {
		score = 100
	}

	level := "LOW"
	review := false
	if score >= 70 {
		level, review = "CRITICAL", true
	} else if score >= 40 {
		level, review = "HIGH", true
	} else if score > 0 {
		level, review = "MEDIUM", true
	}
	summary := "model artifact integrity, attestation, and validation are verified"
	if review {
		summary = "model deployment is blocked pending governance review"
	}
	return ModelSecurityAssessment{score, level, review, flags, summary}
}

type Handler struct{ repo VerificationRepository }

func NewHandler() *Handler { return &Handler{} }

func RegisterRoutes(protected *gin.RouterGroup, handler *Handler, pool *pgxpool.Pool) {
	if protected == nil || handler == nil || pool == nil {
		return
	}
	repo := NewRepository(pool)
	// The migration is authoritative. This idempotent bootstrap supports local
	// development without making a transient startup error remove every route.
	_ = repo.EnsureSchema(context.Background())
	handler.repo = repo
	group := protected.Group("/model-security")
	group.GET("/integrity", middleware.RequirePermission(pool, "MODEL_SECURITY_VIEW"), handler.CheckIntegrity)
	group.GET("/verifications", middleware.RequirePermission(pool, "MODEL_SECURITY_VIEW"), handler.ListVerifications)
	group.GET("/verifications/:id", middleware.RequirePermission(pool, "MODEL_SECURITY_VIEW"), handler.GetVerification)
	group.POST("/verifications", middleware.RequirePermission(pool, "MODEL_SECURITY_MANAGE"), handler.VerifyModel)
	// Keep the original routes as compatibility aliases while clients migrate.
	legacy := protected.Group("/modelsecurity")
	legacy.GET("/integrity", middleware.RequirePermission(pool, "MODEL_SECURITY_VIEW"), handler.CheckIntegrity)
	legacy.POST("/verify", middleware.RequirePermission(pool, "MODEL_SECURITY_MANAGE"), handler.VerifyModel)
}
