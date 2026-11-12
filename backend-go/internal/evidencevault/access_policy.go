package evidencevault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
	"golang.org/x/crypto/bcrypt"
)

type accessRequest struct {
	Password string `json:"password"`
}

func accessTokenHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (h *Handler) createAccessPolicy(c *gin.Context, org, job, owner uuid.UUID, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = h.repo.db.Exec(c, `INSERT INTO evidence_access_policies(job_id,organization_id,owner_user_id,trusted_ip,password_hash,created_at,updated_at) VALUES($1,$2,$3,$4,$5,NOW(),NOW()) ON CONFLICT(job_id) DO UPDATE SET owner_user_id=EXCLUDED.owner_user_id,trusted_ip=EXCLUDED.trusted_ip,password_hash=EXCLUDED.password_hash,updated_at=NOW()`, job, org, owner, c.ClientIP(), string(hash))
	return err
}

func (h *Handler) AuthorizeAccess(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	user, userOK := eid(c, "user_id")
	job, err := uuid.Parse(c.Param("id"))
	if !ok || !userOK || err != nil {
		response.BadRequest(c, "Invalid evidence access context", nil)
		return
	}
	var trustedIP, passwordHash string
	err = h.repo.db.QueryRow(c, `SELECT trusted_ip,password_hash FROM evidence_access_policies WHERE organization_id=$1 AND job_id=$2`, org, job).Scan(&trustedIP, &passwordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		// Evidence preserved before access policies were introduced has no
		// owner password to validate. Keep it accessible only through the
		// authenticated, permission-checked, tenant-scoped route.
		if _, getErr := h.repo.Get(c, org, job); getErr != nil {
			response.NotFound(c, "Evidence job not found", nil)
			return
		}
		response.OK(c, "Legacy evidence access authorized", gin.H{"access_token": "", "trusted_network": true, "legacy_policy": true})
		return
	}
	if err != nil {
		response.Forbidden(c, "Evidence access policy is unavailable", nil)
		return
	}
	var q accessRequest
	_ = c.ShouldBindJSON(&q)
	trusted := strings.TrimSpace(trustedIP) != "" && strings.EqualFold(strings.TrimSpace(trustedIP), strings.TrimSpace(c.ClientIP()))
	if !trusted && bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(q.Password)) != nil {
		response.Forbidden(c, "Different network detected. Owner access password is required", gin.H{"password_required": true})
		return
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		response.InternalServerError(c, "Could not create evidence access grant", nil)
		return
	}
	token := hex.EncodeToString(raw)
	expires := time.Now().UTC().Add(10 * time.Minute)
	_, err = h.repo.db.Exec(c, `INSERT INTO evidence_access_grants(id,organization_id,job_id,user_id,ip_address,token_hash,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,NOW())`, uuid.New(), org, job, user, c.ClientIP(), accessTokenHash(token), expires)
	if err != nil {
		response.InternalServerError(c, "Could not persist evidence access grant", nil)
		return
	}
	response.OK(c, "Evidence access authorized", gin.H{"access_token": token, "expires_at": expires, "trusted_network": trusted})
}

func (h *Handler) requireAccess(c *gin.Context, org, job uuid.UUID) bool {
	var trustedIP string
	err := h.repo.db.QueryRow(c, `SELECT trusted_ip FROM evidence_access_policies WHERE organization_id=$1 AND job_id=$2`, org, job).Scan(&trustedIP)
	if errors.Is(err, pgx.ErrNoRows) {
		// Backward compatibility for records created before owner-password
		// policies existed. Repository.Get enforces organization ownership;
		// route middleware has already enforced vault-view permission.
		if _, getErr := h.repo.Get(c, org, job); getErr == nil {
			return true
		}
		response.NotFound(c, "Evidence job not found", nil)
		return false
	}
	if err != nil {
		response.Forbidden(c, "Evidence access policy is unavailable", nil)
		return false
	}
	if strings.EqualFold(strings.TrimSpace(trustedIP), strings.TrimSpace(c.ClientIP())) {
		return true
	}
	user, ok := eid(c, "user_id")
	token := strings.TrimSpace(c.Query("access_token"))
	if !ok || token == "" {
		response.Error(c, http.StatusForbidden, "Different network detected. Owner access password is required", gin.H{"password_required": true})
		return false
	}
	var exists bool
	_ = h.repo.db.QueryRow(c, `SELECT EXISTS(SELECT 1 FROM evidence_access_grants WHERE organization_id=$1 AND job_id=$2 AND user_id=$3 AND token_hash=$4 AND ip_address=$5 AND expires_at>NOW())`, org, job, user, accessTokenHash(token), c.ClientIP()).Scan(&exists)
	if !exists {
		response.Forbidden(c, "Evidence access grant is invalid or expired", nil)
		return false
	}
	return true
}
