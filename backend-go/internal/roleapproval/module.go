package roleapproval

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
	"net/http"
	"strings"
	"time"
)

type Handler struct{ db *pgxpool.Pool }

func NewHandler(db *pgxpool.Pool) *Handler { return &Handler{db: db} }
func cid(c *gin.Context, k string) (uuid.UUID, bool) {
	v, o := c.Get(k)
	if !o {
		return uuid.Nil, false
	}
	if id, o := v.(uuid.UUID); o {
		return id, true
	}
	s, o := v.(string)
	if !o {
		return uuid.Nil, false
	}
	id, e := uuid.Parse(s)
	return id, e == nil
}

type request struct {
	UserIDs   []uuid.UUID `json:"user_ids" binding:"required,min=1"`
	RoleIDs   []uuid.UUID `json:"role_ids" binding:"required,min=1"`
	ExpiresAt *time.Time  `json:"expires_at"`
	Reason    string      `json:"reason" binding:"required"`
}

func (h *Handler) Create(c *gin.Context) {
	org, o := cid(c, "organization_id")
	actor, a := cid(c, "user_id")
	if !o || !a {
		response.Unauthorized(c, "Identity context missing", nil)
		return
	}
	var q request
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid request", e.Error())
		return
	}
	id := uuid.New()
	_, e := h.db.Exec(c, `INSERT INTO role_assignment_approvals(id,organization_id,user_ids,role_ids,expires_at,reason,requested_by) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, org, q.UserIDs, q.RoleIDs, q.ExpiresAt, strings.TrimSpace(q.Reason), actor)
	if e != nil {
		response.BadRequest(c, "Unable to create approval request", e.Error())
		return
	}
	response.Success(c, http.StatusCreated, "Role assignment approval requested", gin.H{"id": id, "status": "PENDING"})
}
func (h *Handler) List(c *gin.Context) {
	org, o := cid(c, "organization_id")
	if !o {
		response.Unauthorized(c, "Organization context missing", nil)
		return
	}
	rows, e := h.db.Query(c, `SELECT jsonb_build_object('id',id,'user_ids',user_ids,'role_ids',role_ids,'expires_at',expires_at,'reason',reason,'status',status,'requested_by',requested_by,'decided_by',decided_by,'decision_note',decision_note,'requested_at',requested_at,'decided_at',decided_at) FROM role_assignment_approvals WHERE organization_id=$1 ORDER BY requested_at DESC LIMIT 200`, org)
	if e != nil {
		response.InternalServerError(c, "Unable to load approvals", nil)
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var v any
		if rows.Scan(&v) == nil {
			out = append(out, v)
		}
	}
	response.OK(c, "Approval requests retrieved", out)
}

type decision struct {
	Decision string `json:"decision" binding:"required"`
	Note     string `json:"note"`
}

func (h *Handler) Decide(c *gin.Context) {
	org, o := cid(c, "organization_id")
	actor, a := cid(c, "user_id")
	id, e := uuid.Parse(c.Param("id"))
	if !o || !a || e != nil {
		response.BadRequest(c, "Invalid approval context", nil)
		return
	}
	var q decision
	if e = c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid decision", e.Error())
		return
	}
	q.Decision = strings.ToUpper(q.Decision)
	if q.Decision != "APPROVED" && q.Decision != "REJECTED" {
		response.BadRequest(c, "Decision must be APPROVED or REJECTED", nil)
		return
	}
	tx, e := h.db.Begin(c)
	if e != nil {
		response.InternalServerError(c, "Unable to start decision", nil)
		return
	}
	defer tx.Rollback(c)
	var users, roles []uuid.UUID
	var expires any
	e = tx.QueryRow(c, `UPDATE role_assignment_approvals SET status=$1,decided_by=$2,decision_note=$3,decided_at=NOW() WHERE id=$4 AND organization_id=$5 AND status='PENDING' RETURNING user_ids,role_ids,expires_at`, q.Decision, actor, q.Note, id, org).Scan(&users, &roles, &expires)
	if e != nil {
		response.BadRequest(c, "Approval is missing or already decided", nil)
		return
	}
	if q.Decision == "APPROVED" {
		for _, u := range users {
			for _, r := range roles {
				_, e = tx.Exec(c, `INSERT INTO user_roles(id,user_id,role_id,granted_by,granted_at,expires_at,is_active) VALUES($1,$2,$3,$4,NOW(),$5,TRUE) ON CONFLICT(user_id,role_id) DO UPDATE SET granted_by=EXCLUDED.granted_by,granted_at=NOW(),expires_at=EXCLUDED.expires_at,is_active=TRUE`, uuid.New(), u, r, actor, expires)
				if e != nil {
					response.BadRequest(c, "Unable to apply approved roles", e.Error())
					return
				}
			}
		}
	}
	if e = tx.Commit(c); e != nil {
		response.InternalServerError(c, "Unable to commit decision", nil)
		return
	}
	response.OK(c, "Approval decision recorded", gin.H{"id": id, "status": q.Decision})
}
func RegisterRoutes(g *gin.RouterGroup, db *pgxpool.Pool, require func(string) gin.HandlerFunc) {
	h := NewHandler(db)
	x := g.Group("/admin/role-assignment-approvals")
	x.GET("", require("ROLE_VIEW"), h.List)
	x.POST("", require("ROLE_ASSIGN"), h.Create)
	x.POST("/:id/decision", require("ROLE_ASSIGN"), h.Decide)
}
