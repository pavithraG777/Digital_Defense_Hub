package userpreferences

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

type Preferences struct {
	DesktopNotifications bool      `json:"desktop_notifications"`
	SoundNotifications   bool      `json:"sound_notifications"`
	EmailNotifications   bool      `json:"email_notifications"`
	Theme                string    `json:"theme"`
	Language             string    `json:"language"`
	MFAPolicy            string    `json:"mfa_policy"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type Handler struct{ db *pgxpool.Pool }

func NewHandler(db *pgxpool.Pool) *Handler { return &Handler{db: db} }

func contextID(c *gin.Context, key string) (uuid.UUID, bool) {
	v, ok := c.Get(key)
	if !ok {
		return uuid.Nil, false
	}
	s, ok := v.(string)
	if ok {
		id, err := uuid.Parse(s)
		return id, err == nil
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}

func (h *Handler) Get(c *gin.Context) {
	userID, ok := contextID(c, "user_id")
	if !ok {
		response.Unauthorized(c, "User information is missing", nil)
		return
	}
	orgID, ok := contextID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Organization information is missing", nil)
		return
	}
	var p Preferences
	err := h.db.QueryRow(c, `INSERT INTO user_security_preferences(user_id,organization_id) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET organization_id=EXCLUDED.organization_id RETURNING desktop_notifications,sound_notifications,email_notifications,theme,language,mfa_policy,updated_at`, userID, orgID).Scan(&p.DesktopNotifications, &p.SoundNotifications, &p.EmailNotifications, &p.Theme, &p.Language, &p.MFAPolicy, &p.UpdatedAt)
	if err != nil {
		response.InternalServerError(c, "Unable to load preferences", nil)
		return
	}
	response.OK(c, "Preferences retrieved successfully", p)
}

func (h *Handler) Update(c *gin.Context) {
	userID, ok := contextID(c, "user_id")
	if !ok {
		response.Unauthorized(c, "User information is missing", nil)
		return
	}
	orgID, ok := contextID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Organization information is missing", nil)
		return
	}
	var p Preferences
	if err := c.ShouldBindJSON(&p); err != nil {
		response.BadRequest(c, "Invalid preferences", err.Error())
		return
	}
	p.Theme = strings.ToLower(strings.TrimSpace(p.Theme))
	p.Language = strings.ToLower(strings.TrimSpace(p.Language))
	p.MFAPolicy = strings.ToUpper(strings.TrimSpace(p.MFAPolicy))
	if p.Theme != "dark" && p.Theme != "light" && p.Theme != "system" {
		response.BadRequest(c, "Invalid theme", nil)
		return
	}
	if p.Language != "en" && p.Language != "ta" {
		response.BadRequest(c, "Invalid language", nil)
		return
	}
	switch p.MFAPolicy {
	case "USER_CHOICE", "EMAIL_ONLY", "TOTP_ONLY", "EMAIL_OR_TOTP":
	default:
		response.BadRequest(c, "Invalid MFA policy", nil)
		return
	}
	err := h.db.QueryRow(c, `INSERT INTO user_security_preferences(user_id,organization_id,desktop_notifications,sound_notifications,email_notifications,theme,language,mfa_policy,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NOW()) ON CONFLICT(user_id) DO UPDATE SET desktop_notifications=EXCLUDED.desktop_notifications,sound_notifications=EXCLUDED.sound_notifications,email_notifications=EXCLUDED.email_notifications,theme=EXCLUDED.theme,language=EXCLUDED.language,mfa_policy=EXCLUDED.mfa_policy,updated_at=NOW() RETURNING desktop_notifications,sound_notifications,email_notifications,theme,language,mfa_policy,updated_at`, userID, orgID, p.DesktopNotifications, p.SoundNotifications, p.EmailNotifications, p.Theme, p.Language, p.MFAPolicy).Scan(&p.DesktopNotifications, &p.SoundNotifications, &p.EmailNotifications, &p.Theme, &p.Language, &p.MFAPolicy, &p.UpdatedAt)
	if err != nil {
		response.InternalServerError(c, "Unable to save preferences", nil)
		return
	}
	response.Success(c, http.StatusOK, "Preferences saved successfully", p)
}

func RegisterRoutes(group *gin.RouterGroup, db *pgxpool.Pool) {
	h := NewHandler(db)
	group.GET("/user-preferences", h.Get)
	group.PUT("/user-preferences", h.Update)
}
