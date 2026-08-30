package commandanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

type Finding struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
}
type Analysis struct {
	Language         string    `json:"language"`
	Decoded          string    `json:"decoded,omitempty"`
	RiskScore        int       `json:"risk_score"`
	RiskLevel        string    `json:"risk_level"`
	Findings         []Finding `json:"findings"`
	IOCs             []string  `json:"iocs"`
	RequiresSandbox  bool      `json:"requires_sandbox"`
	SignatureVersion int       `json:"signature_version"`
}
type signature struct {
	code        string
	severity    string
	score       int
	pattern     *regexp.Regexp
	description string
}

var signatures = []signature{{"ENCODED_COMMAND", "HIGH", 30, regexp.MustCompile(`(?i)(?:-|/)e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{12,})`), "Encoded command payload"}, {"DOWNLOAD_EXECUTE", "CRITICAL", 40, regexp.MustCompile(`(?i)(invoke-webrequest|iwr|curl|wget).*(invoke-expression|iex|start-process|\|\s*(sh|bash))`), "Download followed by execution"}, {"DEFENDER_TAMPER", "CRITICAL", 45, regexp.MustCompile(`(?i)(set-mppreference|disableantispyware|disablebehaviormonitoring)`), "Security control modification"}, {"PERSISTENCE", "HIGH", 30, regexp.MustCompile(`(?i)(schtasks|new-service|sc\.exe\s+create|currentversion\\run|crontab)`), "Persistence mechanism"}, {"CREDENTIAL_ACCESS", "CRITICAL", 45, regexp.MustCompile(`(?i)(mimikatz|sekurlsa|lsass|credential.*dump|sam\\|ntds\.dit)`), "Credential-access behavior"}, {"OBFUSCATION", "MEDIUM", 20, regexp.MustCompile("(?i)(frombase64string|char\\]|bxor|`[a-z]|\\^.{1,2}\\^|eval\\s*\\()"), "Obfuscation indicator"}}
var iocPattern = regexp.MustCompile(`(?i)(https?://[^\s'"<>]+|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-f0-9]{64}\b)`)

func analyze(language, script string) Analysis {
	language = strings.ToUpper(strings.TrimSpace(language))
	a := Analysis{Language: language, Findings: []Finding{}, IOCs: []string{}, SignatureVersion: 1}
	subject := script
	for _, s := range signatures {
		matches := s.pattern.FindStringSubmatch(subject)
		if len(matches) > 0 {
			evidence := matches[0]
			if len(evidence) > 160 {
				evidence = evidence[:160]
			}
			a.Findings = append(a.Findings, Finding{s.code, s.severity, s.description, evidence})
			a.RiskScore += s.score
			if s.code == "ENCODED_COMMAND" && len(matches) > 1 {
				if decoded, ok := decodePowerShell(matches[1]); ok {
					a.Decoded = decoded
					subject += "\n" + decoded
				}
			}
		}
	}
	a.IOCs = unique(iocPattern.FindAllString(subject, -1))
	if a.RiskScore > 100 {
		a.RiskScore = 100
	}
	a.RiskLevel = "LOW"
	if a.RiskScore >= 80 {
		a.RiskLevel = "CRITICAL"
	} else if a.RiskScore >= 55 {
		a.RiskLevel = "HIGH"
	} else if a.RiskScore >= 25 {
		a.RiskLevel = "MEDIUM"
	}
	a.RequiresSandbox = a.RiskScore >= 55 || a.Decoded != ""
	return a
}
func decodePowerShell(v string) (string, bool) {
	raw, e := base64.StdEncoding.DecodeString(v)
	if e != nil {
		return "", false
	}
	if len(raw) >= 2 && len(raw)%2 == 0 {
		u := make([]uint16, len(raw)/2)
		for i := range u {
			u[i] = uint16(raw[i*2]) | uint16(raw[i*2+1])<<8
		}
		return string(utf16.Decode(u)), true
	}
	return string(raw), true
}
func unique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
func sha256hex(value []byte) string { return fmt.Sprintf("%x", sha256.Sum256(value)) }

type Handler struct{ db *pgxpool.Pool }

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(g *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if g == nil || h == nil || db == nil {
		return
	}
	h.db = db
	_ = ensure(context.Background(), db)
	r := g.Group("/commandanalysis")
	r.POST("/analyze", middleware.RequirePermission(db, "COMMAND_ANALYSIS_RUN"), h.Analyze)
	r.GET("/analyses", middleware.RequirePermission(db, "COMMAND_ANALYSIS_VIEW"), h.List)
	r.GET("/signatures", middleware.RequirePermission(db, "COMMAND_ANALYSIS_VIEW"), h.ListSignatures)
	r.POST("/analyses/:id/sandbox", middleware.RequirePermission(db, "COMMAND_ANALYSIS_RUN"), h.QueueSandbox)
}
func ensure(ctx context.Context, db *pgxpool.Pool) error {
	_, e := db.Exec(ctx, `CREATE TABLE IF NOT EXISTS command_analysis_results(id UUID PRIMARY KEY,organization_id UUID NOT NULL,language TEXT NOT NULL,script_sha256 CHAR(64) NOT NULL,analysis JSONB NOT NULL,signature_version INTEGER NOT NULL,created_by UUID,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());CREATE TABLE IF NOT EXISTS command_sandbox_jobs(id UUID PRIMARY KEY,organization_id UUID NOT NULL,analysis_id UUID NOT NULL,status TEXT NOT NULL DEFAULT 'QUEUED',isolation_profile TEXT NOT NULL,attempt_count INTEGER NOT NULL DEFAULT 0,result JSONB,last_error TEXT,created_by UUID,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),started_at TIMESTAMPTZ,completed_at TIMESTAMPTZ);`)
	if e == nil {
		_, e = db.Exec(ctx, `ALTER TABLE command_analysis_results ADD COLUMN IF NOT EXISTS artifact_uri TEXT`)
	}
	return e
}
func cid(c *gin.Context, key string) (uuid.UUID, bool) {
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

type request struct {
	Language    string `json:"language" binding:"required,oneof=POWERSHELL CMD BASH SH PYTHON JAVASCRIPT"`
	Script      string `json:"script" binding:"required,max=1048576"`
	ArtifactURI string `json:"artifact_uri"`
}

func (h *Handler) Analyze(c *gin.Context) {
	org, ok := cid(c, "organization_id")
	actor, _ := cid(c, "user_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var q request
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid command analysis request", e.Error())
		return
	}
	a := analyze(q.Language, q.Script)
	hash := sha256hex([]byte(q.Script))
	id := uuid.New()
	_, e := h.db.Exec(c, `INSERT INTO command_analysis_results(id,organization_id,language,script_sha256,artifact_uri,analysis,signature_version,created_by)VALUES($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8)`, id, org, a.Language, hash, q.ArtifactURI, a, a.SignatureVersion, actor)
	if e != nil {
		response.InternalServerError(c, "Could not persist command analysis", e.Error())
		return
	}
	response.Success(c, http.StatusCreated, "Command analysis completed", gin.H{"id": id, "script_sha256": hash, "analysis": a})
}
func (h *Handler) List(c *gin.Context) {
	org, ok := cid(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	rows, e := h.db.Query(c, `SELECT jsonb_build_object('id',id,'language',language,'script_sha256',script_sha256,'analysis',analysis,'signature_version',signature_version,'created_at',created_at) FROM command_analysis_results WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100`, org)
	if e != nil {
		response.InternalServerError(c, "Could not list analyses", e.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var v map[string]any
		if e = rows.Scan(&v); e != nil {
			response.InternalServerError(c, "Could not read analysis", e.Error())
			return
		}
		out = append(out, v)
	}
	response.OK(c, "Command analyses loaded", out)
}
func (h *Handler) ListSignatures(c *gin.Context) {
	out := []gin.H{}
	for _, s := range signatures {
		out = append(out, gin.H{"code": s.code, "severity": s.severity, "description": s.description, "version": 1})
	}
	response.OK(c, "Command signatures loaded", out)
}
func (h *Handler) QueueSandbox(c *gin.Context) {
	org, ok := cid(c, "organization_id")
	actor, _ := cid(c, "user_id")
	analysis, e := uuid.Parse(c.Param("id"))
	if !ok || e != nil {
		response.BadRequest(c, "Invalid analysis context", nil)
		return
	}
	var exists bool
	e = h.db.QueryRow(c, `SELECT EXISTS(SELECT 1 FROM command_analysis_results WHERE organization_id=$1 AND id=$2 AND artifact_uri IS NOT NULL)`, org, analysis).Scan(&exists)
	if e != nil || !exists {
		response.Error(c, http.StatusConflict, "Analysis requires an immutable artifact_uri before sandboxing", nil)
		return
	}
	id := uuid.New()
	_, e = h.db.Exec(c, `INSERT INTO command_sandbox_jobs(id,organization_id,analysis_id,status,isolation_profile,created_by)VALUES($1,$2,$3,'QUEUED','NO_NETWORK_EPHEMERAL_READONLY',$4)`, id, org, analysis, actor)
	if e != nil {
		response.InternalServerError(c, "Could not queue sandbox analysis", e.Error())
		return
	}
	response.Accepted(c, "Sandbox analysis queued", gin.H{"job_id": id, "status": "QUEUED", "isolation_profile": "NO_NETWORK_EPHEMERAL_READONLY"})
}
