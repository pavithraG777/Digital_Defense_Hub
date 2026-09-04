package operational

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AnalysisJobRequest struct {
	AnalysisType string         `json:"analysis_type" binding:"required,max=100"`
	TargetURI    string         `json:"target_uri" binding:"required,max=4000"`
	FileName     string         `json:"file_name" binding:"max=255"`
	MIMEType     string         `json:"mime_type" binding:"max=150"`
	SHA256Hash   *string        `json:"sha256_hash" binding:"omitempty,len=64,hexadecimal"`
	Parameters   map[string]any `json:"parameters"`
}

type AnalysisJob struct {
	ID           uuid.UUID      `json:"id"`
	Module       string         `json:"module"`
	AnalysisType string         `json:"analysis_type"`
	TargetURI    string         `json:"target_uri"`
	FileName     string         `json:"file_name"`
	MIMEType     string         `json:"mime_type"`
	SHA256Hash   *string        `json:"sha256_hash,omitempty"`
	Status       string         `json:"status"`
	Parameters   map[string]any `json:"parameters"`
	Result       map[string]any `json:"result"`
	ErrorCode    *string        `json:"error_code,omitempty"`
	ErrorMessage *string        `json:"error_message,omitempty"`
	RequestedBy  uuid.UUID      `json:"requested_by"`
	RequestedAt  time.Time      `json:"requested_at"`
	WorkerID     *string        `json:"worker_id,omitempty"`
	LeaseExpires *time.Time     `json:"lease_expires_at,omitempty"`
	AttemptCount int            `json:"attempt_count"`
	StartedAt    *time.Time     `json:"started_at,omitempty"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
}

type AnalysisJobStore struct {
	DB     *pgxpool.Pool
	Module string
}

const analysisJobColumns = `id,module,analysis_type,target_uri,file_name,mime_type,sha256_hash,status,parameters,result,error_code,error_message,requested_by,requested_at,worker_id,lease_expires_at,attempt_count,started_at,completed_at`

type analysisJobScanner interface{ Scan(...any) error }

func scanAnalysisJob(s analysisJobScanner) (AnalysisJob, error) {
	var job AnalysisJob
	err := s.Scan(&job.ID, &job.Module, &job.AnalysisType, &job.TargetURI, &job.FileName, &job.MIMEType, &job.SHA256Hash, &job.Status, &job.Parameters, &job.Result, &job.ErrorCode, &job.ErrorMessage, &job.RequestedBy, &job.RequestedAt, &job.WorkerID, &job.LeaseExpires, &job.AttemptCount, &job.StartedAt, &job.CompletedAt)
	return job, err
}

func (s AnalysisJobStore) Create(c *gin.Context, forcedType string) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := ContextUUID(c, "user_id")
	if !ok {
		return
	}
	var request AnalysisJobRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid analysis request", "error": err.Error()})
		return
	}
	if forcedType != "" {
		request.AnalysisType = forcedType
	}
	request.AnalysisType = strings.ToUpper(strings.TrimSpace(request.AnalysisType))
	request.TargetURI = strings.TrimSpace(request.TargetURI)
	request.FileName = strings.TrimSpace(request.FileName)
	request.MIMEType = strings.TrimSpace(request.MIMEType)
	if request.MIMEType == "" {
		request.MIMEType = "application/octet-stream"
	}
	if request.Parameters == nil {
		request.Parameters = map[string]any{}
	}
	job, err := scanAnalysisJob(s.DB.QueryRow(c, `INSERT INTO operational_analysis_jobs(id,organization_id,module,analysis_type,target_uri,file_name,mime_type,sha256_hash,status,parameters,requested_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'AWAITING_EXECUTOR',$9,$10) RETURNING `+analysisJobColumns, uuid.New(), org, s.Module, request.AnalysisType, request.TargetURI, request.FileName, request.MIMEType, request.SHA256Hash, request.Parameters, actor))
	if err != nil {
		Failure(c, 500, "Analysis job could not be stored")
		return
	}
	c.JSON(202, gin.H{"success": true, "message": "Analysis job stored and awaiting an authorized executor", "data": job})
}

func (s AnalysisJobStore) List(c *gin.Context) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	rows, err := s.DB.Query(c, `SELECT `+analysisJobColumns+` FROM operational_analysis_jobs WHERE organization_id=$1 AND module=$2 ORDER BY requested_at DESC LIMIT 500`, org, s.Module)
	if err != nil {
		Failure(c, 500, "Analysis jobs could not be loaded")
		return
	}
	defer rows.Close()
	items := make([]AnalysisJob, 0)
	for rows.Next() {
		job, err := scanAnalysisJob(rows)
		if err != nil {
			Failure(c, 500, "Analysis jobs could not be read")
			return
		}
		items = append(items, job)
	}
	c.JSON(200, gin.H{"success": true, "data": items})
}

func (s AnalysisJobStore) Get(c *gin.Context, idText string) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	id, err := uuid.Parse(idText)
	if err != nil {
		Failure(c, 400, "Invalid analysis job ID")
		return
	}
	job, err := scanAnalysisJob(s.DB.QueryRow(c, `SELECT `+analysisJobColumns+` FROM operational_analysis_jobs WHERE organization_id=$1 AND module=$2 AND id=$3`, org, s.Module, id))
	if err == pgx.ErrNoRows {
		Failure(c, 404, "Analysis job not found")
		return
	}
	if err != nil {
		Failure(c, 500, "Analysis job could not be retrieved")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": job})
}
