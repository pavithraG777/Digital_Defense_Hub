package operational

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AnalysisExecutorStore struct{ DB *pgxpool.Pool }

type claimRequest struct {
	WorkerID     string `json:"worker_id" binding:"required,max=200"`
	Module       string `json:"module" binding:"max=80"`
	LeaseSeconds int    `json:"lease_seconds" binding:"omitempty,min=30,max=900"`
}

type workerRequest struct {
	WorkerID     string `json:"worker_id" binding:"required,max=200"`
	LeaseSeconds int    `json:"lease_seconds" binding:"omitempty,min=30,max=900"`
}

type resultRequest struct {
	WorkerID     string         `json:"worker_id" binding:"required,max=200"`
	Status       string         `json:"status" binding:"required,oneof=COMPLETED FAILED"`
	Result       map[string]any `json:"result"`
	ErrorCode    *string        `json:"error_code" binding:"omitempty,max=100"`
	ErrorMessage *string        `json:"error_message" binding:"omitempty,max=4000"`
}

func leaseDuration(seconds int) time.Duration {
	if seconds == 0 {
		seconds = 120
	}
	return time.Duration(seconds) * time.Second
}

func addJobEvent(c *gin.Context, tx pgx.Tx, org, jobID uuid.UUID, event, previous, next string, worker *string, actor *uuid.UUID, details map[string]any) error {
	_, err := tx.Exec(c, `INSERT INTO operational_analysis_job_events(id,organization_id,job_id,event_type,previous_status,new_status,worker_id,actor_id,details) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, uuid.New(), org, jobID, event, previous, next, worker, actor, details)
	return err
}

func (s AnalysisExecutorStore) Claim(c *gin.Context) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := ContextUUID(c, "user_id")
	if !ok {
		return
	}
	var q claimRequest
	if err := c.ShouldBindJSON(&q); err != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid claim request", "error": err.Error()})
		return
	}
	q.WorkerID, q.Module = strings.TrimSpace(q.WorkerID), strings.ToUpper(strings.TrimSpace(q.Module))
	tx, err := s.DB.Begin(c)
	if err != nil {
		Failure(c, 500, "Could not begin job claim")
		return
	}
	defer tx.Rollback(c)
	var id uuid.UUID
	var previousStatus string
	err = tx.QueryRow(c, `SELECT id,status FROM operational_analysis_jobs WHERE organization_id=$1 AND ($2='' OR module=$2) AND (status IN ('QUEUED','AWAITING_EXECUTOR') OR (status='RUNNING' AND lease_expires_at<NOW())) ORDER BY requested_at FOR UPDATE SKIP LOCKED LIMIT 1`, org, q.Module).Scan(&id, &previousStatus)
	if err == pgx.ErrNoRows {
		c.JSON(204, nil)
		return
	}
	if err != nil {
		Failure(c, 500, "Claimable jobs could not be read")
		return
	}
	job, err := scanAnalysisJob(tx.QueryRow(c, `UPDATE operational_analysis_jobs SET status='RUNNING',worker_id=$3,lease_expires_at=NOW()+($4 * interval '1 second'),attempt_count=attempt_count+1,started_at=COALESCE(started_at,NOW()),completed_at=NULL,error_code=NULL,error_message=NULL WHERE organization_id=$1 AND id=$2 RETURNING `+analysisJobColumns, org, id, q.WorkerID, int(leaseDuration(q.LeaseSeconds).Seconds())))
	if err != nil {
		Failure(c, 500, "Job could not be claimed")
		return
	}
	if err = addJobEvent(c, tx, org, id, "CLAIMED", previousStatus, "RUNNING", &q.WorkerID, &actor, map[string]any{"lease_seconds": int(leaseDuration(q.LeaseSeconds).Seconds())}); err != nil {
		Failure(c, 500, "Job claim audit could not be stored")
		return
	}
	if err = tx.Commit(c); err != nil {
		Failure(c, 500, "Job claim could not be committed")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": job})
}

func (s AnalysisExecutorStore) Heartbeat(c *gin.Context) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Failure(c, 400, "Invalid analysis job ID")
		return
	}
	var q workerRequest
	if err = c.ShouldBindJSON(&q); err != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid heartbeat", "error": err.Error()})
		return
	}
	job, err := scanAnalysisJob(s.DB.QueryRow(c, `UPDATE operational_analysis_jobs SET lease_expires_at=NOW()+($4 * interval '1 second') WHERE organization_id=$1 AND id=$2 AND status='RUNNING' AND worker_id=$3 AND lease_expires_at>=NOW() RETURNING `+analysisJobColumns, org, id, strings.TrimSpace(q.WorkerID), int(leaseDuration(q.LeaseSeconds).Seconds())))
	if err == pgx.ErrNoRows {
		Failure(c, 409, "Job is not actively leased by this worker")
		return
	}
	if err != nil {
		Failure(c, 500, "Job heartbeat failed")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": job})
}

func (s AnalysisExecutorStore) Complete(c *gin.Context) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := ContextUUID(c, "user_id")
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Failure(c, 400, "Invalid analysis job ID")
		return
	}
	var q resultRequest
	if err = c.ShouldBindJSON(&q); err != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid job result", "error": err.Error()})
		return
	}
	if q.Result == nil {
		q.Result = map[string]any{}
	}
	if q.Status == "COMPLETED" && (q.ErrorCode != nil || q.ErrorMessage != nil) {
		Failure(c, 400, "Completed jobs cannot contain an error")
		return
	}
	if q.Status == "FAILED" && q.ErrorMessage == nil {
		Failure(c, 400, "Failed jobs require error_message")
		return
	}
	tx, err := s.DB.Begin(c)
	if err != nil {
		Failure(c, 500, "Could not begin result update")
		return
	}
	defer tx.Rollback(c)
	job, err := scanAnalysisJob(tx.QueryRow(c, `UPDATE operational_analysis_jobs SET status=$4,result=$5,error_code=$6,error_message=$7,completed_at=NOW(),lease_expires_at=NULL WHERE organization_id=$1 AND id=$2 AND status='RUNNING' AND worker_id=$3 AND lease_expires_at>=NOW() RETURNING `+analysisJobColumns, org, id, strings.TrimSpace(q.WorkerID), q.Status, q.Result, q.ErrorCode, q.ErrorMessage))
	if err == pgx.ErrNoRows {
		Failure(c, 409, "Job is not running under this worker")
		return
	}
	if err != nil {
		Failure(c, 500, "Job result could not be stored")
		return
	}
	if err = addJobEvent(c, tx, org, id, q.Status, "RUNNING", q.Status, &q.WorkerID, &actor, map[string]any{"error_code": q.ErrorCode}); err != nil {
		Failure(c, 500, "Job result audit could not be stored")
		return
	}
	if err = tx.Commit(c); err != nil {
		Failure(c, 500, "Job result could not be committed")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": job})
}

func (s AnalysisExecutorStore) Transition(c *gin.Context, retry bool) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := ContextUUID(c, "user_id")
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Failure(c, 400, "Invalid analysis job ID")
		return
	}
	previous, next, event := "FAILED", "AWAITING_EXECUTOR", "RETRIED"
	allowed := []string{"FAILED", "CANCELLED"}
	if !retry {
		previous, next, event, allowed = "ACTIVE", "CANCELLED", "CANCELLED", []string{"QUEUED", "AWAITING_EXECUTOR", "RUNNING"}
	}
	tx, err := s.DB.Begin(c)
	if err != nil {
		Failure(c, 500, "Could not begin job transition")
		return
	}
	defer tx.Rollback(c)
	job, err := scanAnalysisJob(tx.QueryRow(c, `UPDATE operational_analysis_jobs SET status=$4,worker_id=NULL,lease_expires_at=NULL,completed_at=CASE WHEN $4='CANCELLED' THEN NOW() ELSE NULL END,error_code=NULL,error_message=NULL,result='{}'::jsonb WHERE organization_id=$1 AND id=$2 AND status=ANY($3) RETURNING `+analysisJobColumns, org, id, allowed, next))
	if err == pgx.ErrNoRows {
		Failure(c, 409, "Job cannot perform this transition from its current status")
		return
	}
	if err != nil {
		Failure(c, 500, "Job transition failed")
		return
	}
	if err = addJobEvent(c, tx, org, id, event, previous, next, nil, &actor, map[string]any{}); err != nil {
		Failure(c, 500, "Job transition audit could not be stored")
		return
	}
	if err = tx.Commit(c); err != nil {
		Failure(c, 500, "Job transition could not be committed")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": job})
}
