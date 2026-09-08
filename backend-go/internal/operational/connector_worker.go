package operational

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/deepfakeforensics"
	"go.uber.org/zap"
)

type MediaConnector interface {
	Analyze(context.Context, deepfakeforensics.MediaEngineRequest) (*deepfakeforensics.MediaEngineResponse, error)
}

type ConnectorWorker struct {
	db               *pgxpool.Pool
	media            MediaConnector
	allowedRoots     []string
	pollInterval     time.Duration
	timeout          time.Duration
	workerID         string
	logger           *zap.Logger
	malwareCommand   string
	memoryCommand    string
	httpClient       *http.Client
	siemURL          string
	ticketURL        string
	integrationToken string
	startOnce        sync.Once
}

func (w *ConnectorWorker) Status() map[string]any {
	return map[string]any{"worker_id": w.workerID, "media_engine_configured": w.media != nil, "malware_scanner_configured": w.malwareCommand != "", "memory_scanner_configured": w.memoryCommand != "", "siem_connector_configured": w.siemURL != "", "ticket_connector_configured": w.ticketURL != "", "allowed_root_count": len(w.allowedRoots)}
}

func NewConnectorWorker(db *pgxpool.Pool, media MediaConnector, roots []string, pollInterval, timeout time.Duration, workerID string, logger *zap.Logger) (*ConnectorWorker, error) {
	if db == nil {
		return nil, errors.New("operational connector database is required")
	}
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	if strings.TrimSpace(workerID) == "" {
		workerID = "operational-connectors"
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	cleanRoots := make([]string, 0, len(roots))
	for _, root := range roots {
		absolute, err := filepath.Abs(strings.TrimSpace(root))
		if err == nil && strings.TrimSpace(root) != "" {
			cleanRoots = append(cleanRoots, filepath.Clean(absolute))
		}
	}
	if len(cleanRoots) == 0 {
		return nil, errors.New("at least one operational connector file root is required")
	}
	malwareCommand := strings.TrimSpace(os.Getenv("MALWARE_SCANNER_COMMAND"))
	if malwareCommand == "" {
		malwareCommand, _ = exec.LookPath("clamscan")
	}
	memoryCommand := strings.TrimSpace(os.Getenv("MEMORY_FORENSICS_COMMAND"))
	if memoryCommand == "" {
		memoryCommand, _ = exec.LookPath("vol")
	}
	return &ConnectorWorker{db: db, media: media, allowedRoots: cleanRoots, pollInterval: pollInterval, timeout: timeout, workerID: workerID, logger: logger, malwareCommand: malwareCommand, memoryCommand: memoryCommand, httpClient: &http.Client{Timeout: timeout}, siemURL: strings.TrimSpace(os.Getenv("SIEM_WEBHOOK_URL")), ticketURL: strings.TrimSpace(os.Getenv("TICKETING_WEBHOOK_URL")), integrationToken: strings.TrimSpace(os.Getenv("INTEGRATION_CONNECTOR_TOKEN"))}, nil
}

func (w *ConnectorWorker) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("operational connector context is required")
	}
	w.startOnce.Do(func() { go w.run(ctx) })
	return nil
}

func (w *ConnectorWorker) run(ctx context.Context) {
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()
	for {
		if err := w.processOne(ctx); err != nil && !errors.Is(err, pgx.ErrNoRows) && !errors.Is(err, context.Canceled) {
			w.logger.Warn("operational connector job failed", zap.Error(err))
		}
		if err := w.processIntegrationAction(ctx); err != nil && !errors.Is(err, pgx.ErrNoRows) && !errors.Is(err, context.Canceled) {
			w.logger.Warn("integration connector action failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type connectorJob struct {
	ID                                                  uuid.UUID
	OrganizationID                                      uuid.UUID
	Module, AnalysisType, TargetURI, FileName, MIMEType string
	ExpectedHash                                        *string
	Parameters                                          map[string]any
}

func (w *ConnectorWorker) processOne(parent context.Context) error {
	tx, err := w.db.Begin(parent)
	if err != nil {
		return err
	}
	defer tx.Rollback(parent)
	var job connectorJob
	err = tx.QueryRow(parent, `SELECT id,organization_id,module,analysis_type,target_uri,file_name,mime_type,sha256_hash,parameters FROM operational_analysis_jobs WHERE module=ANY($1) AND (status IN ('QUEUED','AWAITING_EXECUTOR') OR (status='RUNNING' AND lease_expires_at<NOW())) ORDER BY requested_at FOR UPDATE SKIP LOCKED LIMIT 1`, []string{"IMAGE", "FACE", "AUDIO", "DOCUMENT", "SURVEILLANCE", "MALWARE", "MEMORY_FORENSICS", "EMAIL", "SECURITY_COPILOT"}).Scan(&job.ID, &job.OrganizationID, &job.Module, &job.AnalysisType, &job.TargetURI, &job.FileName, &job.MIMEType, &job.ExpectedHash, &job.Parameters)
	if err != nil {
		return err
	}
	_, err = tx.Exec(parent, `UPDATE operational_analysis_jobs SET status='RUNNING',worker_id=$2,lease_expires_at=NOW()+($3*interval '1 second'),attempt_count=attempt_count+1,started_at=COALESCE(started_at,NOW()),completed_at=NULL,error_code=NULL,error_message=NULL WHERE id=$1`, job.ID, w.workerID, int(w.timeout.Seconds()))
	if err == nil {
		err = addJobEventContext(parent, tx, job.OrganizationID, job.ID, "CONNECTOR_CLAIMED", "AWAITING_EXECUTOR", "RUNNING", w.workerID, map[string]any{"connector": "MEDIA_ENGINE"})
	}
	if err != nil {
		return err
	}
	if err = tx.Commit(parent); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(parent, w.timeout)
	defer cancel()
	result, code, runErr := w.executeConnector(ctx, job)
	status := "COMPLETED"
	message := ""
	if runErr != nil {
		status, message = "FAILED", runErr.Error()
	}
	return w.finish(parent, job, status, code, message, result)
}

func (w *ConnectorWorker) executeMedia(ctx context.Context, job connectorJob) (map[string]any, string, error) {
	if w.media == nil {
		return nil, "MEDIA_CONNECTOR_UNAVAILABLE", errors.New("authenticated media analysis connector is not configured")
	}
	path, err := w.authorizedPath(job.TargetURI)
	if err != nil {
		return nil, "SOURCE_PATH_REJECTED", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, "SOURCE_FILE_UNAVAILABLE", err
	}
	if !info.Mode().IsRegular() {
		return nil, "SOURCE_NOT_REGULAR_FILE", errors.New("analysis source is not a regular file")
	}
	hash, err := fileSHA256(path)
	if err != nil {
		return nil, "SOURCE_HASH_FAILED", err
	}
	if job.ExpectedHash != nil && !strings.EqualFold(strings.TrimSpace(*job.ExpectedHash), hash) {
		return nil, "SOURCE_HASH_MISMATCH", errors.New("analysis source SHA-256 does not match the registered hash")
	}
	jobType, mediaType, err := mediaContract(job)
	if err != nil {
		return nil, "UNSUPPORTED_MEDIA_JOB", err
	}
	evidenceID := job.ID
	request := deepfakeforensics.MediaEngineRequest{RequestID: uuid.New(), OrganizationID: job.OrganizationID, AnalysisJobID: job.ID, EvidenceID: &evidenceID, JobType: jobType, MediaType: mediaType, FileName: firstNonEmpty(job.FileName, filepath.Base(path)), MimeType: job.MIMEType, SourceFilePath: path, FileSizeBytes: info.Size(), FileHash: hash, ExecutionDevice: parameterString(job.Parameters, "execution_device", "CPU"), Parameters: job.Parameters, RequestedAt: time.Now().UTC()}
	response, err := w.media.Analyze(ctx, request)
	if err != nil {
		code := "MEDIA_ENGINE_FAILED"
		if errors.Is(err, deepfakeforensics.ErrMediaEngineUnavailable) {
			code = "MEDIA_CONNECTOR_UNAVAILABLE"
		}
		return nil, code, err
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, "MEDIA_RESULT_ENCODING_FAILED", err
	}
	var result map[string]any
	if err = json.Unmarshal(encoded, &result); err != nil {
		return nil, "MEDIA_RESULT_ENCODING_FAILED", err
	}
	result["verified_source_sha256"] = hash
	return result, "", nil
}

func mediaContract(job connectorJob) (string, string, error) {
	switch job.Module {
	case "IMAGE":
		return deepfakeforensics.JobTypeImageForensics, deepfakeforensics.MediaTypeImage, nil
	case "FACE":
		return deepfakeforensics.JobTypeDeepfakeImage, deepfakeforensics.MediaTypeImage, nil
	case "AUDIO":
		return deepfakeforensics.JobTypeAudioForensics, deepfakeforensics.MediaTypeAudio, nil
	case "DOCUMENT":
		return deepfakeforensics.JobTypeOCRExtraction, deepfakeforensics.MediaTypeDocument, nil
	case "SURVEILLANCE":
		if strings.HasPrefix(strings.ToLower(job.MIMEType), "video/") {
			return deepfakeforensics.JobTypeVideoForensics, deepfakeforensics.MediaTypeVideo, nil
		}
		if strings.HasPrefix(strings.ToLower(job.MIMEType), "image/") {
			return deepfakeforensics.JobTypeImageForensics, deepfakeforensics.MediaTypeImage, nil
		}
	}
	return "", "", fmt.Errorf("module %s with MIME type %s is not supported by the media engine", job.Module, job.MIMEType)
}

func (w *ConnectorWorker) authorizedPath(value string) (string, error) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "file://"))
	absolute, err := filepath.Abs(filepath.FromSlash(value))
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	for _, root := range w.allowedRoots {
		relative, relErr := filepath.Rel(root, absolute)
		if relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return absolute, nil
		}
	}
	return "", errors.New("analysis source is outside configured connector roots")
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err = io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func (w *ConnectorWorker) finish(ctx context.Context, job connectorJob, status, code, message string, result map[string]any) error {
	if result == nil {
		result = map[string]any{}
	}
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var errorCode, errorMessage any
	if code != "" {
		errorCode = code
	}
	if message != "" {
		errorMessage = message
	}
	command, err := tx.Exec(ctx, `UPDATE operational_analysis_jobs SET status=$3,result=$4,error_code=$5,error_message=$6,completed_at=NOW(),lease_expires_at=NULL WHERE id=$1 AND worker_id=$2 AND status='RUNNING'`, job.ID, w.workerID, status, result, errorCode, errorMessage)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return errors.New("connector lost ownership of analysis job")
	}
	if err = addJobEventContext(ctx, tx, job.OrganizationID, job.ID, "CONNECTOR_"+status, "RUNNING", status, w.workerID, map[string]any{"error_code": code}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func addJobEventContext(ctx context.Context, tx pgx.Tx, org, job uuid.UUID, event, previous, next, worker string, details map[string]any) error {
	_, err := tx.Exec(ctx, `INSERT INTO operational_analysis_job_events(id,organization_id,job_id,event_type,previous_status,new_status,worker_id,details) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, uuid.New(), org, job, event, previous, next, worker, details)
	return err
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
func parameterString(values map[string]any, key, fallback string) string {
	if value, ok := values[key].(string); ok && strings.TrimSpace(value) != "" {
		return strings.ToUpper(strings.TrimSpace(value))
	}
	return fallback
}
