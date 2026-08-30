package deepfakeforensics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	defaultTrainingPageSize = 20
	maximumTrainingPageSize = 100
)

// TrainingDataset is the organization-scoped, immutable source definition
// used by a model-training job. File content remains in protected storage.
type TrainingDataset struct {
	ID           uuid.UUID      `json:"id"`
	DatasetCode  string         `json:"dataset_code"`
	DatasetName  string         `json:"dataset_name"`
	Description  *string        `json:"description,omitempty"`
	MediaType    string         `json:"media_type"`
	StorageURI   string         `json:"storage_uri"`
	SHA256Hash   string         `json:"sha256_hash"`
	RecordCount  int64          `json:"record_count"`
	LabelSchema  map[string]any `json:"label_schema"`
	Metadata     map[string]any `json:"metadata"`
	Status       string         `json:"status"`
	RegisteredAt time.Time      `json:"registered_at"`
}

type RegisterTrainingDatasetRequest struct {
	DatasetCode string         `json:"dataset_code" binding:"required,max=100"`
	DatasetName string         `json:"dataset_name" binding:"required,max=255"`
	Description string         `json:"description" binding:"omitempty,max=4000"`
	MediaType   string         `json:"media_type" binding:"required"`
	StorageURI  string         `json:"storage_uri" binding:"required,max=4000"`
	SHA256Hash  string         `json:"sha256_hash" binding:"required,len=64"`
	RecordCount int64          `json:"record_count" binding:"gte=0"`
	LabelSchema map[string]any `json:"label_schema"`
	Metadata    map[string]any `json:"metadata"`
}

type TrainingDatasetListResponse struct {
	Items      []TrainingDataset `json:"items"`
	Total      int64             `json:"total"`
	Page       int               `json:"page"`
	PageSize   int               `json:"page_size"`
	TotalPages int               `json:"total_pages"`
}

type TrainingDatasetVersion struct {
	ID                uuid.UUID      `json:"id"`
	DatasetID         uuid.UUID      `json:"dataset_id"`
	VersionNumber     string         `json:"version_number"`
	StorageURI        string         `json:"storage_uri"`
	SHA256Hash        string         `json:"sha256_hash"`
	RecordCount       int64          `json:"record_count"`
	ClassDistribution map[string]any `json:"class_distribution"`
	ValidationSummary map[string]any `json:"validation_summary"`
	Status            string         `json:"status"`
	ValidatedAt       *time.Time     `json:"validated_at,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
}

type RegisterTrainingDatasetVersionRequest struct {
	VersionNumber     string         `json:"version_number" binding:"required,max=80"`
	StorageURI        string         `json:"storage_uri" binding:"required,max=4000"`
	SHA256Hash        string         `json:"sha256_hash" binding:"required,len=64"`
	RecordCount       int64          `json:"record_count" binding:"gte=0"`
	ClassDistribution map[string]any `json:"class_distribution"`
}

type ValidateTrainingDatasetVersionRequest struct {
	Approved          bool           `json:"approved"`
	ValidationSummary map[string]any `json:"validation_summary"`
}

type CreateTrainingJobRequest struct {
	DatasetVersionID       string         `json:"dataset_version_id" binding:"required"`
	AIModelID              string         `json:"ai_model_id" binding:"omitempty"`
	SplitConfiguration     map[string]any `json:"split_configuration" binding:"required"`
	TrainingConfiguration  map[string]any `json:"training_configuration"`
	ExecutionConfiguration map[string]any `json:"execution_configuration"`
}

type TrainingJob struct {
	ID                 uuid.UUID      `json:"id"`
	JobNumber          string         `json:"job_number"`
	DatasetVersionID   uuid.UUID      `json:"dataset_version_id"`
	AIModelID          *uuid.UUID     `json:"ai_model_id,omitempty"`
	Status             string         `json:"status"`
	SplitConfiguration map[string]any `json:"split_configuration"`
	ErrorCode          *string        `json:"error_code,omitempty"`
	ErrorMessage       *string        `json:"error_message,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
}
type TrainingJobListResponse struct {
	Items      []TrainingJob `json:"items"`
	Total      int64         `json:"total"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
	TotalPages int           `json:"total_pages"`
}

type TrainingJobMetric struct {
	MetricName   string    `json:"metric_name"`
	MetricValue  float64   `json:"metric_value"`
	DatasetSplit string    `json:"dataset_split"`
	EpochNumber  *int      `json:"epoch_number,omitempty"`
	RecordedAt   time.Time `json:"recorded_at"`
}

type TrainingJobDetail struct {
	TrainingJob
	JobType                string              `json:"job_type"`
	TrainingConfiguration  map[string]any      `json:"training_configuration"`
	ExecutionConfiguration map[string]any      `json:"execution_configuration"`
	TrainRecordCount       *int64              `json:"train_record_count,omitempty"`
	ValidationRecordCount  *int64              `json:"validation_record_count,omitempty"`
	TestRecordCount        *int64              `json:"test_record_count,omitempty"`
	WorkerNode             *string             `json:"worker_node,omitempty"`
	ArtifactPath           *string             `json:"artifact_path,omitempty"`
	ArtifactSHA256         *string             `json:"artifact_sha256,omitempty"`
	ArtifactFormat         *string             `json:"artifact_format,omitempty"`
	ProcessingDurationMS   *int64              `json:"processing_duration_ms,omitempty"`
	StartedAt              *time.Time          `json:"started_at,omitempty"`
	CompletedAt            *time.Time          `json:"completed_at,omitempty"`
	Metrics                []TrainingJobMetric `json:"metrics"`
}

type DecideTrainingApprovalRequest struct {
	Approved      bool   `json:"approved"`
	VersionNumber string `json:"version_number" binding:"omitempty,max=100"`
	Activate      bool   `json:"activate"`
	Reason        string `json:"reason" binding:"omitempty,max=2000"`
	AIModelID     string `json:"ai_model_id" binding:"omitempty"`
}

type TrainingApprovalDecision struct {
	TrainingJobID  uuid.UUID  `json:"training_job_id"`
	Decision       string     `json:"decision"`
	ModelVersionID *uuid.UUID `json:"model_version_id,omitempty"`
	Activated      bool       `json:"activated"`
}

type TrainingService struct{ repository *Repository }

func NewTrainingService(repository *Repository) (*TrainingService, error) {
	if repository == nil || !repository.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}
	return &TrainingService{repository: repository}, nil
}

func (s *TrainingService) isAvailable() bool {
	return s != nil && s.repository != nil && s.repository.IsAvailable()
}

func (s *TrainingService) RegisterDataset(ctx context.Context, organizationID, actorID uuid.UUID, request RegisterTrainingDatasetRequest) (*TrainingDataset, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil || actorID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	request.DatasetCode, request.DatasetName, request.MediaType = strings.TrimSpace(request.DatasetCode), strings.TrimSpace(request.DatasetName), NormalizeConstant(request.MediaType)
	request.StorageURI, request.SHA256Hash = strings.TrimSpace(request.StorageURI), strings.ToLower(strings.TrimSpace(request.SHA256Hash))
	if request.DatasetCode == "" || request.DatasetName == "" || request.StorageURI == "" || request.RecordCount < 0 || !isTrainingMediaType(request.MediaType) || !isSHA256(request.SHA256Hash) {
		return nil, fmt.Errorf("%w: invalid dataset details", ErrInvalidRepositoryInput)
	}
	labelSchema, err := json.Marshal(nonNilMap(request.LabelSchema))
	if err != nil {
		return nil, ErrInvalidRepositoryInput
	}
	metadata, err := json.Marshal(nonNilMap(request.Metadata))
	if err != nil {
		return nil, ErrInvalidRepositoryInput
	}
	row := s.repository.databasePool.QueryRow(ctx, `INSERT INTO ml_training_datasets (organization_id, dataset_code, dataset_name, description, media_type, storage_uri, sha256_hash, record_count, label_schema, metadata, status, registered_by) VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$9,$10,'REGISTERED',$11) RETURNING id, dataset_code, dataset_name, description, media_type, storage_uri, sha256_hash, record_count, label_schema, metadata, status, registered_at`, organizationID, request.DatasetCode, request.DatasetName, strings.TrimSpace(request.Description), request.MediaType, request.StorageURI, request.SHA256Hash, request.RecordCount, labelSchema, metadata, actorID)
	return scanTrainingDataset(row)
}

func (s *TrainingService) ListDatasets(ctx context.Context, organizationID uuid.UUID, page, pageSize int) (*TrainingDatasetListResponse, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	page, pageSize = normalizeTrainingPagination(page, pageSize)
	var total int64
	if err := s.repository.databasePool.QueryRow(ctx, `SELECT count(*) FROM ml_training_datasets WHERE organization_id=$1`, organizationID).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := s.repository.databasePool.Query(ctx, `SELECT id,dataset_code,dataset_name,description,media_type,storage_uri,sha256_hash,record_count,label_schema,metadata,status,registered_at FROM ml_training_datasets WHERE organization_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, organizationID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]TrainingDataset, 0)
	for rows.Next() {
		item, err := scanTrainingDataset(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &TrainingDatasetListResponse{Items: items, Total: total, Page: page, PageSize: pageSize, TotalPages: int(math.Ceil(float64(total) / float64(pageSize)))}, nil
}

func (s *TrainingService) RegisterDatasetVersion(ctx context.Context, organizationID, actorID, datasetID uuid.UUID, request RegisterTrainingDatasetVersionRequest) (*TrainingDatasetVersion, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil || actorID == uuid.Nil || datasetID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	request.VersionNumber = strings.TrimSpace(request.VersionNumber)
	request.StorageURI = strings.TrimSpace(request.StorageURI)
	request.SHA256Hash = strings.ToLower(strings.TrimSpace(request.SHA256Hash))
	if request.VersionNumber == "" || request.StorageURI == "" || request.RecordCount < 0 || !isSHA256(request.SHA256Hash) {
		return nil, fmt.Errorf("%w: invalid dataset version details", ErrInvalidRepositoryInput)
	}
	distribution, err := json.Marshal(nonNilMap(request.ClassDistribution))
	if err != nil {
		return nil, ErrInvalidRepositoryInput
	}
	row := s.repository.databasePool.QueryRow(ctx, `INSERT INTO ml_training_dataset_versions (dataset_id,version_number,storage_uri,sha256_hash,record_count,class_distribution,status,created_by) SELECT $1,$2,$3,$4,$5,$6,'DRAFT',$7 WHERE EXISTS (SELECT 1 FROM ml_training_datasets WHERE id=$1 AND organization_id=$8) RETURNING id,dataset_id,version_number,storage_uri,sha256_hash,record_count,class_distribution,validation_summary,status,validated_at,created_at`, datasetID, request.VersionNumber, request.StorageURI, request.SHA256Hash, request.RecordCount, distribution, actorID, organizationID)
	version, err := scanTrainingDatasetVersion(row)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("%w: dataset not found", ErrInvalidRepositoryInput)
	}
	return version, err
}

func (s *TrainingService) ValidateDatasetVersion(ctx context.Context, organizationID, actorID, datasetID, versionID uuid.UUID, request ValidateTrainingDatasetVersionRequest) (*TrainingDatasetVersion, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil || actorID == uuid.Nil || datasetID == uuid.Nil || versionID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	summary, err := json.Marshal(nonNilMap(request.ValidationSummary))
	if err != nil {
		return nil, ErrInvalidRepositoryInput
	}
	status := "REJECTED"
	if request.Approved {
		status = "READY"
	}
	row := s.repository.databasePool.QueryRow(ctx, `UPDATE ml_training_dataset_versions v SET status=$1,validation_summary=$2,validated_by=$3,validated_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP FROM ml_training_datasets d WHERE v.id=$4 AND v.dataset_id=$5 AND d.id=v.dataset_id AND d.organization_id=$6 AND v.status IN ('DRAFT','VALIDATING') RETURNING v.id,v.dataset_id,v.version_number,v.storage_uri,v.sha256_hash,v.record_count,v.class_distribution,v.validation_summary,v.status,v.validated_at,v.created_at`, status, summary, actorID, versionID, datasetID, organizationID)
	version, err := scanTrainingDatasetVersion(row)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("%w: dataset version is unavailable or already validated", ErrInvalidRepositoryInput)
	}
	return version, err
}

func (s *TrainingService) CreateJob(ctx context.Context, organizationID, actorID uuid.UUID, request CreateTrainingJobRequest) (*TrainingJob, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil || actorID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	datasetVersionID, err := uuid.Parse(strings.TrimSpace(request.DatasetVersionID))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid dataset version ID", ErrInvalidRepositoryInput)
	}
	var modelID *uuid.UUID
	if strings.TrimSpace(request.AIModelID) != "" {
		id, e := uuid.Parse(strings.TrimSpace(request.AIModelID))
		if e != nil {
			return nil, fmt.Errorf("%w: invalid AI model ID", ErrInvalidRepositoryInput)
		}
		modelID = &id
	}
	if !validSplit(request.SplitConfiguration) {
		return nil, fmt.Errorf("%w: split configuration must total 100", ErrInvalidRepositoryInput)
	}
	if modelID == nil {
		modelID, err = s.resolveTrainingModel(
			ctx,
			organizationID,
			actorID,
			datasetVersionID,
		)
		if err != nil {
			return nil, err
		}
	}
	split, _ := json.Marshal(request.SplitConfiguration)
	train, _ := json.Marshal(nonNilMap(request.TrainingConfiguration))
	execution, _ := json.Marshal(nonNilMap(request.ExecutionConfiguration))
	jobID := uuid.New()
	jobNumber := "MLT-" + time.Now().UTC().Format("20060102150405") + "-" + strings.ToUpper(jobID.String()[:8])
	row := s.repository.databasePool.QueryRow(ctx, `INSERT INTO ml_training_jobs (id,organization_id,dataset_version_id,ai_model_id,job_number,split_configuration,training_configuration,execution_configuration,requested_by) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9 WHERE EXISTS (SELECT 1 FROM ml_training_dataset_versions v JOIN ml_training_datasets d ON d.id=v.dataset_id WHERE v.id=$3 AND d.organization_id=$2 AND v.status='READY') AND ($4::uuid IS NULL OR EXISTS (SELECT 1 FROM ai_models m WHERE m.id=$4 AND m.organization_id=$2)) RETURNING id,job_number,dataset_version_id,ai_model_id,status,split_configuration,error_code,error_message,created_at`, jobID, organizationID, datasetVersionID, modelID, jobNumber, split, train, execution, actorID)
	job, err := scanTrainingJob(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("%w: dataset version is not ready for this organization", ErrInvalidRepositoryInput)
		}
		return nil, err
	}
	return job, nil
}

func (s *TrainingService) resolveTrainingModel(
	ctx context.Context,
	organizationID, actorID, datasetVersionID uuid.UUID,
) (*uuid.UUID, error) {
	var metadataJSON []byte
	err := s.repository.databasePool.QueryRow(ctx, `SELECT d.metadata FROM ml_training_dataset_versions v JOIN ml_training_datasets d ON d.id=v.dataset_id WHERE v.id=$1 AND d.organization_id=$2 AND v.status='READY'`, datasetVersionID, organizationID).Scan(&metadataJSON)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("%w: dataset version is not ready for this organization", ErrInvalidRepositoryInput)
		}
		return nil, err
	}
	var metadata map[string]any
	if json.Unmarshal(metadataJSON, &metadata) != nil {
		return nil, ErrInvalidRepositoryInput
	}
	if NormalizeConstant(fmt.Sprint(metadata["detector_scope"])) != JobTypeSyntheticImage {
		return nil, nil
	}
	const modelCode = "synthetic-image-detector"
	var modelID uuid.UUID
	err = s.repository.databasePool.QueryRow(ctx, `SELECT id FROM ai_models WHERE organization_id=$1 AND model_code=$2 AND model_type=$3 AND deleted_at IS NULL`, organizationID, modelCode, JobTypeDeepfakeImage).Scan(&modelID)
	if err == nil {
		return &modelID, nil
	}
	if err != pgx.ErrNoRows {
		return nil, err
	}
	modelID = uuid.New()
	_, err = s.repository.databasePool.Exec(ctx, `INSERT INTO ai_models (id,organization_id,model_code,model_name,description,model_type,framework,input_type,output_type,supports_offline_execution,supports_gpu,supports_cpu,status,created_by,created_at,updated_at) VALUES ($1,$2,$3,'AI Generated Image Detector','Dedicated whole-image classifier for camera-original versus AI-generated imagery.',$4,'PYTORCH','IMAGE','CLASSIFICATION',true,false,true,'DEVELOPMENT',$5,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, modelID, organizationID, modelCode, JobTypeDeepfakeImage, actorID)
	if err != nil {
		return nil, fmt.Errorf("create synthetic training model: %w", err)
	}
	return &modelID, nil
}

func (s *TrainingService) ListJobs(ctx context.Context, organizationID uuid.UUID, page, pageSize int) (*TrainingJobListResponse, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	page, pageSize = normalizeTrainingPagination(page, pageSize)
	var total int64
	if err := s.repository.databasePool.QueryRow(ctx, `SELECT count(*) FROM ml_training_jobs WHERE organization_id=$1`, organizationID).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := s.repository.databasePool.Query(ctx, `SELECT id,job_number,dataset_version_id,ai_model_id,status,split_configuration,error_code,error_message,created_at FROM ml_training_jobs WHERE organization_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, organizationID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]TrainingJob, 0)
	for rows.Next() {
		item, e := scanTrainingJob(rows)
		if e != nil {
			return nil, e
		}
		items = append(items, *item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return &TrainingJobListResponse{Items: items, Total: total, Page: page, PageSize: pageSize, TotalPages: int(math.Ceil(float64(total) / float64(pageSize)))}, nil
}

func (s *TrainingService) GetJob(ctx context.Context, organizationID, jobID uuid.UUID) (*TrainingJobDetail, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil || jobID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	var detail TrainingJobDetail
	var split, training, execution []byte
	err := s.repository.databasePool.QueryRow(ctx, `SELECT id,job_number,dataset_version_id,ai_model_id,status,split_configuration,error_code,error_message,created_at,job_type,training_configuration,execution_configuration,train_record_count,validation_record_count,test_record_count,worker_node,artifact_path,artifact_sha256,artifact_format,processing_duration_ms,started_at,completed_at FROM ml_training_jobs WHERE id=$1 AND organization_id=$2`, jobID, organizationID).Scan(
		&detail.ID, &detail.JobNumber, &detail.DatasetVersionID, &detail.AIModelID, &detail.Status, &split, &detail.ErrorCode, &detail.ErrorMessage, &detail.CreatedAt,
		&detail.JobType, &training, &execution, &detail.TrainRecordCount, &detail.ValidationRecordCount, &detail.TestRecordCount, &detail.WorkerNode,
		&detail.ArtifactPath, &detail.ArtifactSHA256, &detail.ArtifactFormat, &detail.ProcessingDurationMS, &detail.StartedAt, &detail.CompletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisJobNotFound
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(split, &detail.SplitConfiguration) != nil {
		detail.SplitConfiguration = map[string]any{}
	}
	if json.Unmarshal(training, &detail.TrainingConfiguration) != nil {
		detail.TrainingConfiguration = map[string]any{}
	}
	if json.Unmarshal(execution, &detail.ExecutionConfiguration) != nil {
		detail.ExecutionConfiguration = map[string]any{}
	}
	detail.Metrics = make([]TrainingJobMetric, 0)
	rows, err := s.repository.databasePool.Query(ctx, `SELECT metric_name,metric_value::float8,dataset_split,epoch_number,recorded_at FROM ml_training_job_metrics WHERE training_job_id=$1 ORDER BY epoch_number NULLS LAST,dataset_split,metric_name,recorded_at`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var metric TrainingJobMetric
		if err = rows.Scan(&metric.MetricName, &metric.MetricValue, &metric.DatasetSplit, &metric.EpochNumber, &metric.RecordedAt); err != nil {
			return nil, err
		}
		detail.Metrics = append(detail.Metrics, metric)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return &detail, nil
}

// CancelJob only cancels work that has not begun. A running training process
// requires an execution-engine cancellation contract and is deliberately not
// marked cancelled until that contract exists.
func (s *TrainingService) CancelJob(ctx context.Context, organizationID, jobID uuid.UUID) (*TrainingJob, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil || jobID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	row := s.repository.databasePool.QueryRow(ctx, `UPDATE ml_training_jobs SET status='CANCELLED',cancelled_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=$1 AND organization_id=$2 AND status='QUEUED' RETURNING id,job_number,dataset_version_id,ai_model_id,status,split_configuration,error_code,error_message,created_at`, jobID, organizationID)
	job, err := scanTrainingJob(row)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("%w: only queued training jobs can be cancelled", ErrAnalysisJobConflict)
	}
	return job, err
}

// DecideApproval records an irreversible analyst decision. Approval creates a
// version only from the worker-verified artifact; optional activation reuses
// the regular activation guard, including the hash and format checks.
func (s *TrainingService) DecideApproval(ctx context.Context, organizationID, actorID, jobID uuid.UUID, request DecideTrainingApprovalRequest) (*TrainingApprovalDecision, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil || actorID == uuid.Nil || jobID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	request.Reason, request.VersionNumber = strings.TrimSpace(request.Reason), strings.TrimSpace(request.VersionNumber)
	request.AIModelID = strings.TrimSpace(request.AIModelID)
	if request.Activate && !request.Approved {
		return nil, fmt.Errorf("%w: rejected training cannot be activated", ErrInvalidRepositoryInput)
	}
	tx, err := s.repository.databasePool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var modelID *uuid.UUID
	var artifactPath, artifactHash, artifactFormat string
	var datasetName, datasetVersion string
	var datasetMetadataJSON []byte
	err = tx.QueryRow(ctx, `SELECT j.ai_model_id,j.artifact_path,j.artifact_sha256,j.artifact_format,d.dataset_name,v.version_number,COALESCE(d.metadata,'{}'::jsonb) FROM ml_training_jobs j JOIN ml_training_dataset_versions v ON v.id=j.dataset_version_id JOIN ml_training_datasets d ON d.id=v.dataset_id WHERE j.id=$1 AND j.organization_id=$2 AND j.status='AWAITING_APPROVAL' FOR UPDATE`, jobID, organizationID).Scan(&modelID, &artifactPath, &artifactHash, &artifactFormat, &datasetName, &datasetVersion, &datasetMetadataJSON)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("%w: training job is not awaiting approval", ErrAnalysisJobConflict)
	}
	if err != nil {
		return nil, err
	}
	decision := "REJECTED"
	result := &TrainingApprovalDecision{TrainingJobID: jobID, Decision: decision}
	if !request.Approved {
		if _, err = tx.Exec(ctx, `INSERT INTO ml_training_model_approvals (training_job_id,decision,decision_reason,decided_by) VALUES ($1,'REJECTED',NULLIF($2,''),$3)`, jobID, request.Reason, actorID); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(ctx, `UPDATE ml_training_jobs SET status='COMPLETED',updated_at=CURRENT_TIMESTAMP WHERE id=$1`, jobID); err != nil {
			return nil, err
		}
		if err = tx.Commit(ctx); err != nil {
			return nil, err
		}
		return result, nil
	}
	if request.AIModelID != "" {
		requestedModelID, parseErr := uuid.Parse(request.AIModelID)
		if parseErr != nil || requestedModelID == uuid.Nil {
			return nil, fmt.Errorf("%w: invalid AI model ID", ErrInvalidRepositoryInput)
		}
		if modelID != nil && *modelID != uuid.Nil && *modelID != requestedModelID {
			return nil, fmt.Errorf("%w: training job is already assigned to a different AI model", ErrAnalysisJobConflict)
		}
		var modelType, framework, inputType string
		modelErr := tx.QueryRow(ctx, `SELECT model_type,framework,input_type FROM ai_models WHERE id=$1 AND organization_id=$2`, requestedModelID, organizationID).Scan(&modelType, &framework, &inputType)
		if modelErr == pgx.ErrNoRows {
			return nil, fmt.Errorf("%w: AI model is unavailable for this organization", ErrInvalidRepositoryInput)
		}
		if modelErr != nil {
			return nil, modelErr
		}
		normalizedModelType := NormalizeConstant(modelType)
		if (normalizedModelType != JobTypeDeepfakeImage && normalizedModelType != JobTypeSyntheticImage) || NormalizeConstant(framework) != "PYTORCH" || NormalizeConstant(inputType) != "IMAGE" {
			return nil, fmt.Errorf("%w: approved PTH artifact requires a PyTorch deepfake image model", ErrInvalidRepositoryInput)
		}
		if modelID == nil || *modelID == uuid.Nil {
			if _, err = tx.Exec(ctx, `UPDATE ml_training_jobs SET ai_model_id=$2,updated_at=CURRENT_TIMESTAMP WHERE id=$1`, jobID, requestedModelID); err != nil {
				return nil, err
			}
			modelID = &requestedModelID
		}
	}
	if modelID == nil || *modelID == uuid.Nil || artifactPath == "" || !isSHA256(strings.ToLower(artifactHash)) || NormalizeConstant(artifactFormat) != "PTH" {
		return nil, fmt.Errorf("%w: approved training needs an assigned model and verified PTH artifact", ErrInvalidRepositoryInput)
	}
	if request.VersionNumber == "" {
		request.VersionNumber = "trained-" + time.Now().UTC().Format("20060102150405")
	}
	versionID := uuid.New()
	var validationAccuracy *float64
	_ = tx.QueryRow(ctx, `SELECT metric_value::float8 FROM ml_training_job_metrics WHERE training_job_id=$1 AND metric_name='accuracy' AND dataset_split='VALIDATION' ORDER BY epoch_number DESC NULLS LAST, recorded_at DESC LIMIT 1`, jobID).Scan(&validationAccuracy)
	configurationValues := map[string]any{"training_job_id": jobID.String(), "artifact_verified_by": "training-worker"}
	var datasetMetadata map[string]any
	if json.Unmarshal(datasetMetadataJSON, &datasetMetadata) == nil {
		for _, key := range []string{"preprocessing", "face_context_analysis", "context_scale", "detector_scope", "positive_class_semantics", "negative_class_semantics", "whole_image_analysis"} {
			if value, exists := datasetMetadata[key]; exists {
				configurationValues[key] = value
			}
		}
		if imageSize, exists := datasetMetadata["image_size"]; exists {
			configurationValues["input_width"] = imageSize
			configurationValues["input_height"] = imageSize
		}
	}
	configuration, _ := json.Marshal(configurationValues)
	_, err = tx.Exec(ctx, `INSERT INTO ai_model_versions (id,ai_model_id,version_number,version_name,model_file_path,model_file_hash,hash_algorithm,model_format,training_dataset_name,training_dataset_version,training_record_count,validation_accuracy,configuration,is_default,status,created_by,trained_at,validated_at,created_at,updated_at) SELECT $1,$2,$3,$4,$5,$6,'SHA256','PTH',$7,$8,j.train_record_count,$9,$10,false,'VALIDATED',$11,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM ml_training_jobs j WHERE j.id=$12`, versionID, *modelID, request.VersionNumber, "Trained "+request.VersionNumber, artifactPath, strings.ToLower(artifactHash), datasetName, datasetVersion, validationAccuracy, configuration, actorID, jobID)
	if err != nil {
		return nil, fmt.Errorf("create trained model version: %w", err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ml_training_model_approvals (training_job_id,ai_model_version_id,decision,decision_reason,decided_by) VALUES ($1,$2,'APPROVED',NULLIF($3,''),$4)`, jobID, versionID, request.Reason, actorID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE ml_training_jobs SET status='COMPLETED',updated_at=CURRENT_TIMESTAMP WHERE id=$1`, jobID); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	result.Decision, result.ModelVersionID = "APPROVED", &versionID
	if request.Activate {
		modelService, serviceErr := NewModelManagementService(s.repository, "")
		if serviceErr != nil {
			return nil, serviceErr
		}
		if err = modelService.repository.ActivateManagedAIModelVersion(ctx, organizationID, *modelID, versionID, actorID, request.Reason); err != nil {
			return nil, err
		}
		if _, err = s.repository.databasePool.Exec(ctx, `UPDATE ml_training_model_approvals SET activated_at=CURRENT_TIMESTAMP,activation_reason=NULLIF($2,'') WHERE training_job_id=$1 AND ai_model_version_id=$3`, jobID, request.Reason, versionID); err != nil {
			return nil, err
		}
		result.Activated = true
	}
	return result, nil
}

type trainingRow interface{ Scan(...any) error }

func scanTrainingDataset(row trainingRow) (*TrainingDataset, error) {
	var item TrainingDataset
	var labels, metadata []byte
	err := row.Scan(&item.ID, &item.DatasetCode, &item.DatasetName, &item.Description, &item.MediaType, &item.StorageURI, &item.SHA256Hash, &item.RecordCount, &labels, &metadata, &item.Status, &item.RegisteredAt)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(labels, &item.LabelSchema) != nil {
		item.LabelSchema = map[string]any{}
	}
	if json.Unmarshal(metadata, &item.Metadata) != nil {
		item.Metadata = map[string]any{}
	}
	return &item, nil
}
func scanTrainingJob(row trainingRow) (*TrainingJob, error) {
	var item TrainingJob
	var split []byte
	err := row.Scan(&item.ID, &item.JobNumber, &item.DatasetVersionID, &item.AIModelID, &item.Status, &split, &item.ErrorCode, &item.ErrorMessage, &item.CreatedAt)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(split, &item.SplitConfiguration) != nil {
		item.SplitConfiguration = map[string]any{}
	}
	return &item, nil
}

func scanTrainingDatasetVersion(row trainingRow) (*TrainingDatasetVersion, error) {
	var item TrainingDatasetVersion
	var distribution, summary []byte
	err := row.Scan(&item.ID, &item.DatasetID, &item.VersionNumber, &item.StorageURI, &item.SHA256Hash, &item.RecordCount, &distribution, &summary, &item.Status, &item.ValidatedAt, &item.CreatedAt)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(distribution, &item.ClassDistribution) != nil {
		item.ClassDistribution = map[string]any{}
	}
	if json.Unmarshal(summary, &item.ValidationSummary) != nil {
		item.ValidationSummary = map[string]any{}
	}
	return &item, nil
}
func normalizeTrainingPagination(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = defaultTrainingPageSize
	}
	if pageSize > maximumTrainingPageSize {
		pageSize = maximumTrainingPageSize
	}
	return page, pageSize
}
func nonNilMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}
func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func isTrainingMediaType(value string) bool {
	for _, candidate := range []string{"IMAGE", "VIDEO", "AUDIO", "DOCUMENT", "MULTIMODAL"} {
		if value == candidate {
			return true
		}
	}
	return false
}
func validSplit(values map[string]any) bool {
	if values == nil {
		return false
	}
	total := 0.0
	for _, key := range []string{"train", "validation", "test"} {
		value, ok := values[key]
		if !ok {
			return false
		}
		number, ok := value.(float64)
		if !ok || number < 0 {
			return false
		}
		total += number
	}
	return math.Abs(total-100) < 0.0001
}
