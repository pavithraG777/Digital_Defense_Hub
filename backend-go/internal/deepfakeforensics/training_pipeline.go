package deepfakeforensics

import (
	"context"
	"encoding/json"
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
	CreatedAt          time.Time      `json:"created_at"`
}
type TrainingJobListResponse struct {
	Items      []TrainingJob `json:"items"`
	Total      int64         `json:"total"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
	TotalPages int           `json:"total_pages"`
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
	split, _ := json.Marshal(request.SplitConfiguration)
	train, _ := json.Marshal(nonNilMap(request.TrainingConfiguration))
	execution, _ := json.Marshal(nonNilMap(request.ExecutionConfiguration))
	jobID := uuid.New()
	jobNumber := "MLT-" + time.Now().UTC().Format("20060102150405") + "-" + strings.ToUpper(jobID.String()[:8])
	row := s.repository.databasePool.QueryRow(ctx, `INSERT INTO ml_training_jobs (id,organization_id,dataset_version_id,ai_model_id,job_number,split_configuration,training_configuration,execution_configuration,requested_by) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9 WHERE EXISTS (SELECT 1 FROM ml_training_dataset_versions v JOIN ml_training_datasets d ON d.id=v.dataset_id WHERE v.id=$3 AND d.organization_id=$2 AND v.status='READY') AND ($4::uuid IS NULL OR EXISTS (SELECT 1 FROM ai_models m WHERE m.id=$4 AND m.organization_id=$2)) RETURNING id,job_number,dataset_version_id,ai_model_id,status,split_configuration,created_at`, jobID, organizationID, datasetVersionID, modelID, jobNumber, split, train, execution, actorID)
	job, err := scanTrainingJob(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("%w: dataset version is not ready for this organization", ErrInvalidRepositoryInput)
		}
		return nil, err
	}
	return job, nil
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
	rows, err := s.repository.databasePool.Query(ctx, `SELECT id,job_number,dataset_version_id,ai_model_id,status,split_configuration,created_at FROM ml_training_jobs WHERE organization_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, organizationID, pageSize, (page-1)*pageSize)
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

// CancelJob only cancels work that has not begun. A running training process
// requires an execution-engine cancellation contract and is deliberately not
// marked cancelled until that contract exists.
func (s *TrainingService) CancelJob(ctx context.Context, organizationID, jobID uuid.UUID) (*TrainingJob, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil || jobID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	row := s.repository.databasePool.QueryRow(ctx, `UPDATE ml_training_jobs SET status='CANCELLED',cancelled_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=$1 AND organization_id=$2 AND status='QUEUED' RETURNING id,job_number,dataset_version_id,ai_model_id,status,split_configuration,created_at`, jobID, organizationID)
	job, err := scanTrainingJob(row)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("%w: only queued training jobs can be cancelled", ErrAnalysisJobConflict)
	}
	return job, err
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
	err := row.Scan(&item.ID, &item.JobNumber, &item.DatasetVersionID, &item.AIModelID, &item.Status, &split, &item.CreatedAt)
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
