package deepfakeforensics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrAnalysisModelActivationRejected = errors.New(
	"AI analysis model activation rejected",
)

type ManagedAIModel struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	ModelCode      string    `json:"model_code"`
	ModelName      string    `json:"model_name"`
	Description    *string   `json:"description,omitempty"`
	ModelType      string    `json:"model_type"`
	Framework      string    `json:"framework"`
	InputType      string    `json:"input_type"`
	OutputType     string    `json:"output_type"`

	SupportsOfflineExecution bool `json:"supports_offline_execution"`
	SupportsGPU              bool `json:"supports_gpu"`
	SupportsCPU              bool `json:"supports_cpu"`

	MinimumMemoryMB      *int   `json:"minimum_memory_mb,omitempty"`
	MaximumFileSizeBytes *int64 `json:"maximum_file_size_bytes,omitempty"`

	Status    string     `json:"status"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type ManagedAIModelVersion struct {
	ID        uuid.UUID `json:"id"`
	AIModelID uuid.UUID `json:"ai_model_id"`

	VersionNumber string  `json:"version_number"`
	VersionName   *string `json:"version_name,omitempty"`

	ModelFilePath string `json:"model_file_path"`
	ModelFileHash string `json:"model_file_hash"`
	HashAlgorithm string `json:"hash_algorithm"`
	ModelFormat   string `json:"model_format"`

	TrainingDatasetName    *string `json:"training_dataset_name,omitempty"`
	TrainingDatasetVersion *string `json:"training_dataset_version,omitempty"`
	TrainingRecordCount    *int64  `json:"training_record_count,omitempty"`

	TrainingAccuracy    *float64 `json:"training_accuracy,omitempty"`
	ValidationAccuracy  *float64 `json:"validation_accuracy,omitempty"`
	PrecisionScore      *float64 `json:"precision_score,omitempty"`
	RecallScore         *float64 `json:"recall_score,omitempty"`
	F1Score             *float64 `json:"f1_score,omitempty"`
	ConfidenceThreshold *float64 `json:"confidence_threshold,omitempty"`

	Configuration map[string]any `json:"configuration"`
	IsDefault     bool           `json:"is_default"`
	Status        string         `json:"status"`
	CreatedBy     *uuid.UUID     `json:"created_by,omitempty"`

	TrainedAt   *time.Time `json:"trained_at,omitempty"`
	ValidatedAt *time.Time `json:"validated_at,omitempty"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type ManagedAIModelAssignment struct {
	ID               uuid.UUID  `json:"id"`
	OrganizationID   uuid.UUID  `json:"organization_id"`
	AIModelID        uuid.UUID  `json:"ai_model_id"`
	AIModelVersionID uuid.UUID  `json:"ai_model_version_id"`
	IsDefault        bool       `json:"is_default"`
	Status           string     `json:"status"`
	AssignedBy       *uuid.UUID `json:"assigned_by,omitempty"`
	Reason           *string    `json:"reason,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type ManagedAIModelBundle struct {
	Model    ManagedAIModel          `json:"model"`
	Versions []ManagedAIModelVersion `json:"versions"`
}

type ManagedAIModelUploadResponse struct {
	Model   ManagedAIModel        `json:"model"`
	Version ManagedAIModelVersion `json:"version"`
}

type ManagedAIModelListResponse struct {
	Items      []ManagedAIModel `json:"items"`
	Total      int64            `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalPages int              `json:"total_pages"`
}

type ManagedAIModelFilter struct {
	ModelType string
	Status    string
	Limit     int
	Offset    int
}

type ActivateAIModelVersionRequest struct {
	Reason string `json:"reason" binding:"omitempty,max=2000"`
}

type UploadAIModelRequest struct {
	ModelCode           string  `form:"model_code"`
	ModelName           string  `form:"model_name"`
	ModelType           string  `form:"model_type"`
	Framework           string  `form:"framework"`
	VersionNumber       string  `form:"version_number"`
	Description         string  `form:"description"`
	SupportsCPU         bool    `form:"supports_cpu"`
	SupportsGPU         bool    `form:"supports_gpu"`
	ConfidenceThreshold float64 `form:"confidence_threshold"`
	TrainingDatasetName string  `form:"training_dataset_name"`
	ValidationAccuracy  float64 `form:"validation_accuracy"`
	PrecisionScore      float64 `form:"precision_score"`
	RecallScore         float64 `form:"recall_score"`
	F1Score             float64 `form:"f1_score"`
}

type UploadAIModelVersionRequest struct {
	VersionNumber       string  `form:"version_number"`
	TrainingDatasetName string  `form:"training_dataset_name"`
	ValidationAccuracy  float64 `form:"validation_accuracy"`
	PrecisionScore      float64 `form:"precision_score"`
	RecallScore         float64 `form:"recall_score"`
	F1Score             float64 `form:"f1_score"`
	ConfidenceThreshold float64 `form:"confidence_threshold"`
}

type RollbackAIModelVersionRequest struct {
	TargetVersionID string `json:"target_version_id" binding:"required"`
	Reason          string `json:"reason" binding:"omitempty,max=2000"`
}

type AssignAIModelVersionRequest struct {
	OrganizationID string `json:"organization_id" binding:"required"`
	ModelVersionID string `json:"model_version_id" binding:"required"`
	IsDefault      bool   `json:"is_default"`
	Reason         string `json:"reason" binding:"omitempty,max=2000"`
}

type ModelManagementService struct {
	repository       *Repository
	modelStorageRoot string
}

func NewModelManagementService(
	repository *Repository,
	storageRoot string,
) (*ModelManagementService, error) {
	if repository == nil ||
		!repository.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}

	if strings.TrimSpace(storageRoot) == "" {
		storageRoot = "./storage/models"
	}

	return &ModelManagementService{
		repository:       repository,
		modelStorageRoot: storageRoot,
	}, nil
}

func (s *ModelManagementService) UploadModel(
	ctx context.Context,
	organizationID uuid.UUID,
	actorUserID uuid.UUID,
	request UploadAIModelRequest,
	file multipart.File,
	originalFileName string,
) (*ManagedAIModelUploadResponse, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil || actorUserID == uuid.Nil || file == nil {
		return nil, ErrInvalidRepositoryInput
	}
	if strings.TrimSpace(request.ModelCode) == "" || strings.TrimSpace(request.ModelName) == "" || strings.TrimSpace(request.ModelType) == "" {
		return nil, ErrInvalidRepositoryInput
	}
	if strings.TrimSpace(request.VersionNumber) == "" {
		request.VersionNumber = "1.0.0"
	}

	modelType := NormalizeConstant(request.ModelType)
	if !IsSupportedJobType(modelType) {
		return nil, fmt.Errorf("%w: unsupported AI model type", ErrInvalidRepositoryInput)
	}
	framework := NormalizeConstant(request.Framework)
	if framework == "" {
		framework = "ONNX"
	}

	filename := strings.TrimSpace(originalFileName)
	if filename == "" {
		return nil, ErrInvalidRepositoryInput
	}
	if err := validateModelArtifactExtension(filename); err != nil {
		return nil, err
	}

	modelCode := strings.TrimSpace(request.ModelCode)
	versionNumber := strings.TrimSpace(request.VersionNumber)
	modelFilePath, storedRelativePath, modelFormat, modelFileHash, err := s.storeModelArtifact(file, filename, modelCode, versionNumber)
	if err != nil {
		return nil, err
	}

	modelID := uuid.New()
	versionID := uuid.New()
	createdAt := time.Now().UTC()
	inputType, outputType := inferModelIO(modelType)
	configuration := map[string]any{
		"uploaded_via_api":     true,
		"uploaded_file_name":   filename,
		"stored_relative_path": storedRelativePath,
		"supports_cpu":         request.SupportsCPU,
		"supports_gpu":         request.SupportsGPU,
		"confidence_threshold": request.ConfidenceThreshold,
	}
	configurationJSON, err := json.Marshal(configuration)
	if err != nil {
		return nil, fmt.Errorf("encode model configuration: %w", err)
	}

	tx, err := s.repository.databasePool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		_ = os.Remove(modelFilePath)
		return nil, fmt.Errorf("begin AI model upload transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	_, err = tx.Exec(ctx, `
		INSERT INTO ai_models (
			id,
			organization_id,
			model_code,
			model_name,
			description,
			model_type,
			framework,
			input_type,
			output_type,
			supports_offline_execution,
			supports_gpu,
			supports_cpu,
			minimum_memory_mb,
			maximum_file_size_bytes,
			status,
			created_by,
			created_at,
			updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULL,NULL,'DEVELOPMENT',$13,$14,$15)
	`, modelID, organizationID, modelCode, strings.TrimSpace(request.ModelName), strings.TrimSpace(request.Description), modelType, framework, inputType, outputType, true, request.SupportsGPU, request.SupportsCPU, actorUserID, createdAt, createdAt)
	if err != nil {
		_ = os.Remove(modelFilePath)
		return nil, fmt.Errorf("insert AI model record: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO ai_model_versions (
			id,
			ai_model_id,
			version_number,
			version_name,
			model_file_path,
			model_file_hash,
			hash_algorithm,
			model_format,
			training_dataset_name,
			training_dataset_version,
			training_record_count,
			training_accuracy,
			validation_accuracy,
			precision_score,
			recall_score,
			f1_score,
			confidence_threshold,
			configuration,
			is_default,
			status,
			created_by,
			trained_at,
			validated_at,
			activated_at,
			created_at,
			updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,'SHA256',$7,$8,NULL,NULL,NULL,$9,$10,$11,$12,$13,$14,false,'VALIDATED',$15,NULL,NULL,NULL,$16,$17)
	`, versionID, modelID, versionNumber, strings.TrimSpace(request.ModelName)+" "+versionNumber, modelFilePath, modelFileHash, modelFormat, strings.TrimSpace(request.TrainingDatasetName), request.ValidationAccuracy, request.PrecisionScore, request.RecallScore, request.F1Score, request.ConfidenceThreshold, configurationJSON, actorUserID, createdAt, createdAt)
	if err != nil {
		_ = os.Remove(modelFilePath)
		return nil, fmt.Errorf("insert AI model version record: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		_ = os.Remove(modelFilePath)
		return nil, fmt.Errorf("commit AI model upload: %w", err)
	}

	model := ManagedAIModel{
		ID:                       modelID,
		OrganizationID:           organizationID,
		ModelCode:                modelCode,
		ModelName:                strings.TrimSpace(request.ModelName),
		Description:              optionalString(strings.TrimSpace(request.Description)),
		ModelType:                modelType,
		Framework:                framework,
		InputType:                inputType,
		OutputType:               outputType,
		SupportsOfflineExecution: true,
		SupportsGPU:              request.SupportsGPU,
		SupportsCPU:              request.SupportsCPU,
		Status:                   "DEVELOPMENT",
		CreatedBy:                &actorUserID,
		CreatedAt:                createdAt,
		UpdatedAt:                createdAt,
	}
	version := ManagedAIModelVersion{
		ID:                  versionID,
		AIModelID:           modelID,
		VersionNumber:       versionNumber,
		VersionName:         optionalString(strings.TrimSpace(request.ModelName) + " " + versionNumber),
		ModelFilePath:       modelFilePath,
		ModelFileHash:       modelFileHash,
		HashAlgorithm:       "SHA256",
		ModelFormat:         modelFormat,
		TrainingDatasetName: optionalString(strings.TrimSpace(request.TrainingDatasetName)),
		ValidationAccuracy:  optionalFloat64(request.ValidationAccuracy),
		PrecisionScore:      optionalFloat64(request.PrecisionScore),
		RecallScore:         optionalFloat64(request.RecallScore),
		F1Score:             optionalFloat64(request.F1Score),
		ConfidenceThreshold: optionalFloat64(request.ConfidenceThreshold),
		Configuration:       configuration,
		IsDefault:           false,
		Status:              "VALIDATED",
		CreatedBy:           &actorUserID,
		CreatedAt:           createdAt,
		UpdatedAt:           createdAt,
	}

	return &ManagedAIModelUploadResponse{Model: model, Version: version}, nil
}

func (s *ModelManagementService) UploadModelVersion(
	ctx context.Context,
	organizationID uuid.UUID,
	actorUserID uuid.UUID,
	modelID uuid.UUID,
	request UploadAIModelVersionRequest,
	file multipart.File,
	originalFileName string,
) (*ManagedAIModelVersion, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil || actorUserID == uuid.Nil || modelID == uuid.Nil || file == nil {
		return nil, ErrInvalidRepositoryInput
	}
	if strings.TrimSpace(request.VersionNumber) == "" {
		return nil, ErrInvalidRepositoryInput
	}
	if err := validateModelArtifactExtension(originalFileName); err != nil {
		return nil, err
	}

	var modelCode string
	err := s.repository.databasePool.QueryRow(ctx, `SELECT model_code FROM ai_models WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`, organizationID, modelID).Scan(&modelCode)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisModelNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lookup AI model for version upload: %w", err)
	}

	modelFilePath, storedRelativePath, modelFormat, modelFileHash, err := s.storeModelArtifact(file, originalFileName, modelCode, request.VersionNumber)
	if err != nil {
		return nil, err
	}

	versionID := uuid.New()
	createdAt := time.Now().UTC()
	configuration := map[string]any{
		"uploaded_via_api":     true,
		"uploaded_file_name":   originalFileName,
		"stored_relative_path": storedRelativePath,
		"confidence_threshold": request.ConfidenceThreshold,
	}
	configurationJSON, err := json.Marshal(configuration)
	if err != nil {
		_ = os.Remove(modelFilePath)
		return nil, fmt.Errorf("encode model version configuration: %w", err)
	}

	_, err = s.repository.databasePool.Exec(ctx, `
		INSERT INTO ai_model_versions (
			id,
			ai_model_id,
			version_number,
			version_name,
			model_file_path,
			model_file_hash,
			hash_algorithm,
			model_format,
			training_dataset_name,
			training_dataset_version,
			training_record_count,
			training_accuracy,
			validation_accuracy,
			precision_score,
			recall_score,
			f1_score,
			confidence_threshold,
			configuration,
			is_default,
			status,
			created_by,
			trained_at,
			validated_at,
			activated_at,
			created_at,
			updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,'SHA256',$7,$8,NULL,NULL,NULL,$9,$10,$11,$12,$13,$14,false,'VALIDATED',$15,NULL,NULL,NULL,$16,$17)
	`, versionID, modelID, request.VersionNumber, "Version "+request.VersionNumber, modelFilePath, modelFileHash, modelFormat, strings.TrimSpace(request.TrainingDatasetName), request.ValidationAccuracy, request.PrecisionScore, request.RecallScore, request.F1Score, request.ConfidenceThreshold, configurationJSON, actorUserID, createdAt, createdAt)
	if err != nil {
		_ = os.Remove(modelFilePath)
		return nil, fmt.Errorf("insert AI model version record: %w", err)
	}

	return &ManagedAIModelVersion{
		ID:                  versionID,
		AIModelID:           modelID,
		VersionNumber:       request.VersionNumber,
		VersionName:         optionalString("Version " + request.VersionNumber),
		ModelFilePath:       modelFilePath,
		ModelFileHash:       modelFileHash,
		HashAlgorithm:       "SHA256",
		ModelFormat:         modelFormat,
		TrainingDatasetName: optionalString(strings.TrimSpace(request.TrainingDatasetName)),
		ValidationAccuracy:  optionalFloat64(request.ValidationAccuracy),
		PrecisionScore:      optionalFloat64(request.PrecisionScore),
		RecallScore:         optionalFloat64(request.RecallScore),
		F1Score:             optionalFloat64(request.F1Score),
		ConfidenceThreshold: optionalFloat64(request.ConfidenceThreshold),
		Configuration:       configuration,
		IsDefault:           false,
		Status:              "VALIDATED",
		CreatedBy:           &actorUserID,
		CreatedAt:           createdAt,
		UpdatedAt:           createdAt,
	}, nil
}

func (s *ModelManagementService) RollbackVersion(
	ctx context.Context,
	organizationID uuid.UUID,
	modelID uuid.UUID,
	request RollbackAIModelVersionRequest,
	actorUserID uuid.UUID,
) (*ManagedAIModelBundle, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil || modelID == uuid.Nil || actorUserID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	versionID, err := uuid.Parse(strings.TrimSpace(request.TargetVersionID))
	if err != nil {
		return nil, ErrInvalidRepositoryInput
	}
	if _, err = s.repository.databasePool.Exec(ctx, `SELECT 1 FROM ai_model_versions v INNER JOIN ai_models m ON m.id = v.ai_model_id WHERE m.organization_id = $1 AND m.id = $2 AND v.id = $3 AND m.deleted_at IS NULL`, organizationID, modelID, versionID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAnalysisModelNotFound
		}
		return nil, fmt.Errorf("validate rollback target: %w", err)
	}
	return s.ActivateVersion(ctx, organizationID, modelID, versionID, actorUserID, ActivateAIModelVersionRequest{Reason: request.Reason})
}

func (s *ModelManagementService) AssignModelVersion(
	ctx context.Context,
	organizationID uuid.UUID,
	actorUserID uuid.UUID,
	modelID uuid.UUID,
	request AssignAIModelVersionRequest,
) (*ManagedAIModelAssignment, error) {
	if !s.isAvailable() || ctx == nil || organizationID == uuid.Nil || actorUserID == uuid.Nil || modelID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	versionID, err := uuid.Parse(strings.TrimSpace(request.ModelVersionID))
	if err != nil {
		return nil, ErrInvalidRepositoryInput
	}
	var assignedOrganizationID uuid.UUID
	err = s.repository.databasePool.QueryRow(ctx, `SELECT m.organization_id FROM ai_models m WHERE m.organization_id = $1 AND m.id = $2 AND m.deleted_at IS NULL`, organizationID, modelID).Scan(&assignedOrganizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisModelNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("validate AI model assignment: %w", err)
	}
	if assignedOrganizationID != organizationID {
		return nil, ErrAnalysisModelNotFound
	}
	_, err = s.repository.databasePool.Exec(ctx, `SELECT 1 FROM ai_model_versions v INNER JOIN ai_models m ON m.id = v.ai_model_id WHERE m.organization_id = $1 AND m.id = $2 AND v.id = $3 AND m.deleted_at IS NULL`, organizationID, modelID, versionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisModelNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("validate AI model version assignment: %w", err)
	}
	createdAt := time.Now().UTC()
	_, err = s.repository.databasePool.Exec(ctx, `
		UPDATE ai_model_versions
		SET is_default = $3,
			status = CASE WHEN $4 THEN 'ACTIVE' ELSE status END,
			updated_at = $5
		WHERE ai_model_id = $1
			AND id = $2
	`, modelID, versionID, request.IsDefault, request.IsDefault, createdAt)
	if err != nil {
		return nil, fmt.Errorf("update AI model assignment state: %w", err)
	}
	_, err = s.repository.databasePool.Exec(ctx, `
		UPDATE ai_model_versions
		SET is_default = false,
			updated_at = $3
		WHERE ai_model_id = $1
			AND id <> $2
			AND is_default = true
	`, modelID, versionID, createdAt)
	if err != nil {
		return nil, fmt.Errorf("clear prior default AI model version: %w", err)
	}
	_, err = s.repository.databasePool.Exec(ctx, `
		UPDATE ai_models
		SET status = 'ACTIVE', updated_at = $3
		WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL
	`, organizationID, modelID, createdAt)
	if err != nil {
		return nil, fmt.Errorf("activate AI model assignment: %w", err)
	}
	return &ManagedAIModelAssignment{ID: uuid.New(), OrganizationID: organizationID, AIModelID: modelID, AIModelVersionID: versionID, IsDefault: request.IsDefault, Status: "ACTIVE", AssignedBy: &actorUserID, Reason: optionalString(strings.TrimSpace(request.Reason)), CreatedAt: createdAt, UpdatedAt: createdAt}, nil
}

func (s *ModelManagementService) storeModelArtifact(
	file multipart.File,
	originalFileName string,
	modelCode string,
	versionNumber string,
) (string, string, string, string, error) {
	if file == nil {
		return "", "", "", "", ErrInvalidRepositoryInput
	}
	if err := validateModelArtifactExtension(originalFileName); err != nil {
		return "", "", "", "", err
	}
	if strings.TrimSpace(modelCode) == "" {
		return "", "", "", "", ErrInvalidRepositoryInput
	}
	if strings.TrimSpace(versionNumber) == "" {
		versionNumber = "1.0.0"
	}

	storageRoot := strings.TrimSpace(s.modelStorageRoot)
	if storageRoot == "" {
		storageRoot = "./storage/models"
	}
	storageRoot = filepath.Clean(storageRoot)
	if err := os.MkdirAll(storageRoot, 0o700); err != nil {
		return "", "", "", "", fmt.Errorf("create model storage root: %w", err)
	}

	relativeDirectory := filepath.ToSlash(filepath.Join("models", strings.TrimSpace(modelCode), strings.TrimSpace(versionNumber)))
	targetDirectory := filepath.Join(storageRoot, filepath.FromSlash(relativeDirectory))
	if err := os.MkdirAll(targetDirectory, 0o700); err != nil {
		return "", "", "", "", fmt.Errorf("create model storage directory: %w", err)
	}

	safeFileName := sanitizeModelArtifactName(originalFileName)
	targetPath := filepath.Join(targetDirectory, safeFileName)
	absoluteRoot, err := filepath.Abs(storageRoot)
	if err != nil {
		return "", "", "", "", fmt.Errorf("resolve model storage root: %w", err)
	}
	absoluteTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return "", "", "", "", fmt.Errorf("resolve model storage target: %w", err)
	}
	if !pathWithinRoot(absoluteRoot, absoluteTarget) {
		return "", "", "", "", fmt.Errorf("%w: model path is outside the managed storage root", ErrManagedMediaPathRequired)
	}

	temporaryPath := filepath.Join(targetDirectory, "."+uuid.NewString()+".tmp")
	output, err := os.Create(temporaryPath)
	if err != nil {
		return "", "", "", "", fmt.Errorf("create model artifact temp file: %w", err)
	}
	hash := sha256.New()
	_, err = io.Copy(io.MultiWriter(output, hash), file)
	_ = output.Close()
	if err != nil {
		_ = os.Remove(temporaryPath)
		return "", "", "", "", fmt.Errorf("write model artifact: %w", err)
	}
	if err = os.Rename(temporaryPath, targetPath); err != nil {
		_ = os.Remove(temporaryPath)
		return "", "", "", "", fmt.Errorf("commit model artifact: %w", err)
	}

	modelFormat := strings.ToUpper(strings.TrimPrefix(strings.TrimSpace(filepath.Ext(safeFileName)), "."))
	return absoluteTarget, filepath.ToSlash(filepath.Join(relativeDirectory, safeFileName)), modelFormat, strings.ToLower(hex.EncodeToString(hash.Sum(nil))), nil
}

func validateModelArtifactExtension(filename string) error {
	ext := strings.ToLower(strings.TrimSpace(filepath.Ext(filename)))
	switch ext {
	case ".onnx", ".pth", ".pt":
		return nil
	default:
		return fmt.Errorf("%w: supported model artifact extensions are .onnx, .pth and .pt", ErrInvalidRepositoryInput)
	}
}

func inferModelIO(modelType string) (string, string) {
	switch NormalizeConstant(modelType) {
	case JobTypeDeepfakeImage,
		JobTypeSyntheticImage:
		return "IMAGE", "CLASSIFICATION"
	case JobTypeDeepfakeVideo:
		return "VIDEO", "CLASSIFICATION"
	case JobTypeDeepfakeAudio:
		return "AUDIO", "CLASSIFICATION"
	case JobTypeDocumentForensics:
		return "DOCUMENT", "CLASSIFICATION"
	case JobTypeOCRExtraction:
		return "DOCUMENT", "TEXT_EXTRACTION"
	case JobTypeAudioVisualConsistency,
		JobTypeLipSyncConsistency,
		JobTypeMetadataIntegrity:
		return "VIDEO", "CONSISTENCY"
	default:
		return "IMAGE", "CLASSIFICATION"
	}
}

func sanitizeModelArtifactName(filename string) string {
	safeName := strings.TrimSpace(filepath.Base(filename))
	if safeName == "" || safeName == "." || safeName == ".." {
		safeName = "model" + strings.ToLower(filepath.Ext(filename))
	}
	return strings.ReplaceAll(safeName, string(os.PathSeparator), "_")
}

func pathWithinRoot(root, target string) bool {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	return target == root || strings.HasPrefix(target, root+string(os.PathSeparator))
}

func optionalString(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
}

func optionalFloat64(value float64) *float64 {
	if value == 0 {
		return nil
	}
	return &value
}

func parseBoolForm(value string) bool {
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	return parsed
}

func parseFloatForm(value string) float64 {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0
	}
	return parsed
}

func (s *ModelManagementService) ListModels(
	ctx context.Context,
	organizationID uuid.UUID,
	filter ManagedAIModelFilter,
) (*ManagedAIModelListResponse, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	filter.ModelType = NormalizeConstant(filter.ModelType)
	if filter.ModelType != "" &&
		!IsSupportedJobType(filter.ModelType) {
		return nil, fmt.Errorf(
			"%w: unsupported media model type",
			ErrInvalidRepositoryInput,
		)
	}
	filter.Status = NormalizeConstant(filter.Status)
	filter.Limit, filter.Offset = normalizeMediaPagination(
		filter.Limit,
		filter.Offset,
	)

	items, total, err := s.repository.ListManagedAIModels(
		ctx,
		organizationID,
		filter,
	)
	if err != nil {
		return nil, err
	}

	page, totalPages := calculateMediaPages(
		total,
		filter.Limit,
		filter.Offset,
	)

	return &ManagedAIModelListResponse{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   filter.Limit,
		TotalPages: totalPages,
	}, nil
}

func (s *ModelManagementService) GetModel(
	ctx context.Context,
	organizationID uuid.UUID,
	modelID uuid.UUID,
) (*ManagedAIModelBundle, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		modelID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	model, err := s.repository.GetManagedAIModel(
		ctx,
		organizationID,
		modelID,
	)
	if err != nil {
		return nil, err
	}
	versions, err := s.repository.ListManagedAIModelVersions(
		ctx,
		organizationID,
		modelID,
	)
	if err != nil {
		return nil, err
	}

	return &ManagedAIModelBundle{
		Model:    *model,
		Versions: versions,
	}, nil
}

func (s *ModelManagementService) ActivateVersion(
	ctx context.Context,
	organizationID uuid.UUID,
	modelID uuid.UUID,
	versionID uuid.UUID,
	actorUserID uuid.UUID,
	request ActivateAIModelVersionRequest,
) (*ManagedAIModelBundle, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		modelID == uuid.Nil ||
		versionID == uuid.Nil ||
		actorUserID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	if err := s.repository.ActivateManagedAIModelVersion(
		ctx,
		organizationID,
		modelID,
		versionID,
		actorUserID,
		strings.TrimSpace(request.Reason),
	); err != nil {
		return nil, err
	}

	return s.GetModel(
		ctx,
		organizationID,
		modelID,
	)
}

func (s *ModelManagementService) isAvailable() bool {
	return s != nil &&
		s.repository != nil &&
		s.repository.IsAvailable()
}

func (r *Repository) ListManagedAIModels(
	ctx context.Context,
	organizationID uuid.UUID,
	filter ManagedAIModelFilter,
) ([]ManagedAIModel, int64, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, 0, err
	}

	conditions := []string{
		"organization_id = $1",
		"deleted_at IS NULL",
		`model_type IN (
			'DEEPFAKE_IMAGE_DETECTION',
			'AI_GENERATED_IMAGE_DETECTION',
			'DEEPFAKE_VIDEO_DETECTION',
			'DEEPFAKE_AUDIO_DETECTION',
			'IMAGE_FORENSICS',
			'VIDEO_FORENSICS',
			'AUDIO_FORENSICS',
			'DOCUMENT_FORENSICS',
			'OCR_EXTRACTION'
		)`,
	}
	arguments := []any{organizationID}
	if filter.ModelType != "" {
		arguments = append(arguments, filter.ModelType)
		conditions = append(
			conditions,
			fmt.Sprintf(
				"model_type = $%d",
				len(arguments),
			),
		)
	}
	if filter.Status != "" {
		arguments = append(arguments, filter.Status)
		conditions = append(
			conditions,
			fmt.Sprintf(
				"status = $%d",
				len(arguments),
			),
		)
	}

	whereClause := strings.Join(conditions, " AND ")
	var total int64
	if err := r.databasePool.QueryRow(
		ctx,
		"SELECT COUNT(*) FROM ai_models WHERE "+whereClause,
		arguments...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf(
			"count managed AI models: %w",
			err,
		)
	}

	arguments = append(arguments, filter.Limit, filter.Offset)
	query := `
		SELECT
			id,
			organization_id,
			model_code,
			model_name,
			description,
			model_type,
			framework,
			input_type,
			output_type,
			supports_offline_execution,
			supports_gpu,
			supports_cpu,
			minimum_memory_mb,
			maximum_file_size_bytes,
			status,
			created_by,
			created_at,
			updated_at
		FROM ai_models
		WHERE ` + whereClause + `
		ORDER BY model_type, model_code, id
		LIMIT $` + fmt.Sprint(len(arguments)-1) + `
		OFFSET $` + fmt.Sprint(len(arguments))

	rows, err := r.databasePool.Query(
		ctx,
		query,
		arguments...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"list managed AI models: %w",
			err,
		)
	}
	defer rows.Close()

	items := make([]ManagedAIModel, 0, filter.Limit)
	for rows.Next() {
		model, scanErr := scanManagedAIModel(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf(
				"scan managed AI model: %w",
				scanErr,
			)
		}
		items = append(items, *model)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"iterate managed AI models: %w",
			err,
		)
	}

	return items, total, nil
}

func (r *Repository) GetManagedAIModel(
	ctx context.Context,
	organizationID uuid.UUID,
	modelID uuid.UUID,
) (*ManagedAIModel, error) {
	model, err := scanManagedAIModel(
		r.databasePool.QueryRow(
			ctx,
			`
				SELECT
					id,
					organization_id,
					model_code,
					model_name,
					description,
					model_type,
					framework,
					input_type,
					output_type,
					supports_offline_execution,
					supports_gpu,
					supports_cpu,
					minimum_memory_mb,
					maximum_file_size_bytes,
					status,
					created_by,
					created_at,
					updated_at
				FROM ai_models
				WHERE organization_id = $1
					AND id = $2
					AND deleted_at IS NULL
			`,
			organizationID,
			modelID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisModelNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"get managed AI model: %w",
			err,
		)
	}

	return model, nil
}

func (r *Repository) ListManagedAIModelVersions(
	ctx context.Context,
	organizationID uuid.UUID,
	modelID uuid.UUID,
) ([]ManagedAIModelVersion, error) {
	rows, err := r.databasePool.Query(
		ctx,
		`
			SELECT
				v.id,
				v.ai_model_id,
				v.version_number,
				v.version_name,
				v.model_file_path,
				v.model_file_hash,
				v.hash_algorithm,
				v.model_format,
				v.training_dataset_name,
				v.training_dataset_version,
				v.training_record_count,
				v.training_accuracy,
				v.validation_accuracy,
				v.precision_score,
				v.recall_score,
				v.f1_score,
				v.confidence_threshold,
				COALESCE(v.configuration, '{}'::jsonb),
				v.is_default,
				v.status,
				v.created_by,
				v.trained_at,
				v.validated_at,
				v.activated_at,
				v.created_at,
				v.updated_at
			FROM ai_model_versions AS v
			INNER JOIN ai_models AS m
				ON m.id = v.ai_model_id
			WHERE m.organization_id = $1
				AND m.id = $2
				AND m.deleted_at IS NULL
			ORDER BY v.created_at DESC, v.id DESC
		`,
		organizationID,
		modelID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list managed AI model versions: %w",
			err,
		)
	}
	defer rows.Close()

	versions := make([]ManagedAIModelVersion, 0)
	for rows.Next() {
		version, scanErr :=
			scanManagedAIModelVersion(rows)
		if scanErr != nil {
			return nil, fmt.Errorf(
				"scan managed AI model version: %w",
				scanErr,
			)
		}
		versions = append(versions, *version)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate managed AI model versions: %w",
			err,
		)
	}

	return versions, nil
}

func (r *Repository) ActivateManagedAIModelVersion(
	ctx context.Context,
	organizationID uuid.UUID,
	modelID uuid.UUID,
	versionID uuid.UUID,
	actorUserID uuid.UUID,
	reason string,
) error {
	if err := r.validateAvailable(); err != nil {
		return err
	}

	tx, err := r.databasePool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return fmt.Errorf(
			"begin AI model activation: %w",
			err,
		)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	var previousModelStatus string
	var previousVersionStatus string
	var modelFilePath string
	var modelFileHash string
	var modelFormat string
	var configurationJSON []byte
	var alreadyDefault bool

	err = tx.QueryRow(
		ctx,
		`
			SELECT
				m.status,
				v.status,
				v.model_file_path,
				v.model_file_hash,
				v.model_format,
				COALESCE(v.configuration, '{}'::jsonb),
				v.is_default
			FROM ai_models AS m
			INNER JOIN ai_model_versions AS v
				ON v.ai_model_id = m.id
			WHERE m.organization_id = $1
				AND m.id = $2
				AND v.id = $3
				AND m.deleted_at IS NULL
			FOR UPDATE OF m, v
		`,
		organizationID,
		modelID,
		versionID,
	).Scan(
		&previousModelStatus,
		&previousVersionStatus,
		&modelFilePath,
		&modelFileHash,
		&modelFormat,
		&configurationJSON,
		&alreadyDefault,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAnalysisModelNotFound
	}
	if err != nil {
		return fmt.Errorf(
			"lock AI model version for activation: %w",
			err,
		)
	}

	if err = validateModelActivationCandidate(
		modelFilePath,
		modelFileHash,
		modelFormat,
		configurationJSON,
	); err != nil {
		return err
	}

	if previousModelStatus == analysisModelStatusActive &&
		previousVersionStatus == analysisModelVersionStatusActive &&
		alreadyDefault {
		return tx.Commit(ctx)
	}

	if _, err = tx.Exec(
		ctx,
		`
			UPDATE ai_model_versions
			SET
				is_default = false,
				updated_at = CURRENT_TIMESTAMP
			WHERE ai_model_id = $1
				AND id <> $2
				AND is_default = true
		`,
		modelID,
		versionID,
	); err != nil {
		return fmt.Errorf(
			"clear previous default AI model version: %w",
			err,
		)
	}

	if _, err = tx.Exec(
		ctx,
		`
			UPDATE ai_model_versions
			SET
				status = $3,
				is_default = true,
				activated_at = CURRENT_TIMESTAMP,
				updated_at = CURRENT_TIMESTAMP
			WHERE ai_model_id = $1
				AND id = $2
		`,
		modelID,
		versionID,
		analysisModelVersionStatusActive,
	); err != nil {
		return fmt.Errorf(
			"activate AI model version: %w",
			err,
		)
	}

	if _, err = tx.Exec(
		ctx,
		`
			UPDATE ai_models
			SET
				status = $3,
				updated_at = CURRENT_TIMESTAMP
			WHERE organization_id = $1
				AND id = $2
				AND deleted_at IS NULL
		`,
		organizationID,
		modelID,
		analysisModelStatusActive,
	); err != nil {
		return fmt.Errorf(
			"activate AI model: %w",
			err,
		)
	}

	if _, err = tx.Exec(
		ctx,
		`
			INSERT INTO ai_model_deployment_audit (
				organization_id,
				ai_model_id,
				ai_model_version_id,
				action,
				previous_model_status,
				new_model_status,
				previous_version_status,
				new_version_status,
				activated_by,
				reason,
				metadata
			)
			VALUES (
					$1, $2, $3, 'ACTIVATE',
					$4, $5, $6, $7, $8,
					NULLIF($9::text, ''),
					jsonb_build_object(
						'model_format', $10::text,
						'activation_source', 'ADMIN_API'
					)
			)
		`,
		organizationID,
		modelID,
		versionID,
		previousModelStatus,
		analysisModelStatusActive,
		previousVersionStatus,
		analysisModelVersionStatusActive,
		actorUserID,
		reason,
		NormalizeConstant(modelFormat),
	); err != nil {
		return fmt.Errorf(
			"audit AI model activation: %w",
			err,
		)
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit AI model activation: %w",
			err,
		)
	}

	return nil
}

func validateModelActivationCandidate(
	modelFilePath string,
	modelFileHash string,
	modelFormat string,
	configurationJSON []byte,
) error {
	modelFilePath = strings.TrimSpace(modelFilePath)
	modelFileHash = strings.ToLower(
		strings.TrimSpace(modelFileHash),
	)
	modelFormat = NormalizeConstant(modelFormat)

	if modelFilePath == "" ||
		len(modelFileHash) != 64 ||
		modelFileHash == strings.Repeat("0", 64) {
		return fmt.Errorf(
			"%w: verified model path and SHA256 hash are required",
			ErrAnalysisModelActivationRejected,
		)
	}
	if _, err := hex.DecodeString(modelFileHash); err != nil {
		return fmt.Errorf(
			"%w: model SHA256 hash is invalid",
			ErrAnalysisModelActivationRejected,
		)
	}

	switch modelFormat {
	case "PTH", "PT", "ONNX", "CUSTOM":
	default:
		return fmt.Errorf(
			"%w: unsupported deployment format",
			ErrAnalysisModelActivationRejected,
		)
	}

	configuration := map[string]any{}
	if len(configurationJSON) > 0 {
		if err := json.Unmarshal(
			configurationJSON,
			&configuration,
		); err != nil {
			return fmt.Errorf(
				"%w: invalid model configuration",
				ErrAnalysisModelActivationRejected,
			)
		}
	}
	if placeholder, ok :=
		configuration["placeholder_file"].(bool); ok && placeholder {
		return fmt.Errorf(
			"%w: placeholder model files cannot be activated",
			ErrAnalysisModelActivationRejected,
		)
	}

	return nil
}

func scanManagedAIModel(
	scanner databaseRowScanner,
) (*ManagedAIModel, error) {
	model := &ManagedAIModel{}
	err := scanner.Scan(
		&model.ID,
		&model.OrganizationID,
		&model.ModelCode,
		&model.ModelName,
		&model.Description,
		&model.ModelType,
		&model.Framework,
		&model.InputType,
		&model.OutputType,
		&model.SupportsOfflineExecution,
		&model.SupportsGPU,
		&model.SupportsCPU,
		&model.MinimumMemoryMB,
		&model.MaximumFileSizeBytes,
		&model.Status,
		&model.CreatedBy,
		&model.CreatedAt,
		&model.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return model, nil
}

func scanManagedAIModelVersion(
	scanner databaseRowScanner,
) (*ManagedAIModelVersion, error) {
	version := &ManagedAIModelVersion{}
	var configurationJSON []byte
	err := scanner.Scan(
		&version.ID,
		&version.AIModelID,
		&version.VersionNumber,
		&version.VersionName,
		&version.ModelFilePath,
		&version.ModelFileHash,
		&version.HashAlgorithm,
		&version.ModelFormat,
		&version.TrainingDatasetName,
		&version.TrainingDatasetVersion,
		&version.TrainingRecordCount,
		&version.TrainingAccuracy,
		&version.ValidationAccuracy,
		&version.PrecisionScore,
		&version.RecallScore,
		&version.F1Score,
		&version.ConfidenceThreshold,
		&configurationJSON,
		&version.IsDefault,
		&version.Status,
		&version.CreatedBy,
		&version.TrainedAt,
		&version.ValidatedAt,
		&version.ActivatedAt,
		&version.CreatedAt,
		&version.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	version.Configuration = map[string]any{}
	if err = json.Unmarshal(
		configurationJSON,
		&version.Configuration,
	); err != nil {
		return nil, fmt.Errorf(
			"decode managed AI model configuration: %w",
			err,
		)
	}

	return version, nil
}
