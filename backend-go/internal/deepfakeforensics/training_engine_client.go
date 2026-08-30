package deepfakeforensics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

const trainingEngineSchemaVersion = "1.0.0"

// TrainingEngineRequest is the explicit, mounted-dataset-only contract with
// the Python trainer. The dataset path is validated again by the engine.
type TrainingEngineRequest struct {
	RequestID           uuid.UUID `json:"request_id"`
	TrainingJobID       uuid.UUID `json:"training_job_id"`
	OrganizationID      uuid.UUID `json:"organization_id"`
	DatasetVersionID    uuid.UUID `json:"dataset_version_id"`
	DatasetPath         string    `json:"dataset_path"`
	ModelCode           string    `json:"model_code"`
	DetectorScope       string    `json:"detector_scope"`
	Epochs              int       `json:"epochs"`
	BatchSize           int       `json:"batch_size"`
	LearningRate        float64   `json:"learning_rate"`
	DeepfakeClassWeight float64   `json:"deepfake_class_weight"`
	SelectionMetric     string    `json:"selection_metric"`
	ValidationPercent   int       `json:"validation_percent"`
	TestPercent         int       `json:"test_percent"`
	Seed                int       `json:"seed"`
}

// VerifyTrainingArtifact maps an engine container path into the backend's
// shared mount and independently checks the file digest before persistence.
func VerifyTrainingArtifact(enginePath, engineRoot, backendRoot, expectedSHA256 string) (string, error) {
	engineRoot = strings.TrimSpace(engineRoot)
	backendRoot = strings.TrimSpace(backendRoot)
	enginePath = strings.TrimSpace(enginePath)
	if engineRoot == "" || backendRoot == "" || enginePath == "" || len(strings.TrimSpace(expectedSHA256)) != 64 {
		return "", ErrInvalidRepositoryInput
	}

	var relativePath string
	if strings.HasPrefix(engineRoot, "/") {
		engineRoot = pathpkg.Clean(engineRoot)
		engineArtifact := pathpkg.Clean(enginePath)
		if !strings.HasPrefix(engineArtifact, engineRoot+"/") {
			return "", fmt.Errorf("%w: training artifact is outside engine artifact root", ErrManagedMediaPathRequired)
		}
		relativePath = strings.TrimPrefix(engineArtifact, engineRoot+"/")
	} else {
		absoluteRoot, err := filepath.Abs(engineRoot)
		if err != nil {
			return "", fmt.Errorf("resolve engine artifact root: %w", err)
		}
		absoluteArtifact, err := filepath.Abs(enginePath)
		if err != nil {
			return "", fmt.Errorf("resolve engine artifact path: %w", err)
		}
		relativePath, err = filepath.Rel(absoluteRoot, absoluteArtifact)
		if err != nil || relativePath == "." || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("%w: training artifact is outside engine artifact root", ErrManagedMediaPathRequired)
		}
	}
	backendArtifact := filepath.Join(filepath.Clean(backendRoot), relativePath)
	file, err := os.Open(backendArtifact)
	if err != nil {
		return "", fmt.Errorf("open training artifact: %w", err)
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err = io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("hash training artifact: %w", err)
	}
	actual := fmt.Sprintf("%x", hasher.Sum(nil))
	if !strings.EqualFold(actual, strings.TrimSpace(expectedSHA256)) {
		return "", fmt.Errorf("%w: training artifact SHA-256 mismatch", ErrMediaStorageIntegrity)
	}
	return backendArtifact, nil
}

type TrainingEngineMetric struct {
	MetricName   string  `json:"metric_name"`
	MetricValue  float64 `json:"metric_value"`
	DatasetSplit string  `json:"dataset_split"`
	EpochNumber  int     `json:"epoch_number"`
}

type TrainingEngineResponse struct {
	RequestID             uuid.UUID              `json:"request_id"`
	TrainingJobID         uuid.UUID              `json:"training_job_id"`
	OrganizationID        uuid.UUID              `json:"organization_id"`
	Success               bool                   `json:"success"`
	ArtifactPath          string                 `json:"artifact_path"`
	ArtifactSHA256        string                 `json:"artifact_sha256"`
	ArtifactFormat        string                 `json:"artifact_format"`
	TrainingRecordCount   int64                  `json:"training_record_count"`
	ValidationRecordCount int64                  `json:"validation_record_count"`
	TestRecordCount       int64                  `json:"test_record_count"`
	Metrics               []TrainingEngineMetric `json:"metrics"`
	ErrorCode             string                 `json:"error_code"`
	ErrorMessage          string                 `json:"error_message"`
	ProcessedAt           time.Time              `json:"processed_at"`
}

// TrainImageClassifier submits one claimed training job. It never treats an
// engine-declared failure as a successful artifact.
func (c *EngineClient) TrainImageClassifier(ctx context.Context, payload TrainingEngineRequest) (*TrainingEngineResponse, error) {
	if !c.isAvailable() || ctx == nil || payload.RequestID == uuid.Nil || payload.TrainingJobID == uuid.Nil || payload.OrganizationID == uuid.Nil || payload.DatasetVersionID == uuid.Nil || strings.TrimSpace(payload.DatasetPath) == "" || strings.TrimSpace(payload.ModelCode) == "" {
		return nil, ErrInvalidRepositoryInput
	}
	if payload.Epochs < 1 || payload.BatchSize < 1 || payload.LearningRate <= 0 || payload.DeepfakeClassWeight < 1 || payload.DeepfakeClassWeight > 3 || (payload.SelectionMetric != "accuracy" && payload.SelectionMetric != "f1" && payload.SelectionMetric != "recall") || payload.ValidationPercent < 10 || payload.ValidationPercent > 40 || payload.TestPercent < 0 || payload.TestPercent > 40 || payload.ValidationPercent+payload.TestPercent > 80 || payload.Seed < 0 {
		return nil, ErrInvalidRepositoryInput
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode training engine request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpointURL("/v1/model-training/image-classification"), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create training engine request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", payload.RequestID.String())
	c.setCommonHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMediaEngineUnavailable, err)
	}
	defer resp.Body.Close()
	responseBody, err := readBoundedEngineResponse(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, engineHTTPError(resp.StatusCode, resp.Status, responseBody)
	}
	var result TrainingEngineResponse
	if err = decodeStrictEngineJSON(responseBody, &result); err != nil {
		return nil, err
	}
	if result.RequestID != payload.RequestID || result.TrainingJobID != payload.TrainingJobID || result.OrganizationID != payload.OrganizationID {
		return nil, fmt.Errorf("%w: training response identity mismatch", ErrInvalidMediaEngineResponse)
	}
	if !result.Success {
		return &result, fmt.Errorf("%w: %s", ErrMediaEngineExecutionFailed, strings.TrimSpace(result.ErrorMessage))
	}
	if strings.TrimSpace(result.ArtifactPath) == "" || len(strings.TrimSpace(result.ArtifactSHA256)) != 64 || NormalizeConstant(result.ArtifactFormat) != "PTH" {
		return nil, fmt.Errorf("%w: invalid training artifact response", ErrInvalidMediaEngineResponse)
	}
	return &result, nil
}
