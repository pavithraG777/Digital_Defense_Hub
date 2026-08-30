package deepfakeforensics

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// TrainingWorker is the durable orchestration boundary for the offline model
// trainer. Model artifacts are never trusted until their shared-volume digest
// has been checked by this process.
type TrainingWorker struct {
	repository  *Repository
	engine      *EngineClient
	logger      *zap.Logger
	poll        time.Duration
	timeout     time.Duration
	node        string
	engineRoot  string
	backendRoot string
	mu          sync.Mutex
	cancel      context.CancelFunc
	wait        sync.WaitGroup
	started     bool
}

type claimedTrainingJob struct {
	ID                    uuid.UUID
	OrganizationID        uuid.UUID
	DatasetVersionID      uuid.UUID
	DatasetPath           string
	ModelCode             string
	DetectorScope         string
	TrainingConfiguration []byte
	SplitConfiguration    []byte
}

func NewTrainingWorker(repository *Repository, engine *EngineClient, logger *zap.Logger, poll, timeout time.Duration, node, engineRoot, backendRoot string) (*TrainingWorker, error) {
	if repository == nil || !repository.IsAvailable() || engine == nil || !engine.isAvailable() || strings.TrimSpace(engineRoot) == "" || strings.TrimSpace(backendRoot) == "" {
		return nil, ErrInvalidRepositoryInput
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	if poll <= 0 {
		poll = time.Second
	}
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	if strings.TrimSpace(node) == "" {
		node = "ml-training"
	}
	return &TrainingWorker{repository: repository, engine: engine, logger: logger, poll: poll, timeout: timeout, node: node, engineRoot: engineRoot, backendRoot: backendRoot}, nil
}

func (w *TrainingWorker) Start(parent context.Context) error {
	if parent == nil {
		parent = context.Background()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		return nil
	}
	ctx, cancel := context.WithCancel(parent)
	w.cancel, w.started = cancel, true
	w.wait.Add(1)
	go w.run(ctx)
	return nil
}

func (w *TrainingWorker) Stop(ctx context.Context) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	cancel := w.cancel
	wasStarted := w.started
	w.started = false
	w.mu.Unlock()
	if !wasStarted {
		return nil
	}
	cancel()
	done := make(chan struct{})
	go func() { w.wait.Wait(); close(done) }()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *TrainingWorker) run(ctx context.Context) {
	defer w.wait.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if !w.processOne(ctx) {
				timer.Reset(w.poll)
			} else {
				timer.Reset(0)
			}
		}
	}
}

func (w *TrainingWorker) processOne(ctx context.Context) bool {
	job, err := w.claim(ctx)
	if err != nil {
		if ctx.Err() == nil {
			w.logger.Error("claim ML training job", zap.Error(err))
		}
		return false
	}
	if job == nil {
		return false
	}
	trainingCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	startedAt := time.Now()
	request, err := trainingEngineRequest(*job)
	if err == nil {
		var response *TrainingEngineResponse
		response, err = w.engine.TrainImageClassifier(trainingCtx, request)
		if err == nil {
			var path string
			path, err = VerifyTrainingArtifact(response.ArtifactPath, w.engineRoot, w.backendRoot, response.ArtifactSHA256)
			if err == nil {
				err = w.persistSuccess(trainingCtx, *job, response, path, time.Since(startedAt).Milliseconds())
			}
		}
	}
	if err != nil {
		w.fail(context.Background(), job.ID, err)
		w.logger.Error("ML training job failed", zap.String("training_job_id", job.ID.String()), zap.Error(err))
	}
	return true
}

func (w *TrainingWorker) claim(ctx context.Context) (*claimedTrainingJob, error) {
	row := w.repository.databasePool.QueryRow(ctx, `WITH candidate AS (SELECT j.id FROM ml_training_jobs j WHERE j.status='QUEUED' ORDER BY j.created_at FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE ml_training_jobs j SET status='RUNNING',worker_node=$1,started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP FROM candidate c WHERE j.id=c.id RETURNING j.id,j.organization_id,j.dataset_version_id,(SELECT v.storage_uri FROM ml_training_dataset_versions v WHERE v.id=j.dataset_version_id),COALESCE((SELECT m.model_code FROM ai_models m WHERE m.id=j.ai_model_id),'deepfake-image-classifier'),COALESCE((SELECT d.metadata->>'detector_scope' FROM ml_training_dataset_versions v JOIN ml_training_datasets d ON d.id=v.dataset_id WHERE v.id=j.dataset_version_id),'DEEPFAKE_IMAGE_DETECTION'),j.training_configuration,j.split_configuration`, w.node)
	var job claimedTrainingJob
	if err := row.Scan(&job.ID, &job.OrganizationID, &job.DatasetVersionID, &job.DatasetPath, &job.ModelCode, &job.DetectorScope, &job.TrainingConfiguration, &job.SplitConfiguration); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &job, nil
}

func trainingEngineRequest(job claimedTrainingJob) (TrainingEngineRequest, error) {
	var cfg, split map[string]any
	if json.Unmarshal(job.TrainingConfiguration, &cfg) != nil || json.Unmarshal(job.SplitConfiguration, &split) != nil {
		return TrainingEngineRequest{}, ErrInvalidRepositoryInput
	}
	epochs, batch, seed := intValue(cfg, "epochs", 5), intValue(cfg, "batch_size", 8), intValue(cfg, "seed", 42)
	lr := floatValue(cfg, "learning_rate", 0.001)
	deepfakeClassWeight := floatValue(cfg, "deepfake_class_weight", 1.0)
	selectionMetric := strings.ToLower(strings.TrimSpace(trainingStringValue(cfg, "selection_metric", "accuracy")))
	validation := int(math.Round(floatValue(split, "validation", 20)))
	test := int(math.Round(floatValue(split, "test", 0)))
	if epochs < 1 || batch < 1 || seed < 0 || lr <= 0 || deepfakeClassWeight < 1 || deepfakeClassWeight > 3 || (selectionMetric != "accuracy" && selectionMetric != "f1" && selectionMetric != "recall") || validation < 10 || validation > 40 || test < 0 || test > 40 || validation+test > 80 {
		return TrainingEngineRequest{}, ErrInvalidRepositoryInput
	}
	detectorScope := NormalizeConstant(job.DetectorScope)
	if detectorScope == "" {
		detectorScope = JobTypeDeepfakeImage
	}
	if detectorScope != JobTypeDeepfakeImage && detectorScope != JobTypeSyntheticImage {
		return TrainingEngineRequest{}, ErrInvalidRepositoryInput
	}
	return TrainingEngineRequest{RequestID: uuid.New(), TrainingJobID: job.ID, OrganizationID: job.OrganizationID, DatasetVersionID: job.DatasetVersionID, DatasetPath: job.DatasetPath, ModelCode: job.ModelCode, DetectorScope: detectorScope, Epochs: epochs, BatchSize: batch, LearningRate: lr, DeepfakeClassWeight: deepfakeClassWeight, SelectionMetric: selectionMetric, ValidationPercent: validation, TestPercent: test, Seed: seed}, nil
}

func intValue(values map[string]any, key string, fallback int) int {
	return int(math.Round(floatValue(values, key, float64(fallback))))
}
func floatValue(values map[string]any, key string, fallback float64) float64 {
	if value, ok := values[key].(float64); ok && !math.IsNaN(value) && !math.IsInf(value, 0) {
		return value
	}
	return fallback
}
func trainingStringValue(values map[string]any, key, fallback string) string {
	if value, ok := values[key].(string); ok && strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func (w *TrainingWorker) persistSuccess(ctx context.Context, job claimedTrainingJob, response *TrainingEngineResponse, verifiedPath string, durationMS int64) error {
	tx, err := w.repository.databasePool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, metric := range response.Metrics {
		metric.MetricName, metric.DatasetSplit = strings.TrimSpace(metric.MetricName), NormalizeConstant(metric.DatasetSplit)
		if metric.MetricName == "" || (metric.DatasetSplit != "TRAIN" && metric.DatasetSplit != "VALIDATION" && metric.DatasetSplit != "TEST") || metric.EpochNumber < 0 || math.IsNaN(metric.MetricValue) || math.IsInf(metric.MetricValue, 0) {
			return ErrInvalidMediaEngineResponse
		}
		if _, err = tx.Exec(ctx, `INSERT INTO ml_training_job_metrics (training_job_id,metric_name,metric_value,dataset_split,epoch_number) VALUES ($1,$2,$3,$4,$5)`, job.ID, metric.MetricName, metric.MetricValue, metric.DatasetSplit, metric.EpochNumber); err != nil {
			return err
		}
	}
	result, err := tx.Exec(ctx, `UPDATE ml_training_jobs SET status='AWAITING_APPROVAL',train_record_count=$2,validation_record_count=$3,test_record_count=$4,artifact_path=$5,artifact_sha256=$6,artifact_format='PTH',processing_duration_ms=$7,completed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=$1 AND status='RUNNING'`, job.ID, response.TrainingRecordCount, response.ValidationRecordCount, response.TestRecordCount, verifiedPath, strings.ToLower(response.ArtifactSHA256), durationMS)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("%w: training job was no longer running", ErrAnalysisJobConflict)
	}
	return tx.Commit(ctx)
}

func (w *TrainingWorker) fail(ctx context.Context, jobID uuid.UUID, cause error) {
	message := safeAnalysisErrorMessage(cause)
	_, _ = w.repository.databasePool.Exec(ctx, `UPDATE ml_training_jobs SET status='FAILED',error_code='TRAINING_EXECUTION_FAILED',error_message=$2,completed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=$1 AND status='RUNNING'`, jobID, message)
}
