package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	defaultDeepfakeForensicsMaximumUploadBytes int64 = 512 * 1024 * 1024

	maximumDeepfakeForensicsWorkerCount = 16
)

// DeepfakeForensicsConfig controls organization-scoped
// media uploads and the durable offline analysis worker.
type DeepfakeForensicsConfig struct {
	Enabled bool

	EngineURL     string
	ServiceToken  string
	EngineTimeout time.Duration

	WorkerCount     int
	PollInterval    time.Duration
	AnalysisTimeout time.Duration
	ProcessingNode  string

	StoragePath        string
	MaximumUploadBytes int64

	StorageEncryptionEnabled bool
	StorageEncryptionKey     string
	QuarantineMalformed      bool

	MaintenanceInterval    time.Duration
	StaleProcessingTimeout time.Duration
	TemporaryFileTTL       time.Duration
	RetentionDays          int

	TrainingArtifactEngineRoot  string
	TrainingArtifactBackendRoot string
	TrainingTimeout             time.Duration
}

func loadDeepfakeForensicsConfig() (
	DeepfakeForensicsConfig,
	error,
) {
	engineTimeout, err := loadConfigurationDuration(
		"DEEPFAKE_FORENSICS_ENGINE_TIMEOUT",
		15*time.Minute,
	)
	if err != nil {
		return DeepfakeForensicsConfig{}, err
	}

	pollInterval, err := loadConfigurationDuration(
		"DEEPFAKE_FORENSICS_POLL_INTERVAL",
		time.Second,
	)
	if err != nil {
		return DeepfakeForensicsConfig{}, err
	}

	analysisTimeout, err := loadConfigurationDuration(
		"DEEPFAKE_FORENSICS_ANALYSIS_TIMEOUT",
		10*time.Minute,
	)
	if err != nil {
		return DeepfakeForensicsConfig{}, err
	}

	maintenanceInterval, err := loadConfigurationDuration(
		"DEEPFAKE_FORENSICS_MAINTENANCE_INTERVAL",
		15*time.Minute,
	)
	if err != nil {
		return DeepfakeForensicsConfig{}, err
	}

	staleProcessingTimeout, err := loadConfigurationDuration(
		"DEEPFAKE_FORENSICS_STALE_PROCESSING_TIMEOUT",
		30*time.Minute,
	)
	if err != nil {
		return DeepfakeForensicsConfig{}, err
	}

	temporaryFileTTL, err := loadConfigurationDuration(
		"DEEPFAKE_FORENSICS_TEMPORARY_FILE_TTL",
		time.Hour,
	)
	if err != nil {
		return DeepfakeForensicsConfig{}, err
	}

	trainingTimeout, err := loadConfigurationDuration(
		"ML_TRAINING_TIMEOUT",
		12*time.Hour,
	)
	if err != nil {
		return DeepfakeForensicsConfig{}, err
	}

	engineURL := strings.TrimSpace(
		viper.GetString(
			"DEEPFAKE_FORENSICS_ENGINE_URL",
		),
	)
	if engineURL == "" {
		engineURL = strings.TrimSpace(
			viper.GetString(
				"AI_RISK_ENGINE_URL",
			),
		)
	}

	serviceToken := strings.TrimSpace(
		viper.GetString(
			"DEEPFAKE_FORENSICS_SERVICE_TOKEN",
		),
	)
	if serviceToken == "" {
		serviceToken = strings.TrimSpace(
			viper.GetString(
				"AI_RISK_SERVICE_TOKEN",
			),
		)
	}

	cfg := DeepfakeForensicsConfig{
		Enabled: viper.GetBool(
			"DEEPFAKE_FORENSICS_ENABLED",
		),

		EngineURL:     engineURL,
		ServiceToken:  serviceToken,
		EngineTimeout: engineTimeout,

		WorkerCount: viper.GetInt(
			"DEEPFAKE_FORENSICS_WORKER_COUNT",
		),
		PollInterval:    pollInterval,
		AnalysisTimeout: analysisTimeout,
		ProcessingNode: strings.TrimSpace(
			viper.GetString(
				"DEEPFAKE_FORENSICS_PROCESSING_NODE",
			),
		),

		StoragePath: strings.TrimSpace(
			viper.GetString(
				"DEEPFAKE_FORENSICS_STORAGE_PATH",
			),
		),
		MaximumUploadBytes: viper.GetInt64(
			"DEEPFAKE_FORENSICS_MAXIMUM_UPLOAD_BYTES",
		),

		StorageEncryptionEnabled: viper.GetBool(
			"DEEPFAKE_FORENSICS_STORAGE_ENCRYPTION_ENABLED",
		),
		StorageEncryptionKey: strings.TrimSpace(
			viper.GetString(
				"DEEPFAKE_FORENSICS_STORAGE_ENCRYPTION_KEY",
			),
		),
		QuarantineMalformed: viper.GetBool(
			"DEEPFAKE_FORENSICS_QUARANTINE_MALFORMED",
		),

		MaintenanceInterval:    maintenanceInterval,
		StaleProcessingTimeout: staleProcessingTimeout,
		TemporaryFileTTL:       temporaryFileTTL,
		RetentionDays: viper.GetInt(
			"DEEPFAKE_FORENSICS_RETENTION_DAYS",
		),
		TrainingArtifactEngineRoot:  strings.TrimSpace(viper.GetString("ML_TRAINING_ARTIFACT_ENGINE_ROOT")),
		TrainingArtifactBackendRoot: strings.TrimSpace(viper.GetString("ML_TRAINING_ARTIFACT_ROOT")),
		TrainingTimeout:             trainingTimeout,
	}

	if err = validateDeepfakeForensicsConfig(
		cfg,
	); err != nil {
		return DeepfakeForensicsConfig{}, err
	}

	return cfg, nil
}

func setDeepfakeForensicsDefaults() {
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_ENABLED",
		true,
	)
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_ENGINE_URL",
		"",
	)
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_SERVICE_TOKEN",
		"",
	)
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_ENGINE_TIMEOUT",
		"15m",
	)

	viper.SetDefault(
		"DEEPFAKE_FORENSICS_WORKER_COUNT",
		2,
	)
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_POLL_INTERVAL",
		"1s",
	)
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_ANALYSIS_TIMEOUT",
		"10m",
	)
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_PROCESSING_NODE",
		"",
	)

	viper.SetDefault(
		"DEEPFAKE_FORENSICS_STORAGE_PATH",
		"./storage/media-analysis",
	)
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_MAXIMUM_UPLOAD_BYTES",
		defaultDeepfakeForensicsMaximumUploadBytes,
	)
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_STORAGE_ENCRYPTION_ENABLED",
		false,
	)
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_STORAGE_ENCRYPTION_KEY",
		"",
	)
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_QUARANTINE_MALFORMED",
		true,
	)

	viper.SetDefault(
		"DEEPFAKE_FORENSICS_MAINTENANCE_INTERVAL",
		"15m",
	)
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_STALE_PROCESSING_TIMEOUT",
		"30m",
	)
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_TEMPORARY_FILE_TTL",
		"1h",
	)
	viper.SetDefault(
		"DEEPFAKE_FORENSICS_RETENTION_DAYS",
		90,
	)
	viper.SetDefault("ML_TRAINING_ARTIFACT_ENGINE_ROOT", "/models/trained")
	viper.SetDefault("ML_TRAINING_ARTIFACT_ROOT", "./storage/trained-models")
	viper.SetDefault("ML_TRAINING_TIMEOUT", "12h")
}

func validateDeepfakeForensicsConfig(
	cfg DeepfakeForensicsConfig,
) error {
	if !cfg.Enabled {
		return nil
	}

	engineURL := strings.TrimSpace(
		cfg.EngineURL,
	)
	parsedURL, err := url.Parse(engineURL)
	if err != nil {
		return fmt.Errorf(
			"DEEPFAKE_FORENSICS_ENGINE_URL is invalid: %w",
			err,
		)
	}
	if parsedURL.Scheme != "http" &&
		parsedURL.Scheme != "https" {
		return errors.New(
			"DEEPFAKE_FORENSICS_ENGINE_URL must use HTTP or HTTPS",
		)
	}
	if strings.TrimSpace(parsedURL.Host) == "" {
		return errors.New(
			"DEEPFAKE_FORENSICS_ENGINE_URL host is required",
		)
	}

	if len(strings.TrimSpace(
		cfg.ServiceToken,
	)) < 32 {
		return errors.New(
			"DEEPFAKE_FORENSICS_SERVICE_TOKEN or AI_RISK_SERVICE_TOKEN must contain at least 32 characters",
		)
	}

	if cfg.EngineTimeout <= 0 {
		return errors.New(
			"DEEPFAKE_FORENSICS_ENGINE_TIMEOUT must be greater than zero",
		)
	}
	if cfg.WorkerCount < 1 ||
		cfg.WorkerCount >
			maximumDeepfakeForensicsWorkerCount {
		return fmt.Errorf(
			"DEEPFAKE_FORENSICS_WORKER_COUNT must be between 1 and %d",
			maximumDeepfakeForensicsWorkerCount,
		)
	}
	if cfg.PollInterval <= 0 {
		return errors.New(
			"DEEPFAKE_FORENSICS_POLL_INTERVAL must be greater than zero",
		)
	}
	if cfg.AnalysisTimeout <= 0 {
		return errors.New(
			"DEEPFAKE_FORENSICS_ANALYSIS_TIMEOUT must be greater than zero",
		)
	}

	if strings.TrimSpace(
		cfg.StoragePath,
	) == "" {
		return errors.New(
			"DEEPFAKE_FORENSICS_STORAGE_PATH is required",
		)
	}
	if cfg.MaximumUploadBytes <= 0 {
		return errors.New(
			"DEEPFAKE_FORENSICS_MAXIMUM_UPLOAD_BYTES must be greater than zero",
		)
	}

	if cfg.StorageEncryptionEnabled {
		key, decodeErr := base64.StdEncoding.DecodeString(
			strings.TrimSpace(
				cfg.StorageEncryptionKey,
			),
		)
		if decodeErr != nil ||
			len(key) != 32 {
			return errors.New(
				"DEEPFAKE_FORENSICS_STORAGE_ENCRYPTION_KEY must be a base64-encoded 32-byte key when storage encryption is enabled",
			)
		}
	}

	if cfg.MaintenanceInterval <= 0 {
		return errors.New(
			"DEEPFAKE_FORENSICS_MAINTENANCE_INTERVAL must be greater than zero",
		)
	}
	if cfg.StaleProcessingTimeout <=
		cfg.AnalysisTimeout {
		return errors.New(
			"DEEPFAKE_FORENSICS_STALE_PROCESSING_TIMEOUT must be greater than DEEPFAKE_FORENSICS_ANALYSIS_TIMEOUT",
		)
	}
	if cfg.TemporaryFileTTL <= 0 {
		return errors.New(
			"DEEPFAKE_FORENSICS_TEMPORARY_FILE_TTL must be greater than zero",
		)
	}
	if cfg.RetentionDays < 0 ||
		cfg.RetentionDays > 3650 {
		return errors.New(
			"DEEPFAKE_FORENSICS_RETENTION_DAYS must be between 0 and 3650",
		)
	}
	if strings.TrimSpace(cfg.TrainingArtifactEngineRoot) == "" || strings.TrimSpace(cfg.TrainingArtifactBackendRoot) == "" {
		return errors.New("ML_TRAINING_ARTIFACT_ENGINE_ROOT and ML_TRAINING_ARTIFACT_ROOT are required")
	}
	if cfg.TrainingTimeout <= 0 {
		return errors.New("ML_TRAINING_TIMEOUT must be greater than zero")
	}

	return nil
}
