package config

import (
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

	return nil
}
