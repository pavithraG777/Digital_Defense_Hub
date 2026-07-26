package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// AdaptiveDeceptionConfig controls automatic canary
// health monitoring and related worker execution.
type AdaptiveDeceptionConfig struct {
	Enabled bool

	HealthCheckInterval time.Duration
	WorkerPollInterval  time.Duration
	CheckTimeout        time.Duration

	BatchSize int
}

func loadAdaptiveDeceptionConfig() (
	AdaptiveDeceptionConfig,
	error,
) {
	healthCheckInterval, err :=
		loadConfigurationDuration(
			"ADAPTIVE_DECEPTION_HEALTH_CHECK_INTERVAL",
			5*time.Minute,
		)
	if err != nil {
		return AdaptiveDeceptionConfig{},
			err
	}

	workerPollInterval, err :=
		loadConfigurationDuration(
			"ADAPTIVE_DECEPTION_WORKER_POLL_INTERVAL",
			time.Minute,
		)
	if err != nil {
		return AdaptiveDeceptionConfig{},
			err
	}

	checkTimeout, err :=
		loadConfigurationDuration(
			"ADAPTIVE_DECEPTION_CHECK_TIMEOUT",
			30*time.Second,
		)
	if err != nil {
		return AdaptiveDeceptionConfig{},
			err
	}

	config := AdaptiveDeceptionConfig{
		Enabled: viper.GetBool(
			"ADAPTIVE_DECEPTION_ENABLED",
		),

		HealthCheckInterval: healthCheckInterval,

		WorkerPollInterval: workerPollInterval,

		CheckTimeout: checkTimeout,

		BatchSize: viper.GetInt(
			"ADAPTIVE_DECEPTION_BATCH_SIZE",
		),
	}

	if err = validateAdaptiveDeceptionConfig(
		config,
	); err != nil {
		return AdaptiveDeceptionConfig{},
			err
	}

	return config, nil
}

func setAdaptiveDeceptionDefaults() {
	viper.SetDefault(
		"ADAPTIVE_DECEPTION_ENABLED",
		true,
	)

	viper.SetDefault(
		"ADAPTIVE_DECEPTION_HEALTH_CHECK_INTERVAL",
		"5m",
	)

	viper.SetDefault(
		"ADAPTIVE_DECEPTION_WORKER_POLL_INTERVAL",
		"1m",
	)

	viper.SetDefault(
		"ADAPTIVE_DECEPTION_CHECK_TIMEOUT",
		"30s",
	)

	viper.SetDefault(
		"ADAPTIVE_DECEPTION_BATCH_SIZE",
		50,
	)
}

func validateAdaptiveDeceptionConfig(
	config AdaptiveDeceptionConfig,
) error {
	if !config.Enabled {
		return nil
	}

	if config.HealthCheckInterval <= 0 {
		return fmt.Errorf(
			"ADAPTIVE_DECEPTION_HEALTH_CHECK_INTERVAL must be greater than zero",
		)
	}

	if config.WorkerPollInterval <= 0 {
		return fmt.Errorf(
			"ADAPTIVE_DECEPTION_WORKER_POLL_INTERVAL must be greater than zero",
		)
	}

	if config.CheckTimeout <= 0 {
		return fmt.Errorf(
			"ADAPTIVE_DECEPTION_CHECK_TIMEOUT must be greater than zero",
		)
	}

	if config.BatchSize < 1 ||
		config.BatchSize > 500 {
		return fmt.Errorf(
			"ADAPTIVE_DECEPTION_BATCH_SIZE must be between 1 and 500",
		)
	}

	return nil
}
