package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	App          AppConfig
	Database     DatabaseConfig
	JWT          JWTConfig
	Storage      StorageConfig
	Log          LogConfig
	AIRisk       AIRiskConfig
	Notification NotificationConfig
}

type AppConfig struct {
	Name     string
	FullName string
	Env      string
	Port     string
	Version  string
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string
}

type JWTConfig struct {
	Secret              string
	AccessTokenDuration time.Duration
}

type StorageConfig struct {
	UploadPath           string
	MaxUploadSize        int64
	CanaryStoragePath    string
	CanaryDeploymentRoot string
}

type LogConfig struct {
	Level string
	File  string
}

type AIRiskConfig struct {
	Enabled bool

	EngineURL    string
	ServiceToken string

	Timeout         time.Duration
	DefaultValidity time.Duration
}

type NotificationConfig struct {
	Worker       NotificationWorkerConfig
	LocalDesktop NotificationLocalDesktopConfig
	Email        NotificationEmailConfig
	SMS          NotificationSMSConfig
	Webhook      NotificationWebhookConfig
}

type NotificationWorkerConfig struct {
	Enabled               bool
	WorkerCount           int
	BatchSize             int
	PollInterval          time.Duration
	DeliveryTimeout       time.Duration
	MaintenanceInterval   time.Duration
	StaleProcessingPeriod time.Duration
}

type NotificationLocalDesktopConfig struct {
	Enabled    bool
	OutboxPath string
}

type NotificationEmailConfig struct {
	Enabled bool

	ProviderName  string
	Host          string
	Port          int
	Username      string
	Password      string
	FromAddress   string
	FromName      string
	SubjectPrefix string

	UseImplicitTLS        bool
	RequireSTARTTLS       bool
	TLSInsecureSkipVerify bool
	Timeout               time.Duration
}

type NotificationSMSConfig struct {
	Enabled bool

	ProviderName string
	EndpointURL  string
	APIKey       string
	APIKeyHeader string
	APIKeyPrefix string
	FromNumber   string

	DefaultCountryCode string
	AllowInsecureHTTP  bool
	Timeout            time.Duration
}

type NotificationWebhookConfig struct {
	Enabled bool

	ProviderName string
	EndpointURL  string
	Secret       string

	SignatureHeader string
	TimestampHeader string

	AllowInsecureHTTP bool
	Timeout           time.Duration
}

func Load() (*Config, error) {
	viper.SetConfigFile(".env")
	viper.SetConfigType("env")

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(
		strings.NewReplacer(".", "_"),
	)

	setConfigurationDefaults()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf(
			"unable to load .env file: %w",
			err,
		)
	}

	accessTokenDuration, err :=
		loadConfigurationDuration(
			"JWT_EXPIRATION",
			15*time.Minute,
		)
	if err != nil {
		return nil, err
	}

	notificationPollInterval, err :=
		loadConfigurationDuration(
			"NOTIFICATION_POLL_INTERVAL",
			2*time.Second,
		)
	if err != nil {
		return nil, err
	}

	notificationDeliveryTimeout, err :=
		loadConfigurationDuration(
			"NOTIFICATION_DELIVERY_TIMEOUT",
			30*time.Second,
		)
	if err != nil {
		return nil, err
	}

	notificationMaintenanceInterval, err :=
		loadConfigurationDuration(
			"NOTIFICATION_MAINTENANCE_INTERVAL",
			time.Minute,
		)
	if err != nil {
		return nil, err
	}

	notificationStaleProcessingPeriod, err :=
		loadConfigurationDuration(
			"NOTIFICATION_STALE_PROCESSING_PERIOD",
			5*time.Minute,
		)
	if err != nil {
		return nil, err
	}

	emailTimeout, err :=
		loadConfigurationDuration(
			"NOTIFICATION_EMAIL_TIMEOUT",
			30*time.Second,
		)
	if err != nil {
		return nil, err
	}

	smsTimeout, err :=
		loadConfigurationDuration(
			"NOTIFICATION_SMS_TIMEOUT",
			20*time.Second,
		)
	if err != nil {
		return nil, err
	}

	webhookTimeout, err :=
		loadConfigurationDuration(
			"NOTIFICATION_WEBHOOK_TIMEOUT",
			20*time.Second,
		)
	if err != nil {
		return nil, err
	}

	aiRiskEngineTimeout, err :=
		loadConfigurationDuration(
			"AI_RISK_ENGINE_TIMEOUT",
			15*time.Second,
		)
	if err != nil {
		return nil, err
	}

	aiRiskDefaultValidity, err :=
		loadConfigurationDuration(
			"AI_RISK_DEFAULT_VALIDITY",
			24*time.Hour,
		)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		App: AppConfig{
			Name:     viper.GetString("APP_NAME"),
			FullName: viper.GetString("APP_FULL_NAME"),
			Env:      viper.GetString("APP_ENV"),
			Port:     viper.GetString("APP_PORT"),
			Version:  viper.GetString("APP_VERSION"),
		},

		Database: DatabaseConfig{
			Host:     viper.GetString("DB_HOST"),
			Port:     viper.GetString("DB_PORT"),
			User:     viper.GetString("DB_USER"),
			Password: viper.GetString("DB_PASSWORD"),
			Name:     viper.GetString("DB_NAME"),
			SSLMode:  viper.GetString("DB_SSLMODE"),
		},

		JWT: JWTConfig{
			Secret:              viper.GetString("JWT_SECRET"),
			AccessTokenDuration: accessTokenDuration,
		},

		Storage: StorageConfig{
			UploadPath: viper.GetString(
				"UPLOAD_PATH",
			),
			MaxUploadSize: viper.GetInt64(
				"MAX_UPLOAD_SIZE",
			),
			CanaryStoragePath: viper.GetString(
				"CANARY_STORAGE_PATH",
			),
			CanaryDeploymentRoot: viper.GetString(
				"CANARY_DEPLOYMENT_ROOT",
			),
		},

		Log: LogConfig{
			Level: viper.GetString("LOG_LEVEL"),
			File:  viper.GetString("LOG_FILE"),
		},

		AIRisk: AIRiskConfig{
			Enabled: viper.GetBool(
				"AI_RISK_ENABLED",
			),
			EngineURL: strings.TrimSpace(
				viper.GetString(
					"AI_RISK_ENGINE_URL",
				),
			),
			ServiceToken: strings.TrimSpace(
				viper.GetString(
					"AI_RISK_SERVICE_TOKEN",
				),
			),
			Timeout:         aiRiskEngineTimeout,
			DefaultValidity: aiRiskDefaultValidity,
		},

		Notification: NotificationConfig{
			Worker: NotificationWorkerConfig{
				Enabled: viper.GetBool(
					"NOTIFICATION_WORKER_ENABLED",
				),
				WorkerCount: viper.GetInt(
					"NOTIFICATION_WORKER_COUNT",
				),
				BatchSize: viper.GetInt(
					"NOTIFICATION_BATCH_SIZE",
				),
				PollInterval:          notificationPollInterval,
				DeliveryTimeout:       notificationDeliveryTimeout,
				MaintenanceInterval:   notificationMaintenanceInterval,
				StaleProcessingPeriod: notificationStaleProcessingPeriod,
			},

			LocalDesktop: NotificationLocalDesktopConfig{
				Enabled: viper.GetBool(
					"NOTIFICATION_LOCAL_DESKTOP_ENABLED",
				),
				OutboxPath: viper.GetString(
					"NOTIFICATION_LOCAL_DESKTOP_OUTBOX_PATH",
				),
			},

			Email: NotificationEmailConfig{
				Enabled: viper.GetBool(
					"NOTIFICATION_EMAIL_ENABLED",
				),
				ProviderName: viper.GetString(
					"NOTIFICATION_EMAIL_PROVIDER_NAME",
				),
				Host: viper.GetString(
					"NOTIFICATION_EMAIL_HOST",
				),
				Port: viper.GetInt(
					"NOTIFICATION_EMAIL_PORT",
				),
				Username: viper.GetString(
					"NOTIFICATION_EMAIL_USERNAME",
				),
				Password: viper.GetString(
					"NOTIFICATION_EMAIL_PASSWORD",
				),
				FromAddress: viper.GetString(
					"NOTIFICATION_EMAIL_FROM_ADDRESS",
				),
				FromName: viper.GetString(
					"NOTIFICATION_EMAIL_FROM_NAME",
				),
				SubjectPrefix: viper.GetString(
					"NOTIFICATION_EMAIL_SUBJECT_PREFIX",
				),
				UseImplicitTLS: viper.GetBool(
					"NOTIFICATION_EMAIL_USE_IMPLICIT_TLS",
				),
				RequireSTARTTLS: viper.GetBool(
					"NOTIFICATION_EMAIL_REQUIRE_STARTTLS",
				),
				TLSInsecureSkipVerify: viper.GetBool(
					"NOTIFICATION_EMAIL_TLS_INSECURE_SKIP_VERIFY",
				),
				Timeout: emailTimeout,
			},

			SMS: NotificationSMSConfig{
				Enabled: viper.GetBool(
					"NOTIFICATION_SMS_ENABLED",
				),
				ProviderName: viper.GetString(
					"NOTIFICATION_SMS_PROVIDER_NAME",
				),
				EndpointURL: viper.GetString(
					"NOTIFICATION_SMS_ENDPOINT_URL",
				),
				APIKey: viper.GetString(
					"NOTIFICATION_SMS_API_KEY",
				),
				APIKeyHeader: viper.GetString(
					"NOTIFICATION_SMS_API_KEY_HEADER",
				),
				APIKeyPrefix: viper.GetString(
					"NOTIFICATION_SMS_API_KEY_PREFIX",
				),
				FromNumber: viper.GetString(
					"NOTIFICATION_SMS_FROM_NUMBER",
				),
				DefaultCountryCode: viper.GetString(
					"NOTIFICATION_SMS_DEFAULT_COUNTRY_CODE",
				),
				AllowInsecureHTTP: viper.GetBool(
					"NOTIFICATION_SMS_ALLOW_INSECURE_HTTP",
				),
				Timeout: smsTimeout,
			},

			Webhook: NotificationWebhookConfig{
				Enabled: viper.GetBool(
					"NOTIFICATION_WEBHOOK_ENABLED",
				),
				ProviderName: viper.GetString(
					"NOTIFICATION_WEBHOOK_PROVIDER_NAME",
				),
				EndpointURL: viper.GetString(
					"NOTIFICATION_WEBHOOK_ENDPOINT_URL",
				),
				Secret: viper.GetString(
					"NOTIFICATION_WEBHOOK_SECRET",
				),
				SignatureHeader: viper.GetString(
					"NOTIFICATION_WEBHOOK_SIGNATURE_HEADER",
				),
				TimestampHeader: viper.GetString(
					"NOTIFICATION_WEBHOOK_TIMESTAMP_HEADER",
				),
				AllowInsecureHTTP: viper.GetBool(
					"NOTIFICATION_WEBHOOK_ALLOW_INSECURE_HTTP",
				),
				Timeout: webhookTimeout,
			},
		},
	}

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func setConfigurationDefaults() {
	viper.SetDefault(
		"AI_RISK_ENABLED",
		true,
	)
	viper.SetDefault(
		"AI_RISK_ENGINE_URL",
		"http://127.0.0.1:8091",
	)
	viper.SetDefault(
		"AI_RISK_ENGINE_TIMEOUT",
		"15s",
	)
	viper.SetDefault(
		"AI_RISK_DEFAULT_VALIDITY",
		"24h",
	)
	viper.SetDefault(
		"CANARY_STORAGE_PATH",
		"./storage/canary",
	)
	viper.SetDefault(
		"CANARY_DEPLOYMENT_ROOT",
		"./storage/canary-deployments",
	)

	viper.SetDefault(
		"NOTIFICATION_WORKER_ENABLED",
		true,
	)
	viper.SetDefault(
		"NOTIFICATION_WORKER_COUNT",
		4,
	)
	viper.SetDefault(
		"NOTIFICATION_BATCH_SIZE",
		20,
	)
	viper.SetDefault(
		"NOTIFICATION_POLL_INTERVAL",
		"2s",
	)
	viper.SetDefault(
		"NOTIFICATION_DELIVERY_TIMEOUT",
		"30s",
	)
	viper.SetDefault(
		"NOTIFICATION_MAINTENANCE_INTERVAL",
		"1m",
	)
	viper.SetDefault(
		"NOTIFICATION_STALE_PROCESSING_PERIOD",
		"5m",
	)

	viper.SetDefault(
		"NOTIFICATION_LOCAL_DESKTOP_ENABLED",
		true,
	)
	viper.SetDefault(
		"NOTIFICATION_LOCAL_DESKTOP_OUTBOX_PATH",
		"./storage/notification-outbox/local-desktop",
	)

	viper.SetDefault(
		"NOTIFICATION_EMAIL_ENABLED",
		false,
	)
	viper.SetDefault(
		"NOTIFICATION_EMAIL_PROVIDER_NAME",
		"DDH_SMTP",
	)
	viper.SetDefault(
		"NOTIFICATION_EMAIL_PORT",
		587,
	)
	viper.SetDefault(
		"NOTIFICATION_EMAIL_FROM_NAME",
		"Digital Defense Hub",
	)
	viper.SetDefault(
		"NOTIFICATION_EMAIL_SUBJECT_PREFIX",
		"[DDH]",
	)
	viper.SetDefault(
		"NOTIFICATION_EMAIL_USE_IMPLICIT_TLS",
		false,
	)
	viper.SetDefault(
		"NOTIFICATION_EMAIL_REQUIRE_STARTTLS",
		true,
	)
	viper.SetDefault(
		"NOTIFICATION_EMAIL_TLS_INSECURE_SKIP_VERIFY",
		false,
	)
	viper.SetDefault(
		"NOTIFICATION_EMAIL_TIMEOUT",
		"30s",
	)

	viper.SetDefault(
		"NOTIFICATION_SMS_ENABLED",
		false,
	)
	viper.SetDefault(
		"NOTIFICATION_SMS_PROVIDER_NAME",
		"DDH_HTTP_SMS",
	)
	viper.SetDefault(
		"NOTIFICATION_SMS_API_KEY_HEADER",
		"Authorization",
	)
	viper.SetDefault(
		"NOTIFICATION_SMS_API_KEY_PREFIX",
		"Bearer",
	)
	viper.SetDefault(
		"NOTIFICATION_SMS_DEFAULT_COUNTRY_CODE",
		"+91",
	)
	viper.SetDefault(
		"NOTIFICATION_SMS_ALLOW_INSECURE_HTTP",
		false,
	)
	viper.SetDefault(
		"NOTIFICATION_SMS_TIMEOUT",
		"20s",
	)

	viper.SetDefault(
		"NOTIFICATION_WEBHOOK_ENABLED",
		false,
	)
	viper.SetDefault(
		"NOTIFICATION_WEBHOOK_PROVIDER_NAME",
		"DDH_WEBHOOK",
	)
	viper.SetDefault(
		"NOTIFICATION_WEBHOOK_SIGNATURE_HEADER",
		"X-DDH-Signature",
	)
	viper.SetDefault(
		"NOTIFICATION_WEBHOOK_TIMESTAMP_HEADER",
		"X-DDH-Timestamp",
	)
	viper.SetDefault(
		"NOTIFICATION_WEBHOOK_ALLOW_INSECURE_HTTP",
		false,
	)
	viper.SetDefault(
		"NOTIFICATION_WEBHOOK_TIMEOUT",
		"20s",
	)
}

func loadConfigurationDuration(
	key string,
	defaultValue time.Duration,
) (time.Duration, error) {
	duration, err := parseDuration(
		viper.GetString(key),
		defaultValue,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"invalid %s value: %w",
			key,
			err,
		)
	}

	return duration, nil
}

func parseDuration(
	value string,
	defaultValue time.Duration,
) (time.Duration, error) {
	value = strings.TrimSpace(value)

	if value == "" {
		return defaultValue, nil
	}

	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}

	return duration, nil
}

func validate(
	cfg *Config,
) error {
	if strings.TrimSpace(cfg.App.Name) == "" {
		return fmt.Errorf(
			"APP_NAME is required",
		)
	}

	if strings.TrimSpace(cfg.App.Port) == "" {
		return fmt.Errorf(
			"APP_PORT is required",
		)
	}

	if strings.TrimSpace(cfg.Database.Host) == "" {
		return fmt.Errorf(
			"DB_HOST is required",
		)
	}

	if strings.TrimSpace(cfg.Database.Port) == "" {
		return fmt.Errorf(
			"DB_PORT is required",
		)
	}

	if strings.TrimSpace(cfg.Database.User) == "" {
		return fmt.Errorf(
			"DB_USER is required",
		)
	}

	if strings.TrimSpace(cfg.Database.Name) == "" {
		return fmt.Errorf(
			"DB_NAME is required",
		)
	}

	if len(cfg.JWT.Secret) < 32 {
		return fmt.Errorf(
			"JWT_SECRET must contain at least 32 characters",
		)
	}

	if cfg.JWT.AccessTokenDuration <= 0 {
		return fmt.Errorf(
			"JWT_EXPIRATION must be greater than zero",
		)
	}

	if strings.TrimSpace(
		cfg.Storage.CanaryStoragePath,
	) == "" {
		return fmt.Errorf(
			"CANARY_STORAGE_PATH is required",
		)
	}

	if strings.TrimSpace(
		cfg.Storage.CanaryDeploymentRoot,
	) == "" {
		return fmt.Errorf(
			"CANARY_DEPLOYMENT_ROOT is required",
		)
	}

	if err := validateNotificationConfig(
		cfg.Notification,
	); err != nil {
		return err
	}

	return nil
}

func validateNotificationConfig(
	cfg NotificationConfig,
) error {
	if cfg.Worker.Enabled {
		if cfg.Worker.WorkerCount < 1 {
			return fmt.Errorf(
				"NOTIFICATION_WORKER_COUNT must be at least 1",
			)
		}

		if cfg.Worker.BatchSize < 1 {
			return fmt.Errorf(
				"NOTIFICATION_BATCH_SIZE must be at least 1",
			)
		}

		if cfg.Worker.PollInterval <= 0 {
			return fmt.Errorf(
				"NOTIFICATION_POLL_INTERVAL must be greater than zero",
			)
		}

		if cfg.Worker.DeliveryTimeout <= 0 {
			return fmt.Errorf(
				"NOTIFICATION_DELIVERY_TIMEOUT must be greater than zero",
			)
		}

		if cfg.Worker.MaintenanceInterval <= 0 {
			return fmt.Errorf(
				"NOTIFICATION_MAINTENANCE_INTERVAL must be greater than zero",
			)
		}

		if cfg.Worker.StaleProcessingPeriod <= 0 {
			return fmt.Errorf(
				"NOTIFICATION_STALE_PROCESSING_PERIOD must be greater than zero",
			)
		}
	}

	if cfg.LocalDesktop.Enabled &&
		strings.TrimSpace(
			cfg.LocalDesktop.OutboxPath,
		) == "" {
		return fmt.Errorf(
			"NOTIFICATION_LOCAL_DESKTOP_OUTBOX_PATH is required",
		)
	}

	if cfg.Email.Enabled {
		if strings.TrimSpace(cfg.Email.Host) == "" {
			return fmt.Errorf(
				"NOTIFICATION_EMAIL_HOST is required",
			)
		}

		if cfg.Email.Port < 1 ||
			cfg.Email.Port > 65535 {
			return fmt.Errorf(
				"NOTIFICATION_EMAIL_PORT must be between 1 and 65535",
			)
		}

		if strings.TrimSpace(
			cfg.Email.FromAddress,
		) == "" {
			return fmt.Errorf(
				"NOTIFICATION_EMAIL_FROM_ADDRESS is required",
			)
		}

		if cfg.Email.UseImplicitTLS &&
			cfg.Email.RequireSTARTTLS {
			return fmt.Errorf(
				"email implicit TLS and STARTTLS cannot both be enabled",
			)
		}

		usernameConfigured :=
			strings.TrimSpace(
				cfg.Email.Username,
			) != ""
		passwordConfigured :=
			strings.TrimSpace(
				cfg.Email.Password,
			) != ""

		if usernameConfigured != passwordConfigured {
			return fmt.Errorf(
				"notification email username and password must be configured together",
			)
		}
	}

	if cfg.SMS.Enabled &&
		strings.TrimSpace(
			cfg.SMS.EndpointURL,
		) == "" {
		return fmt.Errorf(
			"NOTIFICATION_SMS_ENDPOINT_URL is required",
		)
	}

	if cfg.Webhook.Enabled {
		if strings.TrimSpace(
			cfg.Webhook.EndpointURL,
		) == "" {
			return fmt.Errorf(
				"NOTIFICATION_WEBHOOK_ENDPOINT_URL is required",
			)
		}

		if len(strings.TrimSpace(
			cfg.Webhook.Secret,
		)) < 32 {
			return fmt.Errorf(
				"NOTIFICATION_WEBHOOK_SECRET must contain at least 32 characters",
			)
		}
	}

	return nil
}
