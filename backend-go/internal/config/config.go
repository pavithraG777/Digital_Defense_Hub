package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	App      AppConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Storage  StorageConfig
	Log      LogConfig
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
	UploadPath    string
	MaxUploadSize int64
}

type LogConfig struct {
	Level string
	File  string
}

func Load() (*Config, error) {
	viper.SetConfigFile(".env")
	viper.SetConfigType("env")

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf(
			"unable to load .env file: %w",
			err,
		)
	}

	accessTokenDuration, err := parseDuration(
		viper.GetString("JWT_EXPIRATION"),
		15*time.Minute,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid JWT_EXPIRATION value: %w",
			err,
		)
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
			UploadPath:    viper.GetString("UPLOAD_PATH"),
			MaxUploadSize: viper.GetInt64("MAX_UPLOAD_SIZE"),
		},

		Log: LogConfig{
			Level: viper.GetString("LOG_LEVEL"),
			File:  viper.GetString("LOG_FILE"),
		},
	}

	fmt.Println("JWT Secret:", cfg.JWT.Secret)
	fmt.Println("JWT Secret Length:", len(cfg.JWT.Secret))
	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
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

func validate(cfg *Config) error {
	if strings.TrimSpace(cfg.App.Name) == "" {
		return fmt.Errorf("APP_NAME is required")
	}

	if strings.TrimSpace(cfg.App.Port) == "" {
		return fmt.Errorf("APP_PORT is required")
	}

	if strings.TrimSpace(cfg.Database.Host) == "" {
		return fmt.Errorf("DB_HOST is required")
	}

	if strings.TrimSpace(cfg.Database.Port) == "" {
		return fmt.Errorf("DB_PORT is required")
	}

	if strings.TrimSpace(cfg.Database.User) == "" {
		return fmt.Errorf("DB_USER is required")
	}

	if strings.TrimSpace(cfg.Database.Name) == "" {
		return fmt.Errorf("DB_NAME is required")
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

	return nil
}
