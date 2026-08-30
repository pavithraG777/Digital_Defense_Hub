package notification

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
)

type Module struct {
	Repository            *Repository
	Service               *Service
	SecurityNotifications *SecurityNotificationService
	Handler               *Handler
	Providers             *ProviderRegistry
	Dispatcher            *Dispatcher
	Worker                *Worker
}

func NewModule(
	databasePool *pgxpool.Pool,
	notificationConfig config.NotificationConfig,
	logger *zap.Logger,
) (*Module, error) {
	if databasePool == nil {
		return nil, errors.New(
			"database pool is required for notification module",
		)
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	repository := NewRepository(databasePool)

	service, err := NewService(repository)
	if err != nil {
		return nil, fmt.Errorf(
			"initialize notification service: %w",
			err,
		)
	}

	handler := NewHandler(service)

	providers, err := buildNotificationProviders(
		notificationConfig,
	)
	if err != nil {
		return nil, err
	}

	providerRegistry, err :=
		NewProviderRegistry(providers...)
	if err != nil {
		return nil, fmt.Errorf(
			"initialize notification provider registry: %w",
			err,
		)
	}

	securityNotificationService, err :=
		NewSecurityNotificationService(
			repository,
			service,
			providerRegistry,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"initialize automatic security notification service: %w",
			err,
		)
	}

	dispatcher, err := NewDispatcher(
		repository,
		providerRegistry,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"initialize notification dispatcher: %w",
			err,
		)
	}

	var worker *Worker

	if notificationConfig.Worker.Enabled {
		worker, err = NewWorker(
			repository,
			dispatcher,
			logger,
			WorkerConfig{
				WorkerCount: notificationConfig.
					Worker.WorkerCount,
				BatchSize: notificationConfig.
					Worker.BatchSize,
				PollInterval: notificationConfig.
					Worker.PollInterval,
				DeliveryTimeout: notificationConfig.
					Worker.DeliveryTimeout,
				MaintenanceInterval: notificationConfig.
					Worker.MaintenanceInterval,
				StaleProcessingPeriod: notificationConfig.
					Worker.StaleProcessingPeriod,
			},
		)
		if err != nil {
			return nil, fmt.Errorf(
				"initialize notification worker: %w",
				err,
			)
		}
	}

	return &Module{
		Repository:            repository,
		Service:               service,
		SecurityNotifications: securityNotificationService,
		Handler:               handler,
		Providers:             providerRegistry,
		Dispatcher:            dispatcher,
		Worker:                worker,
	}, nil
}

func (m *Module) Start(
	ctx context.Context,
) error {
	if m == nil {
		return errors.New(
			"notification module is required",
		)
	}

	if m.Worker == nil {
		return nil
	}

	return m.Worker.Start(ctx)
}

func (m *Module) Stop(
	ctx context.Context,
) error {
	if m == nil ||
		m.Worker == nil {
		return nil
	}

	return m.Worker.Stop(ctx)
}

func (m *Module) WorkerEnabled() bool {
	return m != nil &&
		m.Worker != nil
}

func buildNotificationProviders(
	notificationConfig config.NotificationConfig,
) ([]Provider, error) {
	providers := []Provider{
		NewInAppProvider(),
	}

	if notificationConfig.LocalDesktop.Enabled {
		localDesktopProvider, err :=
			NewLocalDesktopProvider(
				LocalDesktopProviderConfig{
					OutboxPath: notificationConfig.
						LocalDesktop.OutboxPath,
				},
			)
		if err != nil {
			return nil, fmt.Errorf(
				"initialize local desktop notification provider: %w",
				err,
			)
		}

		providers = append(
			providers,
			localDesktopProvider,
		)
	}

	if notificationConfig.Email.Enabled {
		emailProvider, err :=
			NewEmailProvider(
				EmailProviderConfig{
					ProviderName: notificationConfig.
						Email.ProviderName,
					Host: notificationConfig.
						Email.Host,
					Port: notificationConfig.
						Email.Port,
					Username: notificationConfig.
						Email.Username,
					Password: notificationConfig.
						Email.Password,
					FromAddress: notificationConfig.
						Email.FromAddress,
					FromName: notificationConfig.
						Email.FromName,
					SubjectPrefix: notificationConfig.
						Email.SubjectPrefix,
					UseImplicitTLS: notificationConfig.
						Email.UseImplicitTLS,
					RequireSTARTTLS: notificationConfig.
						Email.RequireSTARTTLS,
					TLSInsecureSkipVerify: notificationConfig.
						Email.TLSInsecureSkipVerify,
					Timeout: notificationConfig.
						Email.Timeout,
				},
			)
		if err != nil {
			return nil, fmt.Errorf(
				"initialize email notification provider: %w",
				err,
			)
		}

		providers = append(
			providers,
			emailProvider,
		)
	}

	if notificationConfig.SMS.Enabled {
		var smsProvider Provider
		var err error
		if strings.EqualFold(notificationConfig.SMS.ProviderName, "AWS_SNS") {
			smsProvider, err = NewAWSSNSProvider(AWSSNSProviderConfig{
				Region:             notificationConfig.SMS.AWSRegion,
				Profile:            notificationConfig.SMS.AWSProfile,
				SenderID:           notificationConfig.SMS.AWSSenderID,
				SMSType:            notificationConfig.SMS.AWSSMSType,
				DefaultCountryCode: notificationConfig.SMS.DefaultCountryCode,
				Timeout:            notificationConfig.SMS.Timeout,
			})
		} else {
			smsProvider, err = NewSMSProvider(
				SMSProviderConfig{
					ProviderName: notificationConfig.
						SMS.ProviderName,
					EndpointURL: notificationConfig.
						SMS.EndpointURL,
					APIKey: notificationConfig.
						SMS.APIKey,
					APIKeyHeader: notificationConfig.
						SMS.APIKeyHeader,
					APIKeyPrefix: notificationConfig.
						SMS.APIKeyPrefix,
					FromNumber: notificationConfig.
						SMS.FromNumber,
					DefaultCountryCode: notificationConfig.
						SMS.DefaultCountryCode,
					AllowInsecureHTTP: notificationConfig.
						SMS.AllowInsecureHTTP,
					Timeout: notificationConfig.
						SMS.Timeout,
				},
			)
		}
		if err != nil {
			return nil, fmt.Errorf(
				"initialize SMS notification provider: %w",
				err,
			)
		}

		providers = append(
			providers,
			smsProvider,
		)
	}

	if notificationConfig.Webhook.Enabled {
		webhookProvider, err :=
			NewWebhookProvider(
				WebhookProviderConfig{
					ProviderName: notificationConfig.
						Webhook.ProviderName,
					EndpointURL: notificationConfig.
						Webhook.EndpointURL,
					Secret: notificationConfig.
						Webhook.Secret,
					SignatureHeader: notificationConfig.
						Webhook.SignatureHeader,
					TimestampHeader: notificationConfig.
						Webhook.TimestampHeader,
					AllowInsecureHTTP: notificationConfig.
						Webhook.AllowInsecureHTTP,
					Timeout: notificationConfig.
						Webhook.Timeout,
				},
			)
		if err != nil {
			return nil, fmt.Errorf(
				"initialize webhook notification provider: %w",
				err,
			)
		}

		providers = append(
			providers,
			webhookProvider,
		)
	}

	return providers, nil
}
