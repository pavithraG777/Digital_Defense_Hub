package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/commandanalysis"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/database"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/evidencevault"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/logger"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/recovery"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/router"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/securityevents"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/threatintel"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	if err = logger.Init(); err != nil {
		log.Fatal(err)
	}
	defer logger.Sync()

	db, err := database.Connect(
		cfg,
		logger.Log,
	)
	if err != nil {
		logger.Log.Error(
			"Database connection failed",
			zap.Error(err),
		)
		return
	}
	defer db.Close(logger.Log)

	httpRouter,
		fileMonitorService,
		notificationModule,
		preEncryptionWorker,
		adaptiveDeceptionHealthWorker,
		adaptiveDeceptionFingerprintWorker,
		deepfakeForensicsWorker,
		dfirWorker :=
		router.SetupRouterWithRuntime(
			db,
			cfg,
		)

	runtimeContext, cancelRuntime :=
		context.WithCancel(
			context.Background(),
		)
	defer cancelRuntime()
	eventWorker := securityevents.NewWorker(db.Pool)
	if err = eventWorker.Start(runtimeContext); err != nil {
		logger.Log.Error("Security event worker failed to start", zap.Error(err))
		return
	}
	if sandboxURL := viper.GetString("COMMAND_SANDBOX_URL"); sandboxURL != "" {
		sandboxWorker := commandanalysis.NewSandboxWorker(db.Pool, sandboxURL, viper.GetString("COMMAND_SANDBOX_TOKEN"))
		if err = sandboxWorker.Start(runtimeContext); err != nil {
			logger.Log.Error("Command sandbox worker failed to start", zap.Error(err))
			return
		}
	}
	if recoveryURL := viper.GetString("RECOVERY_RUNNER_URL"); recoveryURL != "" {
		recoveryWorker := recovery.NewWorker(db.Pool, recoveryURL, viper.GetString("RECOVERY_RUNNER_TOKEN"))
		if err = recoveryWorker.Start(runtimeContext); err != nil {
			logger.Log.Error("Recovery worker failed to start", zap.Error(err))
			return
		}
	}
	var providerWorker *threatintel.ProviderWorker
	if providerURL := viper.GetString("THREAT_INTEL_PROVIDER_URL"); providerURL != "" {
		providerWorker = threatintel.NewProviderWorker(db.Pool, providerURL, viper.GetString("THREAT_INTEL_PROVIDER_TOKEN"))
	} else {
		providerWorker, err = threatintel.NewLocalProviderWorker(db.Pool, viper.GetString("THREAT_INTEL_LOCAL_FEED_PATH"))
		if err != nil {
			logger.Log.Error("Local threat intelligence feed failed to load", zap.Error(err))
			return
		}
	}
	if err = providerWorker.Start(runtimeContext); err != nil {
		logger.Log.Error("Threat intelligence provider worker failed to start", zap.Error(err))
		return
	}
	integrityWorker := evidencevault.NewIntegrityWorker(db.Pool, evidencevault.LoadSigningKeysFromEnvironment())
	if err = integrityWorker.Start(runtimeContext); err != nil {
		logger.Log.Error("Evidence integrity worker failed to start", zap.Error(err))
		return
	}

	if err = notificationModule.Start(
		runtimeContext,
	); err != nil {
		logger.Log.Error(
			"Notification worker failed to start",
			zap.Error(err),
		)
		return
	}

	if preEncryptionWorker != nil {
		if err = preEncryptionWorker.Start(
			runtimeContext,
		); err != nil {
			logger.Log.Error(
				"Pre-encryption detection worker failed to start",
				zap.Error(err),
			)

			stopContext, cancelStop :=
				context.WithTimeout(
					context.Background(),
					5*time.Second,
				)

			if stopErr := notificationModule.Stop(
				stopContext,
			); stopErr != nil {
				logger.Log.Error(
					"Notification worker rollback failed",
					zap.Error(stopErr),
				)
			}

			cancelStop()
			return
		}
	}

	if adaptiveDeceptionFingerprintWorker != nil {
		if err =
			adaptiveDeceptionFingerprintWorker.Start(
				runtimeContext,
			); err != nil {
			logger.Log.Error(
				"Adaptive deception fingerprint worker failed to start",
				zap.Error(err),
			)

			stopContext, cancelStop :=
				context.WithTimeout(
					context.Background(),
					5*time.Second,
				)

			if preEncryptionWorker != nil {
				if stopErr :=
					preEncryptionWorker.Stop(
						stopContext,
					); stopErr != nil {
					logger.Log.Error(
						"Pre-encryption worker rollback failed",
						zap.Error(stopErr),
					)
				}
			}

			if stopErr := notificationModule.Stop(
				stopContext,
			); stopErr != nil {
				logger.Log.Error(
					"Notification worker rollback failed",
					zap.Error(stopErr),
				)
			}

			cancelStop()
			return
		}
	}

	if adaptiveDeceptionHealthWorker != nil {
		if err =
			adaptiveDeceptionHealthWorker.Start(
				runtimeContext,
			); err != nil {
			logger.Log.Error(
				"Adaptive deception health worker failed to start",
				zap.Error(err),
			)

			stopContext, cancelStop :=
				context.WithTimeout(
					context.Background(),
					5*time.Second,
				)

			if adaptiveDeceptionFingerprintWorker != nil {
				if stopErr :=
					adaptiveDeceptionFingerprintWorker.Stop(
						stopContext,
					); stopErr != nil {
					logger.Log.Error(
						"Adaptive deception fingerprint worker rollback failed",
						zap.Error(stopErr),
					)
				}
			}

			if preEncryptionWorker != nil {
				if stopErr :=
					preEncryptionWorker.Stop(
						stopContext,
					); stopErr != nil {
					logger.Log.Error(
						"Pre-encryption worker rollback failed",
						zap.Error(stopErr),
					)
				}
			}

			if stopErr := notificationModule.Stop(
				stopContext,
			); stopErr != nil {
				logger.Log.Error(
					"Notification worker rollback failed",
					zap.Error(stopErr),
				)
			}

			cancelStop()
			return
		}
	}

	if deepfakeForensicsWorker != nil {
		if err =
			deepfakeForensicsWorker.Start(
				runtimeContext,
			); err != nil {
			logger.Log.Error(
				"Deepfake forensics worker failed to start",
				zap.Error(err),
			)

			stopContext, cancelStop :=
				context.WithTimeout(
					context.Background(),
					5*time.Second,
				)

			if adaptiveDeceptionHealthWorker != nil {
				if stopErr :=
					adaptiveDeceptionHealthWorker.Stop(
						stopContext,
					); stopErr != nil {
					logger.Log.Error(
						"Adaptive deception health worker rollback failed",
						zap.Error(stopErr),
					)
				}
			}

			if adaptiveDeceptionFingerprintWorker != nil {
				if stopErr :=
					adaptiveDeceptionFingerprintWorker.Stop(
						stopContext,
					); stopErr != nil {
					logger.Log.Error(
						"Adaptive deception fingerprint worker rollback failed",
						zap.Error(stopErr),
					)
				}
			}

			if preEncryptionWorker != nil {
				if stopErr :=
					preEncryptionWorker.Stop(
						stopContext,
					); stopErr != nil {
					logger.Log.Error(
						"Pre-encryption worker rollback failed",
						zap.Error(stopErr),
					)
				}
			}

			if stopErr := notificationModule.Stop(
				stopContext,
			); stopErr != nil {
				logger.Log.Error(
					"Notification worker rollback failed",
					zap.Error(stopErr),
				)
			}

			cancelStop()
			return
		}
	}

	if dfirWorker != nil {
		if err = dfirWorker.Start(
			runtimeContext,
		); err != nil {
			logger.Log.Error(
				"DFIR worker failed to start",
				zap.Error(err),
			)

			stopContext, cancelStop := context.WithTimeout(context.Background(), 5*time.Second)
			if deepfakeForensicsWorker != nil {
				_ = deepfakeForensicsWorker.Stop(stopContext)
			}
			if adaptiveDeceptionHealthWorker != nil {
				_ = adaptiveDeceptionHealthWorker.Stop(stopContext)
			}
			if adaptiveDeceptionFingerprintWorker != nil {
				_ = adaptiveDeceptionFingerprintWorker.Stop(stopContext)
			}
			if preEncryptionWorker != nil {
				_ = preEncryptionWorker.Stop(stopContext)
			}
			_ = notificationModule.Stop(stopContext)
			cancelStop()

			return
		}
	}

	if err = fileMonitorService.Start(
		runtimeContext,
	); err != nil {
		logger.Log.Error(
			"File monitor service failed to start",
			zap.Error(err),
		)

		stopContext, cancelStop :=
			context.WithTimeout(
				context.Background(),
				5*time.Second,
			)

		if deepfakeForensicsWorker != nil {
			if stopErr :=
				deepfakeForensicsWorker.Stop(
					stopContext,
				); stopErr != nil {
				logger.Log.Error(
					"Deepfake forensics worker rollback failed",
					zap.Error(stopErr),
				)
			}
		}

		if adaptiveDeceptionHealthWorker != nil {
			if stopErr :=
				adaptiveDeceptionHealthWorker.Stop(
					stopContext,
				); stopErr != nil {
				logger.Log.Error(
					"Adaptive deception health worker rollback failed",
					zap.Error(stopErr),
				)
			}
		}

		if adaptiveDeceptionFingerprintWorker != nil {
			if stopErr :=
				adaptiveDeceptionFingerprintWorker.Stop(
					stopContext,
				); stopErr != nil {
				logger.Log.Error(
					"Adaptive deception fingerprint worker rollback failed",
					zap.Error(stopErr),
				)
			}
		}

		if preEncryptionWorker != nil {
			if stopErr :=
				preEncryptionWorker.Stop(
					stopContext,
				); stopErr != nil {
				logger.Log.Error(
					"Pre-encryption worker rollback failed",
					zap.Error(stopErr),
				)
			}
		}

		if stopErr := notificationModule.Stop(
			stopContext,
		); stopErr != nil {
			logger.Log.Error(
				"Notification worker rollback failed",
				zap.Error(stopErr),
			)
		}

		cancelStop()
		return
	}

	server := &http.Server{
		Addr:              ":" + cfg.App.Port,
		Handler:           httpRouter,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErrors := make(
		chan error,
		1,
	)

	go func() {
		logger.Log.Info(
			"Server started",
			zap.String(
				"port",
				cfg.App.Port,
			),
		)

		serverErrors <- server.ListenAndServe()
	}()

	signalContext, stopSignals :=
		signal.NotifyContext(
			context.Background(),
			os.Interrupt,
			syscall.SIGINT,
			syscall.SIGTERM,
		)
	defer stopSignals()

	select {
	case <-signalContext.Done():
		logger.Log.Info(
			"Shutdown signal received",
		)

	case serverError := <-serverErrors:
		if serverError != nil &&
			!errors.Is(
				serverError,
				http.ErrServerClosed,
			) {
			logger.Log.Error(
				"Server stopped unexpectedly",
				zap.Error(serverError),
			)
		}
	}

	shutdownContext, cancelShutdown :=
		context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
	defer cancelShutdown()

	if err = server.Shutdown(
		shutdownContext,
	); err != nil {
		logger.Log.Error(
			"HTTP server graceful shutdown failed",
			zap.Error(err),
		)
	}

	if err = fileMonitorService.Stop(
		shutdownContext,
	); err != nil {
		logger.Log.Error(
			"File monitor shutdown failed",
			zap.Error(err),
		)
	}

	if deepfakeForensicsWorker != nil {
		if err =
			deepfakeForensicsWorker.Stop(
				shutdownContext,
			); err != nil {
			logger.Log.Error(
				"Deepfake forensics worker shutdown failed",
				zap.Error(err),
			)
		}
	}

	if adaptiveDeceptionHealthWorker != nil {
		if err =
			adaptiveDeceptionHealthWorker.Stop(
				shutdownContext,
			); err != nil {
			logger.Log.Error(
				"Adaptive deception health worker shutdown failed",
				zap.Error(err),
			)
		}
	}

	if adaptiveDeceptionFingerprintWorker != nil {
		if err =
			adaptiveDeceptionFingerprintWorker.Stop(
				shutdownContext,
			); err != nil {
			logger.Log.Error(
				"Adaptive deception fingerprint worker shutdown failed",
				zap.Error(err),
			)
		}
	}

	if preEncryptionWorker != nil {
		if err = preEncryptionWorker.Stop(
			shutdownContext,
		); err != nil {
			logger.Log.Error(
				"Pre-encryption worker shutdown failed",
				zap.Error(err),
			)
		}
	}

	if err = notificationModule.Stop(
		shutdownContext,
	); err != nil {
		logger.Log.Error(
			"Notification worker shutdown failed",
			zap.Error(err),
		)
	}

	cancelRuntime()

	logger.Log.Info(
		"Server stopped gracefully",
	)
}
