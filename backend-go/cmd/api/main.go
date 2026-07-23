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

	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/database"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/logger"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/router"
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

	db, err := database.Connect(cfg, logger.Log)
	if err != nil {
		logger.Log.Error(
			"Database connection failed",
			zap.Error(err),
		)
		return
	}
	defer db.Close(logger.Log)

	httpRouter, fileMonitorService :=
		router.SetupRouterWithRuntime(
			db,
			cfg,
		)

	monitorContext, cancelMonitor :=
		context.WithCancel(context.Background())
	defer cancelMonitor()

	if err = fileMonitorService.Start(
		monitorContext,
	); err != nil {
		logger.Log.Error(
			"File monitor service failed to start",
			zap.Error(err),
		)
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

	serverErrors := make(chan error, 1)

	go func() {
		logger.Log.Info(
			"Server started",
			zap.String("port", cfg.App.Port),
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

	cancelMonitor()

	if err = fileMonitorService.Stop(
		shutdownContext,
	); err != nil {
		logger.Log.Error(
			"File monitor shutdown failed",
			zap.Error(err),
		)
	}

	if err = server.Shutdown(
		shutdownContext,
	); err != nil {
		logger.Log.Error(
			"HTTP server graceful shutdown failed",
			zap.Error(err),
		)
		return
	}

	logger.Log.Info(
		"Server stopped gracefully",
	)
}
