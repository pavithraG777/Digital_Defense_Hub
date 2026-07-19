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

	if err := logger.Init(); err != nil {
		log.Fatal(err)
	}
	defer logger.Sync()

	db, err := database.Connect(cfg, logger.Log)
	if err != nil {
		logger.Log.Fatal(
			"Database connection failed",
			zap.Error(err),
		)
	}
	defer db.Close(logger.Log)

	r := router.SetupRouter(
		db,
		cfg,
	)

	server := &http.Server{
		Addr:              ":" + cfg.App.Port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Log.Info(
			"Server started",
			zap.String("port", cfg.App.Port),
		)

		if err := server.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			logger.Log.Fatal(
				"Server failed",
				zap.Error(err),
			)
		}
	}()

	stop := make(chan os.Signal, 1)

	signal.Notify(
		stop,
		syscall.SIGINT,
		syscall.SIGTERM,
	)

	<-stop

	logger.Log.Info("Shutdown signal received")

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Log.Error(
			"Graceful shutdown failed",
			zap.Error(err),
		)
		return
	}

	logger.Log.Info("Server stopped gracefully")
}
