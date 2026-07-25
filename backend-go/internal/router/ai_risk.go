package router

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/airisk"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
)

func initializeAIRiskModule(
	databasePool *pgxpool.Pool,
	aiRiskConfig config.AIRiskConfig,
) (*airisk.RiskScoreHandler, error) {
	if !aiRiskConfig.Enabled {
		return nil, nil
	}

	if databasePool == nil {
		return nil, fmt.Errorf(
			"database pool is required for AI risk module",
		)
	}

	riskEngineClient, err :=
		airisk.NewRiskEngineClient(
			aiRiskConfig.EngineURL,
			aiRiskConfig.ServiceToken,
			aiRiskConfig.Timeout,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to initialize AI Risk Engine client: %w",
			err,
		)
	}

	riskRepository := airisk.NewRepository(
		databasePool,
	)

	riskService, err := airisk.NewService(
		riskRepository,
		riskEngineClient,
		aiRiskConfig.DefaultValidity,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to initialize AI risk service: %w",
			err,
		)
	}

	riskHandler := airisk.NewRiskScoreHandler(
		riskService,
	)

	return riskHandler, nil
}
