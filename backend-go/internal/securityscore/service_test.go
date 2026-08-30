package securityscore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCalculateOrganizationRiskUsesAvailableRealFactors(t *testing.T) {
	result := calculateOrganizationRisk(rawOrganizationSignals{
		Organization: OrganizationIdentity{ID: "org-1", Code: "ORG1", Name: "One", Status: "ACTIVE"},
		TotalThreats: 3, OpenThreats: 2, AverageThreatScore: 60, MaximumThreatScore: 90,
		TotalIncidents: 2, OpenIncidents: 2, OpenCriticalIncidents: 1, OpenHighIncidents: 1,
	})

	require.True(t, result.DataAvailable)
	require.NotNil(t, result.RiskScore)
	// Threat=79.5, incident=40. With behavior unavailable the 50:30
	// weights normalize to 62.5% and 37.5%, producing 64.7.
	require.InDelta(t, 64.7, *result.RiskScore, 0.1)
	require.Equal(t, "HIGH", result.RiskLevel)
	require.False(t, result.Factors[2].Available)
	require.Nil(t, result.Factors[2].Score)
}

func TestCalculateOrganizationRiskDoesNotFabricateMissingScore(t *testing.T) {
	result := calculateOrganizationRisk(rawOrganizationSignals{Organization: OrganizationIdentity{ID: "org-2"}})
	require.False(t, result.DataAvailable)
	require.Nil(t, result.RiskScore)
	require.Equal(t, "NOT_AVAILABLE", result.RiskLevel)
}

func TestRiskLevelThresholds(t *testing.T) {
	require.Equal(t, "LOW", riskLevel(34.9))
	require.Equal(t, "MEDIUM", riskLevel(35))
	require.Equal(t, "HIGH", riskLevel(60))
	require.Equal(t, "CRITICAL", riskLevel(80))
}
