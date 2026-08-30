package threatintel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLocalProviderReturnsCuratedExactMatch(t *testing.T) {
	now := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	provider := &localIntelligenceProvider{
		entries: map[string]localFeedEntry{
			"DOMAIN\x00malware.invalid": {
				Type: "DOMAIN", Value: "malware.invalid",
				Reputation: 92, Confidence: 88,
				Tags:      []string{"c2", "college-demo"},
				Reference: "local-feed:demo-c2-001",
			},
		},
		now: func() time.Time { return now },
	}

	result, err := provider.Enrich(context.Background(), providerQuery{
		Type: "DOMAIN", Value: "malware.invalid",
	})

	require.NoError(t, err)
	require.Equal(t, 92, result.Reputation)
	require.Equal(t, 88, result.Confidence)
	require.Equal(t, "local-feed:demo-c2-001", result.SourceReference)
	require.Equal(t, true, result.Raw["offline"])
}

func TestLocalProviderClassifiesPrivateIPWithoutExternalLookup(t *testing.T) {
	provider, err := newLocalIntelligenceProvider("")
	require.NoError(t, err)

	result, err := provider.Enrich(context.Background(), providerQuery{
		Type: "IP", Value: "192.168.10.25",
	})

	require.NoError(t, err)
	require.Equal(t, "LOCAL_NETWORK_CLASSIFIER", result.Provider)
	require.Equal(t, 0, result.Reputation)
	require.Equal(t, 95, result.Confidence)
	require.Contains(t, result.Tags, "non-public")
}

func TestLocalProviderDoesNotMarkUnknownIndicatorAsMalicious(t *testing.T) {
	provider, err := newLocalIntelligenceProvider("")
	require.NoError(t, err)

	result, err := provider.Enrich(context.Background(), providerQuery{
		Type:  "SHA256",
		Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})

	require.NoError(t, err)
	require.Equal(t, 0, result.Reputation)
	require.Equal(t, 20, result.Confidence)
	require.Contains(t, result.Tags, "unknown")
	require.NotEmpty(t, result.SourceReference)
}
