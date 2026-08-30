package threatintel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type localFeedEntry struct {
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	Reputation int      `json:"reputation"`
	Confidence int      `json:"confidence"`
	Tags       []string `json:"tags"`
	Reference  string   `json:"reference"`
}

type localIntelligenceProvider struct {
	entries map[string]localFeedEntry
	now     func() time.Time
}

// NewLocalProviderWorker creates an offline provider. An empty feed path is
// valid and still provides deterministic private/reserved/unknown verdicts.
func NewLocalProviderWorker(db *pgxpool.Pool, feedPath string) (*ProviderWorker, error) {
	provider, err := newLocalIntelligenceProvider(feedPath)
	if err != nil {
		return nil, err
	}
	return &ProviderWorker{db: db, owner: "local-" + fmt.Sprint(time.Now().UnixNano()), provider: provider}, nil
}

func newLocalIntelligenceProvider(feedPath string) (*localIntelligenceProvider, error) {
	p := &localIntelligenceProvider{entries: map[string]localFeedEntry{}, now: func() time.Time { return time.Now().UTC() }}
	feedPath = strings.TrimSpace(feedPath)
	if feedPath == "" {
		return p, nil
	}
	data, err := os.ReadFile(feedPath)
	if err != nil {
		return nil, fmt.Errorf("read local threat intelligence feed: %w", err)
	}
	var entries []localFeedEntry
	if err = json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode local threat intelligence feed: %w", err)
	}
	for _, entry := range entries {
		kind := strings.ToUpper(strings.TrimSpace(entry.Type))
		value, normalizeErr := normalize(kind, entry.Value)
		if normalizeErr != nil || entry.Reputation < 0 || entry.Reputation > 100 || entry.Confidence < 0 || entry.Confidence > 100 || strings.TrimSpace(entry.Reference) == "" {
			return nil, fmt.Errorf("invalid local threat intelligence feed entry %q", entry.Reference)
		}
		entry.Type, entry.Value = kind, value
		p.entries[kind+"\x00"+value] = entry
	}
	return p, nil
}

func (p *localIntelligenceProvider) Enrich(_ context.Context, query providerQuery) (providerResult, error) {
	now := p.now()
	if entry, ok := p.entries[strings.ToUpper(query.Type)+"\x00"+query.Value]; ok {
		return providerResult{Provider: "LOCAL_OFFLINE_FEED", SourceReference: entry.Reference, Reputation: entry.Reputation, Confidence: entry.Confidence, Tags: entry.Tags, LastSeenAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour), Raw: map[string]any{"match": "exact", "offline": true}}, nil
	}
	if strings.EqualFold(query.Type, "IP") {
		if ip := net.ParseIP(query.Value); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			return providerResult{Provider: "LOCAL_NETWORK_CLASSIFIER", SourceReference: "builtin:non-public-ip", Reputation: 0, Confidence: 95, Tags: []string{"non-public", "offline"}, LastSeenAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour), Raw: map[string]any{"match": "network-classification", "offline": true}}, nil
		}
	}
	digest := sha256.Sum256([]byte(strings.ToUpper(query.Type) + ":" + query.Value))
	return providerResult{Provider: "LOCAL_OFFLINE_FEED", SourceReference: "local:unknown:" + hex.EncodeToString(digest[:8]), Reputation: 0, Confidence: 20, Tags: []string{"unknown", "offline"}, LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour), Raw: map[string]any{"match": "none", "offline": true}}, nil
}
