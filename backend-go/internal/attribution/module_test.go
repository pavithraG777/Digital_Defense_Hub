package attribution

import (
	"testing"
	"time"
)

func TestCalculateLeadUsesHistoryAndFreshness(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	observation := Observation{
		Provider:           "provider-a",
		SourceReference:    "ref-1",
		Reputation:         70,
		ProviderConfidence: 90,
		LastSeenAt:         now.Add(-time.Hour),
		ExpiresAt:          now.Add(24 * time.Hour),
	}

	withoutHistory := calculateLead([]Observation{observation}, 0, now)
	withHistory := calculateLead([]Observation{observation}, 3, now)
	if withHistory.Confidence <= withoutHistory.Confidence {
		t.Fatalf("history should increase confidence: without=%v with=%v", withoutHistory.Confidence, withHistory.Confidence)
	}

	expired := observation
	expired.ExpiresAt = now.Add(-time.Hour)
	expiredLead := calculateLead([]Observation{expired}, 0, now)
	if expiredLead.Confidence >= withoutHistory.Confidence {
		t.Fatalf("expired intelligence must not be scored above fresh intelligence: expired=%v fresh=%v", expiredLead.Confidence, withoutHistory.Confidence)
	}
}

func TestCalculateLeadPenalizesConflictingAttribution(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	base := Observation{Provider: "a", SourceReference: "1", Reputation: 80, ProviderConfidence: 90, CountryCode: "IN", Association: "group-a", LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	consistent := base
	consistent.Provider = "b"
	consistent.SourceReference = "2"
	conflicting := consistent
	conflicting.CountryCode = "US"
	conflicting.Association = "group-b"

	consistentLead := calculateLead([]Observation{base, consistent}, 0, now)
	conflictingLead := calculateLead([]Observation{base, conflicting}, 0, now)
	if len(conflictingLead.Conflicts) != 2 {
		t.Fatalf("expected two explicit conflicts, got %#v", conflictingLead.Conflicts)
	}
	if conflictingLead.Confidence >= consistentLead.Confidence {
		t.Fatalf("conflicts should reduce confidence: conflict=%v consistent=%v", conflictingLead.Confidence, consistentLead.Confidence)
	}
}
