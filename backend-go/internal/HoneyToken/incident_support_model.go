package honeytoken

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// IncidentThreat represents the relationship between an incident and a
// correlated threat.
type IncidentThreat struct {
	IncidentID   uuid.UUID  `json:"incident_id"`
	ThreatID     uuid.UUID  `json:"threat_id"`
	RelationType string     `json:"relation_type"`
	AddedBy      *uuid.UUID `json:"added_by,omitempty"`
	AddedAt      time.Time  `json:"added_at"`
}

// IncidentTimelineEntry represents an immutable chronological incident event.
type IncidentTimelineEntry struct {
	ID             uuid.UUID       `json:"id"`
	IncidentID     uuid.UUID       `json:"incident_id"`
	OrganizationID uuid.UUID       `json:"organization_id"`
	EventType      string          `json:"event_type"`
	Title          string          `json:"title"`
	Description    *string         `json:"description,omitempty"`
	PreviousStatus *string         `json:"previous_status,omitempty"`
	NewStatus      *string         `json:"new_status,omitempty"`
	ActorUserID    *uuid.UUID      `json:"actor_user_id,omitempty"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
	OccurredAt     time.Time       `json:"occurred_at"`
	CreatedAt      time.Time       `json:"created_at"`
}

// IncidentEvidence represents forensic evidence associated with an incident.
type IncidentEvidence struct {
	ID             uuid.UUID `json:"id"`
	IncidentID     uuid.UUID `json:"incident_id"`
	OrganizationID uuid.UUID `json:"organization_id"`

	EvidenceCode string  `json:"evidence_code"`
	EvidenceType string  `json:"evidence_type"`
	EvidenceName string  `json:"evidence_name"`
	Description  *string `json:"description,omitempty"`

	ThreatID        *uuid.UUID `json:"threat_id,omitempty"`
	FileEventID     *uuid.UUID `json:"file_event_id,omitempty"`
	ProtectedFileID *uuid.UUID `json:"protected_file_id,omitempty"`
	HoneytokenID    *uuid.UUID `json:"honeytoken_id,omitempty"`
	CanaryFileID    *uuid.UUID `json:"canary_file_id,omitempty"`

	StoragePath      *string `json:"-"`
	OriginalFileName *string `json:"original_file_name,omitempty"`
	MimeType         *string `json:"mime_type,omitempty"`
	FileSizeBytes    *int64  `json:"file_size_bytes,omitempty"`

	EvidenceHash    *string `json:"evidence_hash,omitempty"`
	HashAlgorithm   string  `json:"hash_algorithm"`
	IntegrityStatus string  `json:"integrity_status"`
	IsImmutable     bool    `json:"is_immutable"`

	CollectedBy *uuid.UUID `json:"collected_by,omitempty"`
	VerifiedBy  *uuid.UUID `json:"verified_by,omitempty"`
	CollectedAt time.Time  `json:"collected_at"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`

	Metadata json.RawMessage `json:"metadata,omitempty"`

	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}
