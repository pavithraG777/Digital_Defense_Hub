package honeytoken

import (
	"time"

	"github.com/google/uuid"
)

// InvestigationCase is the analyst workspace that groups related incidents.
type InvestigationCase struct {
	ID                 uuid.UUID
	OrganizationID     uuid.UUID
	CaseNumber         string
	Title              string
	Description        *string
	Status             string
	Priority           string
	LeadInvestigatorID *uuid.UUID
	OpenedBy           uuid.UUID
	OpenedAt           time.Time
	ClosedAt           *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}
