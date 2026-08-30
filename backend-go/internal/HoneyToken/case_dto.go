package honeytoken

import "time"

type CreateInvestigationCaseRequest struct {
	Title              string  `json:"title" binding:"required,min=3,max=255"`
	Description        *string `json:"description,omitempty" binding:"omitempty,max=10000"`
	Priority           string  `json:"priority" binding:"omitempty,oneof=LOW MEDIUM HIGH URGENT"`
	LeadInvestigatorID *string `json:"lead_investigator_id,omitempty" binding:"omitempty,uuid"`
}

type UpdateInvestigationCaseRequest struct {
	Title       *string `json:"title,omitempty" binding:"omitempty,min=3,max=255"`
	Description *string `json:"description,omitempty" binding:"omitempty,max=10000"`
	Priority    *string `json:"priority,omitempty" binding:"omitempty,oneof=LOW MEDIUM HIGH URGENT"`
	Status      *string `json:"status,omitempty" binding:"omitempty,oneof=OPEN ACTIVE ON_HOLD CLOSED CANCELLED"`
}

type LinkCaseIncidentRequest struct {
	IncidentID string `json:"incident_id" binding:"required,uuid"`
}

type InvestigationCaseResponse struct {
	ID                 string     `json:"id"`
	OrganizationID     string     `json:"organization_id"`
	CaseNumber         string     `json:"case_number"`
	Title              string     `json:"title"`
	Description        *string    `json:"description,omitempty"`
	Status             string     `json:"status"`
	Priority           string     `json:"priority"`
	LeadInvestigatorID *string    `json:"lead_investigator_id,omitempty"`
	OpenedBy           string     `json:"opened_by"`
	OpenedAt           time.Time  `json:"opened_at"`
	ClosedAt           *time.Time `json:"closed_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type InvestigationCaseListResponse struct {
	Cases []InvestigationCaseResponse `json:"cases"`
	Total int64                       `json:"total"`
}
