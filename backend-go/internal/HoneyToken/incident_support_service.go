package honeytoken

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

var ErrInvalidIncidentMetadata = errors.New(
	"invalid incident metadata",
)

// LinkIncidentThreat links an existing organization threat to an incident.
func (s *IncidentService) LinkIncidentThreat(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID string,
	actorUserID uuid.UUID,
	request LinkIncidentThreatRequest,
) error {
	if organizationID == uuid.Nil ||
		actorUserID == uuid.Nil {
		return ErrInvalidIncidentRequest
	}

	parsedIncidentID, err := parseIncidentRequiredUUID(
		incidentID,
		"incident ID",
	)
	if err != nil {
		return err
	}

	threatID, err := parseIncidentRequiredUUID(
		request.ThreatID,
		"threat ID",
	)
	if err != nil {
		return err
	}

	relationType := strings.ToUpper(
		strings.TrimSpace(request.RelationType),
	)

	if relationType == "" {
		relationType = IncidentThreatRelationRelated
	}

	if !isSupportedIncidentThreatRelation(
		relationType,
	) {
		return fmt.Errorf(
			"%w: unsupported threat relation",
			ErrInvalidIncidentRequest,
		)
	}

	return s.repository.LinkThreat(
		ctx,
		organizationID,
		parsedIncidentID,
		threatID,
		relationType,
		actorUserID,
	)
}

// ListIncidentThreats returns threats linked to an incident.
func (s *IncidentService) ListIncidentThreats(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID string,
) ([]IncidentThreatResponse, error) {
	parsedIncidentID, err := parseIncidentRequiredUUID(
		incidentID,
		"incident ID",
	)
	if err != nil {
		return nil, err
	}

	linkedThreats, err :=
		s.repository.ListLinkedThreats(
			ctx,
			organizationID,
			parsedIncidentID,
		)
	if err != nil {
		return nil, err
	}

	responses := make(
		[]IncidentThreatResponse,
		0,
		len(linkedThreats),
	)

	for index := range linkedThreats {
		responses = append(
			responses,
			buildIncidentThreatResponse(
				&linkedThreats[index],
			),
		)
	}

	return responses, nil
}

// AddIncidentTimelineNote adds a manual investigator note.
func (s *IncidentService) AddIncidentTimelineNote(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID string,
	actorUserID uuid.UUID,
	request AddIncidentTimelineNoteRequest,
) (*IncidentTimelineResponse, error) {
	if organizationID == uuid.Nil ||
		actorUserID == uuid.Nil {
		return nil, ErrInvalidIncidentRequest
	}

	parsedIncidentID, err := parseIncidentRequiredUUID(
		incidentID,
		"incident ID",
	)
	if err != nil {
		return nil, err
	}

	title := strings.TrimSpace(request.Title)
	if title == "" {
		return nil, fmt.Errorf(
			"%w: timeline title is required",
			ErrInvalidIncidentRequest,
		)
	}

	metadata, err := normalizeIncidentMetadata(
		request.Metadata,
	)
	if err != nil {
		return nil, err
	}

	entry := &IncidentTimelineEntry{
		EventType: IncidentTimelineEventNoteAdded,
		Title:     title,
		Description: normalizeIncidentOptionalText(
			request.Description,
		),
		ActorUserID: incidentUUIDPointer(
			actorUserID,
		),
		Metadata: metadata,
	}

	err = s.repository.AddTimelineEntry(
		ctx,
		organizationID,
		parsedIncidentID,
		entry,
	)
	if err != nil {
		return nil, err
	}

	response := buildIncidentTimelineResponse(
		entry,
	)

	return &response, nil
}

// ListIncidentTimeline returns validated paginated incident history.
func (s *IncidentService) ListIncidentTimeline(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID string,
	request IncidentTimelineListQuery,
) (*IncidentTimelineListResponse, error) {
	parsedIncidentID, err := parseIncidentRequiredUUID(
		incidentID,
		"incident ID",
	)
	if err != nil {
		return nil, err
	}

	eventType := strings.ToUpper(
		strings.TrimSpace(request.EventType),
	)

	if eventType != "" &&
		!isSupportedIncidentTimelineEvent(
			eventType,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported timeline event type",
			ErrInvalidIncidentRequest,
		)
	}

	page := request.Page
	if page <= 0 {
		page = 1
	}

	pageSize := request.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}

	if pageSize > 100 {
		pageSize = 100
	}

	entries, total, err :=
		s.repository.ListTimeline(
			ctx,
			organizationID,
			parsedIncidentID,
			eventType,
			pageSize,
			(page-1)*pageSize,
		)
	if err != nil {
		return nil, err
	}

	responses := make(
		[]IncidentTimelineResponse,
		0,
		len(entries),
	)

	for index := range entries {
		responses = append(
			responses,
			buildIncidentTimelineResponse(
				&entries[index],
			),
		)
	}

	totalPages := 0

	if total > 0 {
		totalPages = int(
			(total + int64(pageSize) - 1) /
				int64(pageSize),
		)
	}

	return &IncidentTimelineListResponse{
		Entries:    responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

func buildIncidentThreatResponse(
	threat *IncidentLinkedThreat,
) IncidentThreatResponse {
	return IncidentThreatResponse{
		ThreatID:     threat.ThreatID.String(),
		ThreatCode:   threat.ThreatCode,
		ThreatType:   threat.ThreatType,
		Severity:     threat.Severity,
		Status:       threat.Status,
		RelationType: threat.RelationType,
		AddedBy: incidentOptionalUUIDString(
			threat.AddedBy,
		),
		AddedAt: threat.AddedAt,
	}
}

func buildIncidentTimelineResponse(
	entry *IncidentTimelineEntry,
) IncidentTimelineResponse {
	return IncidentTimelineResponse{
		ID:             entry.ID.String(),
		EventType:      entry.EventType,
		Title:          entry.Title,
		Description:    entry.Description,
		PreviousStatus: entry.PreviousStatus,
		NewStatus:      entry.NewStatus,
		ActorUserID: incidentOptionalUUIDString(
			entry.ActorUserID,
		),
		Metadata:   entry.Metadata,
		OccurredAt: entry.OccurredAt,
		CreatedAt:  entry.CreatedAt,
	}
}

func normalizeIncidentMetadata(
	value json.RawMessage,
) (json.RawMessage, error) {
	trimmedValue := bytes.TrimSpace(value)

	if len(trimmedValue) == 0 {
		return json.RawMessage(`{}`), nil
	}

	if !json.Valid(trimmedValue) ||
		trimmedValue[0] != '{' {
		return nil, fmt.Errorf(
			"%w: metadata must be a JSON object",
			ErrInvalidIncidentMetadata,
		)
	}

	return append(
		json.RawMessage(nil),
		trimmedValue...,
	), nil
}

func isSupportedIncidentThreatRelation(
	value string,
) bool {
	switch value {
	case IncidentThreatRelationPrimary,
		IncidentThreatRelationRelated,
		IncidentThreatRelationSupporting:
		return true

	default:
		return false
	}
}

func isSupportedIncidentTimelineEvent(
	value string,
) bool {
	switch value {
	case IncidentTimelineEventCreated,
		IncidentTimelineEventThreatLinked,
		IncidentTimelineEventAssigned,
		IncidentTimelineEventStatusChanged,
		IncidentTimelineEventInvestigationUpdated,
		IncidentTimelineEventContainmentAction,
		IncidentTimelineEventEvidenceAdded,
		IncidentTimelineEventNoteAdded,
		IncidentTimelineEventSystemAction:
		return true

	default:
		return false
	}
}
