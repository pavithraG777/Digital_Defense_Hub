package dfir

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type AssessmentRequest struct {
	Signals       []string `json:"signals"`
	EvidenceCount int      `json:"evidence_count"`
}

type AssessmentResponse struct {
	Score        float64 `json:"score"`
	Severity     string  `json:"severity"`
	Confidence   float64 `json:"confidence"`
	Summary      string  `json:"summary"`
	RuleScore    float64 `json:"rule_score"`
	MLScore      float64 `json:"ml_score"`
	ModelVersion string  `json:"model_version"`
	Mode         string  `json:"mode"`
}

type Incident struct {
	ID             uuid.UUID          `json:"id"`
	OrganizationID uuid.UUID          `json:"organization_id"`
	Title          string             `json:"title"`
	Severity       string             `json:"severity"`
	Signals        []string           `json:"signals"`
	Summary        string             `json:"summary"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
	Assessment     AssessmentResponse `json:"assessment"`
	EvidenceCount  int                `json:"evidence_count"`
	TimelineCount  int                `json:"timeline_count"`
}

type EvidenceArtifact struct {
	ID         uuid.UUID `json:"id"`
	IncidentID uuid.UUID `json:"incident_id"`
	Type       string    `json:"type"`
	Source     string    `json:"source"`
	Hash       string    `json:"hash"`
	CreatedAt  time.Time `json:"created_at"`
}

type TimelineEvent struct {
	ID         uuid.UUID              `json:"id"`
	IncidentID uuid.UUID              `json:"incident_id"`
	EventType  string                 `json:"event_type"`
	Source     string                 `json:"source"`
	Timestamp  time.Time              `json:"timestamp"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type ChainOfCustodyEntry struct {
	ID         uuid.UUID `json:"id"`
	ArtifactID uuid.UUID `json:"artifact_id"`
	IncidentID uuid.UUID `json:"incident_id"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	Note       string    `json:"note"`
	Timestamp  time.Time `json:"timestamp"`
}

type InvestigationReport struct {
	ID          uuid.UUID `json:"id"`
	IncidentID  uuid.UUID `json:"incident_id"`
	GeneratedAt time.Time `json:"generated_at"`
	CreatedAt   time.Time `json:"created_at"`
	Summary     string    `json:"summary"`
	JSONReport  string    `json:"json_report"`
	PDFReport   []byte    `json:"pdf_report"`
	Severity    string    `json:"severity"`
}

type IncidentSummary struct {
	IncidentID    uuid.UUID `json:"incident_id"`
	Title         string    `json:"title"`
	Severity      string    `json:"severity"`
	EvidenceCount int       `json:"evidence_count"`
	TimelineCount int       `json:"timeline_count"`
	LastUpdated   time.Time `json:"last_updated"`
}

type RelatedIncident struct {
	IncidentID    uuid.UUID `json:"incident_id"`
	Title         string    `json:"title"`
	Severity      string    `json:"severity"`
	SharedSignals int       `json:"shared_signals"`
}

type Service struct {
	model      *MLModel
	repository *Repository

	mu             sync.RWMutex
	incidents      map[uuid.UUID]*Incident
	evidence       map[uuid.UUID]*EvidenceArtifact
	timeline       map[uuid.UUID][]*TimelineEvent
	chainOfCustody map[uuid.UUID][]*ChainOfCustodyEntry
	reports        map[uuid.UUID]*InvestigationReport
}

type MLModel struct {
	Weights map[string]float64
	Bias    float64
	Version string
}

func NewService() *Service {
	return NewServiceWithRepository(nil)
}

func NewServiceWithRepository(repository *Repository) *Service {
	return &Service{
		model:          NewMLModel(),
		repository:     repository,
		incidents:      make(map[uuid.UUID]*Incident),
		evidence:       make(map[uuid.UUID]*EvidenceArtifact),
		timeline:       make(map[uuid.UUID][]*TimelineEvent),
		chainOfCustody: make(map[uuid.UUID][]*ChainOfCustodyEntry),
		reports:        make(map[uuid.UUID]*InvestigationReport),
	}
}

func (s *Service) CreateIncident(organizationID uuid.UUID, title string, signals []string) (*Incident, error) {
	if s == nil {
		return nil, ErrDFIRServiceUnavailable
	}
	if organizationID == uuid.Nil {
		return nil, ErrInvalidDFIRIncident
	}
	if strings.TrimSpace(title) == "" {
		return nil, ErrInvalidDFIRIncident
	}

	assessment := s.AssessRansomwareIndicators(AssessmentRequest{Signals: signals, EvidenceCount: len(signals)})
	incident := &Incident{
		ID:             uuid.New(),
		OrganizationID: organizationID,
		Title:          strings.TrimSpace(title),
		Severity:       assessment.Severity,
		Signals:        append([]string(nil), signals...),
		Summary:        assessment.Summary,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
		Assessment:     assessment,
	}

	if s.repository != nil {
		ctx := context.Background()
		if err := s.repository.EnsureSchema(ctx); err != nil {
			return nil, err
		}
		stored, err := s.repository.CreateIncident(ctx, incident)
		if err == nil {
			return stored, nil
		}
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.incidents[incident.ID] = incident

	return incident, nil
}

func (s *Service) AddEvidence(incidentID uuid.UUID, artifactType string, source string, hash string) (*EvidenceArtifact, error) {
	if s == nil {
		return nil, ErrDFIRServiceUnavailable
	}
	if incidentID == uuid.Nil {
		return nil, ErrInvalidDFIREvidence
	}
	if strings.TrimSpace(artifactType) == "" || strings.TrimSpace(source) == "" {
		return nil, ErrInvalidDFIREvidence
	}

	evidence := &EvidenceArtifact{
		ID:         uuid.New(),
		IncidentID: incidentID,
		Type:       strings.TrimSpace(artifactType),
		Source:     strings.TrimSpace(source),
		Hash:       strings.TrimSpace(hash),
		CreatedAt:  time.Now().UTC(),
	}

	if s.repository != nil {
		ctx := context.Background()
		if err := s.repository.EnsureSchema(ctx); err != nil {
			return nil, err
		}
		stored, err := s.repository.CreateEvidence(ctx, evidence)
		if err == nil {
			return stored, nil
		}
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.incidents[incidentID]; !ok {
		return nil, ErrIncidentNotFound
	}
	s.evidence[evidence.ID] = evidence
	s.incidents[incidentID].EvidenceCount++
	s.incidents[incidentID].UpdatedAt = time.Now().UTC()
	return evidence, nil
}

func (s *Service) AddTimelineEvent(incidentID uuid.UUID, eventType string, source string, metadata map[string]interface{}) (*TimelineEvent, error) {
	if s == nil {
		return nil, ErrDFIRServiceUnavailable
	}
	if incidentID == uuid.Nil {
		return nil, ErrInvalidDFIRTimelineEvent
	}
	if strings.TrimSpace(eventType) == "" {
		return nil, ErrInvalidDFIRTimelineEvent
	}

	event := &TimelineEvent{
		ID:         uuid.New(),
		IncidentID: incidentID,
		EventType:  strings.TrimSpace(eventType),
		Source:     strings.TrimSpace(source),
		Timestamp:  time.Now().UTC(),
		Metadata:   metadata,
	}

	if s.repository != nil {
		ctx := context.Background()
		if err := s.repository.EnsureSchema(ctx); err != nil {
			return nil, err
		}
		stored, err := s.repository.CreateTimelineEvent(ctx, event)
		if err == nil {
			return stored, nil
		}
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.incidents[incidentID]; !ok {
		return nil, ErrIncidentNotFound
	}
	s.timeline[incidentID] = append(s.timeline[incidentID], event)
	s.incidents[incidentID].TimelineCount = len(s.timeline[incidentID])
	s.incidents[incidentID].UpdatedAt = time.Now().UTC()
	return event, nil
}

func (s *Service) IncidentSummary(incidentID uuid.UUID) *IncidentSummary {
	if s == nil || incidentID == uuid.Nil {
		return nil
	}
	if s.repository != nil {
		ctx := context.Background()
		summary, err := s.repository.GetIncidentSummary(ctx, incidentID)
		if err == nil {
			return summary
		}
		return nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	incident, ok := s.incidents[incidentID]
	if !ok {
		return nil
	}
	return &IncidentSummary{
		IncidentID:    incident.ID,
		Title:         incident.Title,
		Severity:      incident.Severity,
		EvidenceCount: incident.EvidenceCount,
		TimelineCount: incident.TimelineCount,
		LastUpdated:   incident.UpdatedAt,
	}
}

func (s *Service) ListIncidents(organizationID uuid.UUID) ([]*Incident, error) {
	if s == nil {
		return nil, ErrDFIRServiceUnavailable
	}
	if organizationID == uuid.Nil {
		return nil, ErrInvalidDFIRIncident
	}

	if s.repository != nil {
		ctx := context.Background()
		return s.repository.ListIncidents(ctx, organizationID)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Incident, 0, len(s.incidents))
	for _, incident := range s.incidents {
		if incident.OrganizationID == organizationID {
			result = append(result, incident)
		}
	}
	return result, nil
}

func (s *Service) ListEvidence(incidentID uuid.UUID) ([]*EvidenceArtifact, error) {
	if s == nil {
		return nil, ErrDFIRServiceUnavailable
	}
	if incidentID == uuid.Nil {
		return nil, ErrInvalidDFIREvidence
	}

	if s.repository != nil {
		ctx := context.Background()
		return s.repository.ListEvidence(ctx, incidentID)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*EvidenceArtifact, 0)
	for _, evidence := range s.evidence {
		if evidence.IncidentID == incidentID {
			result = append(result, evidence)
		}
	}
	return result, nil
}

func (s *Service) ListTimeline(incidentID uuid.UUID) ([]*TimelineEvent, error) {
	if s == nil {
		return nil, ErrDFIRServiceUnavailable
	}
	if incidentID == uuid.Nil {
		return nil, ErrInvalidDFIRTimelineEvent
	}

	if s.repository != nil {
		ctx := context.Background()
		return s.repository.ListTimeline(ctx, incidentID)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*TimelineEvent, 0)
	for _, event := range s.timeline[incidentID] {
		result = append(result, event)
	}
	return result, nil
}

func (s *Service) FindRelatedIncidents(incidentID uuid.UUID) ([]*RelatedIncident, error) {
	if s == nil {
		return nil, ErrDFIRServiceUnavailable
	}
	if incidentID == uuid.Nil {
		return nil, ErrInvalidDFIRIncident
	}

	if s.repository != nil {
		ctx := context.Background()
		incident, err := s.repository.GetIncident(ctx, incidentID)
		if err != nil {
			return nil, ErrIncidentNotFound
		}
		candidates, err := s.repository.ListIncidents(ctx, incident.OrganizationID)
		if err != nil {
			return nil, err
		}

		signalSet := make(map[string]struct{}, len(incident.Signals))
		for _, signal := range incident.Signals {
			signalSet[strings.ToLower(strings.TrimSpace(signal))] = struct{}{}
		}

		var related []*RelatedIncident
		for _, candidate := range candidates {
			if candidate.ID == incidentID {
				continue
			}
			shared := 0
			for _, signal := range candidate.Signals {
				if _, exists := signalSet[strings.ToLower(strings.TrimSpace(signal))]; exists {
					shared++
				}
			}
			if shared > 0 {
				related = append(related, &RelatedIncident{
					IncidentID:    candidate.ID,
					Title:         candidate.Title,
					Severity:      candidate.Severity,
					SharedSignals: shared,
				})
			}
		}
		return related, nil
	}

	s.mu.RLock()
	incident, ok := s.incidents[incidentID]
	if !ok {
		s.mu.RUnlock()
		return nil, ErrIncidentNotFound
	}
	signalSet := make(map[string]struct{}, len(incident.Signals))
	for _, signal := range incident.Signals {
		signalSet[strings.ToLower(strings.TrimSpace(signal))] = struct{}{}
	}

	var related []*RelatedIncident
	for _, candidate := range s.incidents {
		if candidate.ID == incidentID {
			continue
		}
		shared := 0
		for _, signal := range candidate.Signals {
			if _, exists := signalSet[strings.ToLower(strings.TrimSpace(signal))]; exists {
				shared++
			}
		}
		if shared > 0 {
			related = append(related, &RelatedIncident{
				IncidentID:    candidate.ID,
				Title:         candidate.Title,
				Severity:      candidate.Severity,
				SharedSignals: shared,
			})
		}
	}
	s.mu.RUnlock()

	return related, nil
}

func HashEvidence(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	hash := sha256.Sum256(payload)
	return hex.EncodeToString(hash[:])
}

func ValidateEvidenceHash(hash string, payload []byte) bool {
	if hash == "" || len(payload) == 0 {
		return false
	}
	return HashEvidence(payload) == strings.ToLower(strings.TrimSpace(hash))
}

func (s *Service) PreserveEvidence(incidentID uuid.UUID, artifactType string, source string, payload []byte, actor string) (*EvidenceArtifact, error) {
	if s == nil {
		return nil, ErrDFIRServiceUnavailable
	}
	if incidentID == uuid.Nil {
		return nil, ErrInvalidDFIREvidence
	}
	if strings.TrimSpace(artifactType) == "" || strings.TrimSpace(source) == "" || len(payload) == 0 {
		return nil, ErrInvalidDFIREvidence
	}

	hash := HashEvidence(payload)
	evidence, err := s.AddEvidence(incidentID, artifactType, source, hash)
	if err != nil {
		return nil, err
	}

	if err := s.AddChainOfCustody(incidentID, evidence.ID, actor, "preserved", "Evidence preserved and hashed"); err != nil {
		return nil, err
	}
	return evidence, nil
}

func (s *Service) AddChainOfCustody(incidentID uuid.UUID, artifactID uuid.UUID, actor string, action string, note string) error {
	if s == nil {
		return ErrDFIRServiceUnavailable
	}
	if incidentID == uuid.Nil || artifactID == uuid.Nil {
		return ErrInvalidDFIRIncident
	}
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(action) == "" {
		return errors.New("invalid chain of custody entry")
	}

	entry := &ChainOfCustodyEntry{
		ID:         uuid.New(),
		ArtifactID: artifactID,
		IncidentID: incidentID,
		Actor:      strings.TrimSpace(actor),
		Action:     strings.TrimSpace(action),
		Note:       strings.TrimSpace(note),
		Timestamp:  time.Now().UTC(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.chainOfCustody[artifactID] = append(s.chainOfCustody[artifactID], entry)
	return nil
}

func (s *Service) GetChainOfCustody(artifactID uuid.UUID) ([]*ChainOfCustodyEntry, error) {
	if s == nil {
		return nil, ErrDFIRServiceUnavailable
	}
	if artifactID == uuid.Nil {
		return nil, errors.New("invalid artifact id")
	}

	s.mu.RLock()
	entries := s.chainOfCustody[artifactID]
	s.mu.RUnlock()
	if len(entries) == 0 {
		return nil, errors.New("chain of custody not found")
	}
	return append([]*ChainOfCustodyEntry(nil), entries...), nil
}

func (s *Service) GenerateInvestigationReport(incidentID uuid.UUID) (*InvestigationReport, error) {
	if s == nil {
		return nil, ErrDFIRServiceUnavailable
	}
	if incidentID == uuid.Nil {
		return nil, ErrInvalidDFIRIncident
	}

	var incident *Incident
	if s.repository != nil {
		ctx := context.Background()
		var err error
		incident, err = s.repository.GetIncident(ctx, incidentID)
		if err != nil {
			return nil, ErrIncidentNotFound
		}
	} else {
		s.mu.RLock()
		var ok bool
		incident, ok = s.incidents[incidentID]
		s.mu.RUnlock()
		if !ok {
			return nil, ErrIncidentNotFound
		}
	}

	summaryText := strings.TrimSpace(incident.Summary)
	if summaryText == "" {
		summaryText = fmt.Sprintf(
			"Investigation report for incident '%s' with severity %s, %d evidence items and %d timeline events.",
			incident.Title,
			incident.Severity,
			incident.EvidenceCount,
			incident.TimelineCount,
		)
	}

	report := &InvestigationReport{
		ID:          uuid.New(),
		IncidentID:  incident.ID,
		GeneratedAt: time.Now().UTC(),
		CreatedAt:   time.Now().UTC(),
		Summary:     summaryText,
		JSONReport:  fmt.Sprintf(`{"incident_id":"%s","title":"%s","severity":"%s","summary":"%s"}`, incident.ID, incident.Title, incident.Severity, summaryText),
		PDFReport:   []byte("PDF_REPORT_PLACEHOLDER"),
		Severity:    incident.Severity,
	}

	s.mu.Lock()
	s.reports[report.ID] = report
	s.mu.Unlock()

	return report, nil
}

var (
	ErrDFIRServiceUnavailable   = errors.New("DFIR service is unavailable")
	ErrInvalidDFIRIncident      = errors.New("invalid DFIR incident")
	ErrInvalidDFIREvidence      = errors.New("invalid DFIR evidence")
	ErrInvalidDFIRTimelineEvent = errors.New("invalid DFIR timeline event")
	ErrIncidentNotFound         = errors.New("incident not found")
)

func init() {
	_ = ErrDFIRServiceUnavailable
}

func NewMLModel() *MLModel {
	return &MLModel{
		Weights: map[string]float64{
			"rapid_file_encryption":    0.92,
			"shadow_copy_deletion":     0.85,
			"backup_deletion":          0.78,
			"canary_access":            0.83,
			"honeytoken_trigger":       0.86,
			"suspicious_powershell":    0.74,
			"privilege_escalation":     0.79,
			"unusual_network_transfer": 0.68,
			"evidence_count":           0.18,
		},
		Bias:    -1.35,
		Version: "hybrid-ransomware-v1",
	}
}

func (s *Service) AssessRansomwareIndicators(req AssessmentRequest) AssessmentResponse {
	ruleScore := 0.0
	matched := 0

	weights := map[string]float64{
		"rapid_file_encryption":    35,
		"shadow_copy_deletion":     25,
		"backup_deletion":          20,
		"canary_access":            20,
		"honeytoken_trigger":       20,
		"suspicious_powershell":    15,
		"privilege_escalation":     15,
		"unusual_network_transfer": 10,
	}

	for _, signal := range req.Signals {
		normalized := strings.ToLower(strings.TrimSpace(signal))
		if weight, ok := weights[normalized]; ok {
			ruleScore += weight
			matched++
		}
	}

	if req.EvidenceCount > 0 {
		ruleScore += float64(min(req.EvidenceCount, 10)) * 2.5
	}

	features := map[string]float64{}
	for _, signal := range req.Signals {
		normalized := strings.ToLower(strings.TrimSpace(signal))
		features[normalized] = 1
	}
	features["evidence_count"] = float64(min(req.EvidenceCount, 10))

	mlScore := 0.0
	if s.model != nil {
		mlScore = s.model.Predict(features)
	}

	combinedScore := (ruleScore * 0.7) + (mlScore * 100 * 0.3)
	confidence := 0.55 + (mlScore * 0.35) + float64(matched)*0.03
	if confidence > 0.95 {
		confidence = 0.95
	}

	severity := "low"
	switch {
	case combinedScore >= 90:
		severity = "critical"
	case combinedScore >= 60:
		severity = "high"
	case combinedScore >= 35:
		severity = "medium"
	}

	if matched == 0 {
		return AssessmentResponse{
			Score:        combinedScore,
			Severity:     "low",
			Confidence:   0.35,
			Summary:      "No ransomware-style signals matched the current evidence set.",
			RuleScore:    ruleScore,
			MLScore:      mlScore,
			ModelVersion: s.model.Version,
			Mode:         "hybrid",
		}
	}

	return AssessmentResponse{
		Score:        combinedScore,
		Severity:     severity,
		Confidence:   confidence,
		Summary:      "Ransomware-style indicators were detected and scored using a hybrid rule + ML approach.",
		RuleScore:    ruleScore,
		MLScore:      mlScore,
		ModelVersion: s.model.Version,
		Mode:         "hybrid",
	}
}

func (m *MLModel) Predict(features map[string]float64) float64 {
	if m == nil {
		return 0
	}
	linear := m.Bias
	for name, value := range features {
		if weight, ok := m.Weights[name]; ok {
			linear += weight * value
		}
	}
	return 1 / (1 + math.Exp(-linear))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
