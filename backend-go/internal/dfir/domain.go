package dfir

import "time"

// EvidenceType enumerates the main evidence categories used in a defensive DFIR workflow.
type EvidenceType string

const (
	EvidenceTypeFile        EvidenceType = "file"
	EvidenceTypeNetwork     EvidenceType = "network"
	EvidenceTypeEndpoint    EvidenceType = "endpoint"
	EvidenceTypeMemory      EvidenceType = "memory"
	EvidenceTypeHoneytoken  EvidenceType = "honeytoken"
	EvidenceTypeCanary      EvidenceType = "canary"
	EvidenceTypeMalware     EvidenceType = "malware"
	EvidenceTypeThreatIntel EvidenceType = "threat_intel"
	EvidenceTypeCredential  EvidenceType = "credential"
	EvidenceTypeSystemEvent EvidenceType = "system_event"
)

// RiskLevel expresses the severity of a detection or investigation outcome.
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// DetectionRule models a defensive detection rule used by the DFIR scoring engine.
type DetectionRule struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Signals     map[string]float64 `json:"signals"`
	Weight      float64            `json:"weight"`
	Confidence  float64            `json:"confidence"`
	RiskLevel   RiskLevel          `json:"risk_level"`
	Notes       string             `json:"notes"`
}

// DetectionFinding contains a normalized finding generated from event signals.
type DetectionFinding struct {
	MatchedSignals []string           `json:"matched_signals"`
	RuleScores     map[string]float64 `json:"rule_scores"`
	Score          float64            `json:"score"`
	RiskLevel      RiskLevel          `json:"risk_level"`
	Confidence     float64            `json:"confidence"`
	Summary        string             `json:"summary"`
	RuleCount      int                `json:"rule_count"`
}

// HoneytokenAsset captures an intelligence artifact designed to detect unauthorized access.
type HoneytokenAsset struct {
	ID         string                 `json:"id"`
	AssetType  string                 `json:"asset_type"`
	Identifier string                 `json:"identifier"`
	OrgID      string                 `json:"organization_id"`
	CreatedAt  time.Time              `json:"created_at"`
	Rotating   bool                   `json:"rotating"`
	LastSeen   time.Time              `json:"last_seen,omitempty"`
	Additional map[string]interface{} `json:"additional,omitempty"`
}

// CanaryAsset models a defensive canary file or object with forensic tracking.
type CanaryAsset struct {
	ID          string                 `json:"id"`
	OrgID       string                 `json:"organization_id"`
	Path        string                 `json:"path"`
	Kind        string                 `json:"kind"`
	FirstSeen   time.Time              `json:"first_seen,omitempty"`
	LastSeen    time.Time              `json:"last_seen,omitempty"`
	AccessCount int                    `json:"access_count"`
	Events      []string               `json:"events,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NetworkEvidence models defensive network telemetry used in attribution and triage.
type NetworkEvidence struct {
	ID              string    `json:"id"`
	OrganizationID  string    `json:"organization_id"`
	SourceIP        string    `json:"source_ip,omitempty"`
	DestinationIP   string    `json:"destination_ip,omitempty"`
	SourcePort      int       `json:"source_port,omitempty"`
	DestinationPort int       `json:"destination_port,omitempty"`
	Protocol        string    `json:"protocol,omitempty"`
	ConnectionTime  time.Time `json:"connection_time,omitempty"`
	SessionDuration float64   `json:"session_duration,omitempty"`
	DNSQuery        string    `json:"dns_query,omitempty"`
	TLSFingerprint  string    `json:"tls_fingerprint,omitempty"`
	ASN             int       `json:"asn,omitempty"`
	ISP             string    `json:"isp,omitempty"`
	Country         string    `json:"country,omitempty"`
	Region          string    `json:"region,omitempty"`
	City            string    `json:"city,omitempty"`
}

// EndpointEvidence captures host telemetry for investigation.
type EndpointEvidence struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Hostname       string    `json:"hostname,omitempty"`
	Username       string    `json:"username,omitempty"`
	Domain         string    `json:"domain,omitempty"`
	LoggedInUser   string    `json:"logged_in_user,omitempty"`
	ProcessTree    string    `json:"process_tree,omitempty"`
	ParentProcess  string    `json:"parent_process,omitempty"`
	CommandLine    string    `json:"command_line,omitempty"`
	CollectedAt    time.Time `json:"collected_at,omitempty"`
}

// AttributionInsight captures evidence-based attribution confidence and supporting signals.
type AttributionInsight struct {
	ID             string                 `json:"id"`
	IncidentID     string                 `json:"incident_id"`
	Confidence     float64                `json:"confidence"`
	Summary        string                 `json:"summary"`
	Signals        []string               `json:"signals,omitempty"`
	Infrastructure map[string]interface{} `json:"infrastructure,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
}
