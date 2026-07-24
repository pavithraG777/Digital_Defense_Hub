package honeytoken

// Incident-threat relations describe how a threat belongs to an incident.
const (
	IncidentThreatRelationPrimary    = "PRIMARY"
	IncidentThreatRelationRelated    = "RELATED"
	IncidentThreatRelationSupporting = "SUPPORTING"
)

// Incident timeline event types describe investigation history actions.
const (
	IncidentTimelineEventCreated              = "CREATED"
	IncidentTimelineEventThreatLinked         = "THREAT_LINKED"
	IncidentTimelineEventAssigned             = "ASSIGNED"
	IncidentTimelineEventStatusChanged        = "STATUS_CHANGED"
	IncidentTimelineEventInvestigationUpdated = "INVESTIGATION_UPDATED"
	IncidentTimelineEventContainmentAction    = "CONTAINMENT_ACTION"
	IncidentTimelineEventEvidenceAdded        = "EVIDENCE_ADDED"
	IncidentTimelineEventNoteAdded            = "NOTE_ADDED"
	IncidentTimelineEventSystemAction         = "SYSTEM_ACTION"
)

// Incident evidence types classify forensic artifacts.
const (
	IncidentEvidenceTypeFileEvent          = "FILE_EVENT"
	IncidentEvidenceTypeProtectedFile      = "PROTECTED_FILE"
	IncidentEvidenceTypeHoneytoken         = "HONEYTOKEN"
	IncidentEvidenceTypeCanaryFile         = "CANARY_FILE"
	IncidentEvidenceTypeFileCopy           = "FILE_COPY"
	IncidentEvidenceTypeLog                = "LOG"
	IncidentEvidenceTypeScreenshot         = "SCREENSHOT"
	IncidentEvidenceTypeMemoryDump         = "MEMORY_DUMP"
	IncidentEvidenceTypeProcessInformation = "PROCESS_INFORMATION"
	IncidentEvidenceTypeSystemArtifact     = "SYSTEM_ARTIFACT"
	IncidentEvidenceTypeMedia              = "MEDIA"
	IncidentEvidenceTypeReport             = "REPORT"
	IncidentEvidenceTypeOther              = "OTHER"
)

// Incident evidence integrity statuses represent verification results.
const (
	IncidentEvidenceIntegrityPending     = "PENDING"
	IncidentEvidenceIntegrityVerified    = "VERIFIED"
	IncidentEvidenceIntegrityMismatch    = "MISMATCH"
	IncidentEvidenceIntegrityUnavailable = "UNAVAILABLE"
)

// Incident evidence hash algorithms.
const (
	IncidentEvidenceHashAlgorithmSHA256 = "SHA256"
	IncidentEvidenceHashAlgorithmSHA384 = "SHA384"
	IncidentEvidenceHashAlgorithmSHA512 = "SHA512"
)

// Incident evidence identifiers and storage configuration.
const (
	IncidentEvidenceCodePrefix = "DDH-EVD"
)
