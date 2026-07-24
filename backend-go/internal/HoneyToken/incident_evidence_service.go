package honeytoken

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidIncidentEvidence = errors.New(
		"invalid incident evidence",
	)
	ErrIncidentEvidenceHashUnavailable = errors.New(
		"incident evidence hash is unavailable",
	)
)

// AddIncidentEvidence registers forensic evidence for an incident.
func (s *IncidentService) AddIncidentEvidence(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID string,
	actorUserID uuid.UUID,
	request AddIncidentEvidenceRequest,
) (*IncidentEvidenceResponse, error) {
	if organizationID == uuid.Nil ||
		actorUserID == uuid.Nil {
		return nil, ErrInvalidIncidentEvidence
	}

	parsedIncidentID, err := parseIncidentRequiredUUID(
		incidentID,
		"incident ID",
	)
	if err != nil {
		return nil, err
	}

	evidenceType := strings.ToUpper(
		strings.TrimSpace(request.EvidenceType),
	)
	evidenceName := strings.TrimSpace(
		request.EvidenceName,
	)

	if !isSupportedIncidentEvidenceType(
		evidenceType,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported evidence type",
			ErrInvalidIncidentEvidence,
		)
	}

	if evidenceName == "" {
		return nil, fmt.Errorf(
			"%w: evidence name is required",
			ErrInvalidIncidentEvidence,
		)
	}

	threatID, err := parseIncidentOptionalUUID(
		request.ThreatID,
		"threat ID",
	)
	if err != nil {
		return nil, err
	}

	fileEventID, err := parseIncidentOptionalUUID(
		request.FileEventID,
		"file event ID",
	)
	if err != nil {
		return nil, err
	}

	protectedFileID, err :=
		parseIncidentOptionalUUID(
			request.ProtectedFileID,
			"protected file ID",
		)
	if err != nil {
		return nil, err
	}

	honeytokenID, err := parseIncidentOptionalUUID(
		request.HoneytokenID,
		"honeytoken ID",
	)
	if err != nil {
		return nil, err
	}

	canaryFileID, err := parseIncidentOptionalUUID(
		request.CanaryFileID,
		"canary file ID",
	)
	if err != nil {
		return nil, err
	}

	if err = validateIncidentEvidenceReference(
		evidenceType,
		fileEventID,
		protectedFileID,
		honeytokenID,
		canaryFileID,
	); err != nil {
		return nil, err
	}

	hashAlgorithm := strings.ToUpper(
		strings.TrimSpace(request.HashAlgorithm),
	)
	if hashAlgorithm == "" {
		hashAlgorithm =
			IncidentEvidenceHashAlgorithmSHA256
	}

	if !isSupportedIncidentEvidenceHashAlgorithm(
		hashAlgorithm,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported hash algorithm",
			ErrInvalidIncidentEvidence,
		)
	}

	evidenceHash, err := normalizeIncidentEvidenceHash(
		request.EvidenceHash,
		hashAlgorithm,
	)
	if err != nil {
		return nil, err
	}

	collectedAt, err :=
		parseIncidentEvidenceCollectedAt(
			request.CollectedAt,
		)
	if err != nil {
		return nil, err
	}

	metadata, err := normalizeIncidentMetadata(
		request.Metadata,
	)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	evidenceID := uuid.New()

	evidence := &IncidentEvidence{
		ID:             evidenceID,
		IncidentID:     parsedIncidentID,
		OrganizationID: organizationID,

		EvidenceCode: generateIncidentEvidenceCode(
			evidenceID,
			now,
		),
		EvidenceType: evidenceType,
		EvidenceName: evidenceName,
		Description: normalizeIncidentOptionalText(
			request.Description,
		),

		ThreatID:        threatID,
		FileEventID:     fileEventID,
		ProtectedFileID: protectedFileID,
		HoneytokenID:    honeytokenID,
		CanaryFileID:    canaryFileID,

		OriginalFileName: normalizeIncidentOptionalText(
			request.OriginalFileName,
		),
		MimeType: normalizeIncidentOptionalText(
			request.MimeType,
		),
		FileSizeBytes: request.FileSizeBytes,

		EvidenceHash:    evidenceHash,
		HashAlgorithm:   hashAlgorithm,
		IntegrityStatus: IncidentEvidenceIntegrityPending,
		IsImmutable:     true,

		CollectedBy: incidentUUIDPointer(
			actorUserID,
		),
		CollectedAt: collectedAt,
		Metadata:    metadata,
	}

	err = s.repository.CreateEvidence(
		ctx,
		evidence,
		actorUserID,
	)
	if err != nil {
		return nil, err
	}

	response := buildIncidentEvidenceResponse(
		evidence,
	)

	return &response, nil
}

// GetIncidentEvidence returns one evidence record.
func (s *IncidentService) GetIncidentEvidence(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID string,
	evidenceID string,
) (*IncidentEvidenceResponse, error) {
	parsedIncidentID, err := parseIncidentRequiredUUID(
		incidentID,
		"incident ID",
	)
	if err != nil {
		return nil, err
	}

	parsedEvidenceID, err := parseIncidentRequiredUUID(
		evidenceID,
		"evidence ID",
	)
	if err != nil {
		return nil, err
	}

	evidence, err := s.repository.FindEvidenceByID(
		ctx,
		organizationID,
		parsedIncidentID,
		parsedEvidenceID,
	)
	if err != nil {
		return nil, err
	}

	response := buildIncidentEvidenceResponse(
		evidence,
	)

	return &response, nil
}

// ListIncidentEvidence returns validated paginated evidence.
func (s *IncidentService) ListIncidentEvidence(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID string,
	request IncidentEvidenceListQuery,
) (*IncidentEvidenceListResponse, error) {
	parsedIncidentID, err := parseIncidentRequiredUUID(
		incidentID,
		"incident ID",
	)
	if err != nil {
		return nil, err
	}

	evidenceType := strings.ToUpper(
		strings.TrimSpace(request.EvidenceType),
	)
	integrityStatus := strings.ToUpper(
		strings.TrimSpace(request.IntegrityStatus),
	)

	if evidenceType != "" &&
		!isSupportedIncidentEvidenceType(
			evidenceType,
		) {
		return nil, ErrInvalidIncidentEvidence
	}

	if integrityStatus != "" &&
		!isSupportedIncidentEvidenceIntegrityStatus(
			integrityStatus,
		) {
		return nil, ErrInvalidIncidentEvidence
	}

	page := request.Page
	if page <= 0 {
		page = 1
	}

	pageSize := request.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}

	if pageSize > 100 {
		pageSize = 100
	}

	evidenceItems, total, err :=
		s.repository.ListEvidence(
			ctx,
			organizationID,
			parsedIncidentID,
			evidenceType,
			integrityStatus,
			pageSize,
			(page-1)*pageSize,
		)
	if err != nil {
		return nil, err
	}

	responses := make(
		[]IncidentEvidenceResponse,
		0,
		len(evidenceItems),
	)

	for index := range evidenceItems {
		responses = append(
			responses,
			buildIncidentEvidenceResponse(
				&evidenceItems[index],
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

	return &IncidentEvidenceListResponse{
		Evidence:   responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// VerifyIncidentEvidence compares a calculated hash with the original hash
// using constant-time comparison and records the result.
func (s *IncidentService) VerifyIncidentEvidence(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID string,
	evidenceID string,
	actorUserID uuid.UUID,
	request VerifyIncidentEvidenceRequest,
) (*IncidentEvidenceResponse, error) {
	if actorUserID == uuid.Nil {
		return nil, ErrInvalidIncidentEvidence
	}

	parsedIncidentID, err := parseIncidentRequiredUUID(
		incidentID,
		"incident ID",
	)
	if err != nil {
		return nil, err
	}

	parsedEvidenceID, err := parseIncidentRequiredUUID(
		evidenceID,
		"evidence ID",
	)
	if err != nil {
		return nil, err
	}

	evidence, err := s.repository.FindEvidenceByID(
		ctx,
		organizationID,
		parsedIncidentID,
		parsedEvidenceID,
	)
	if err != nil {
		return nil, err
	}

	if evidence.EvidenceHash == nil {
		return nil,
			ErrIncidentEvidenceHashUnavailable
	}

	calculatedHashValue := strings.TrimSpace(
		request.CalculatedHash,
	)

	calculatedHash, err :=
		normalizeIncidentEvidenceHash(
			&calculatedHashValue,
			evidence.HashAlgorithm,
		)
	if err != nil {
		return nil, err
	}

	integrityStatus :=
		IncidentEvidenceIntegrityMismatch

	if subtle.ConstantTimeCompare(
		[]byte(*evidence.EvidenceHash),
		[]byte(*calculatedHash),
	) == 1 {
		integrityStatus =
			IncidentEvidenceIntegrityVerified
	}

	verifiedEvidence, err :=
		s.repository.VerifyEvidence(
			ctx,
			organizationID,
			parsedIncidentID,
			parsedEvidenceID,
			integrityStatus,
			actorUserID,
		)
	if err != nil {
		return nil, err
	}

	response := buildIncidentEvidenceResponse(
		verifiedEvidence,
	)

	return &response, nil
}

func buildIncidentEvidenceResponse(
	evidence *IncidentEvidence,
) IncidentEvidenceResponse {
	return IncidentEvidenceResponse{
		ID:           evidence.ID.String(),
		EvidenceCode: evidence.EvidenceCode,
		EvidenceType: evidence.EvidenceType,
		EvidenceName: evidence.EvidenceName,
		Description:  evidence.Description,

		ThreatID: incidentOptionalUUIDString(
			evidence.ThreatID,
		),
		FileEventID: incidentOptionalUUIDString(
			evidence.FileEventID,
		),
		ProtectedFileID: incidentOptionalUUIDString(
			evidence.ProtectedFileID,
		),
		HoneytokenID: incidentOptionalUUIDString(
			evidence.HoneytokenID,
		),
		CanaryFileID: incidentOptionalUUIDString(
			evidence.CanaryFileID,
		),

		OriginalFileName: evidence.
			OriginalFileName,
		MimeType:      evidence.MimeType,
		FileSizeBytes: evidence.FileSizeBytes,

		EvidenceHash:    evidence.EvidenceHash,
		HashAlgorithm:   evidence.HashAlgorithm,
		IntegrityStatus: evidence.IntegrityStatus,
		IsImmutable:     evidence.IsImmutable,

		CollectedBy: incidentOptionalUUIDString(
			evidence.CollectedBy,
		),
		VerifiedBy: incidentOptionalUUIDString(
			evidence.VerifiedBy,
		),
		CollectedAt: evidence.CollectedAt,
		VerifiedAt:  evidence.VerifiedAt,
		Metadata:    evidence.Metadata,
		CreatedAt:   evidence.CreatedAt,
		UpdatedAt:   evidence.UpdatedAt,
	}
}

func generateIncidentEvidenceCode(
	evidenceID uuid.UUID,
	createdAt time.Time,
) string {
	identifier := strings.ReplaceAll(
		evidenceID.String(),
		"-",
		"",
	)

	return fmt.Sprintf(
		"%s-%s-%s",
		IncidentEvidenceCodePrefix,
		createdAt.UTC().Format("20060102"),
		strings.ToUpper(identifier[:8]),
	)
}

func normalizeIncidentEvidenceHash(
	value *string,
	hashAlgorithm string,
) (*string, error) {
	if value == nil ||
		strings.TrimSpace(*value) == "" {
		return nil, nil
	}

	normalizedHash := strings.ToLower(
		strings.TrimSpace(*value),
	)

	requiredLength := 0

	switch hashAlgorithm {
	case IncidentEvidenceHashAlgorithmSHA256:
		requiredLength = 64

	case IncidentEvidenceHashAlgorithmSHA384:
		requiredLength = 96

	case IncidentEvidenceHashAlgorithmSHA512:
		requiredLength = 128

	default:
		return nil, ErrInvalidIncidentEvidence
	}

	if len(normalizedHash) != requiredLength {
		return nil, fmt.Errorf(
			"%w: invalid evidence hash length",
			ErrInvalidIncidentEvidence,
		)
	}

	if _, err := hex.DecodeString(
		normalizedHash,
	); err != nil {
		return nil, fmt.Errorf(
			"%w: evidence hash must be hexadecimal",
			ErrInvalidIncidentEvidence,
		)
	}

	return &normalizedHash, nil
}

func parseIncidentEvidenceCollectedAt(
	value *string,
) (time.Time, error) {
	if value == nil ||
		strings.TrimSpace(*value) == "" {
		return time.Now().UTC(), nil
	}

	parsedValue, err := time.Parse(
		time.RFC3339,
		strings.TrimSpace(*value),
	)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"%w: collected_at must use RFC3339 format",
			ErrInvalidIncidentEvidence,
		)
	}

	parsedValue = parsedValue.UTC()

	if parsedValue.After(
		time.Now().UTC().Add(5 * time.Minute),
	) {
		return time.Time{}, fmt.Errorf(
			"%w: collected_at is in the future",
			ErrInvalidIncidentEvidence,
		)
	}

	return parsedValue, nil
}

func validateIncidentEvidenceReference(
	evidenceType string,
	fileEventID *uuid.UUID,
	protectedFileID *uuid.UUID,
	honeytokenID *uuid.UUID,
	canaryFileID *uuid.UUID,
) error {
	switch evidenceType {
	case IncidentEvidenceTypeFileEvent:
		if fileEventID == nil {
			return fmt.Errorf(
				"%w: file_event_id is required",
				ErrInvalidIncidentEvidence,
			)
		}

	case IncidentEvidenceTypeProtectedFile:
		if protectedFileID == nil {
			return fmt.Errorf(
				"%w: protected_file_id is required",
				ErrInvalidIncidentEvidence,
			)
		}

	case IncidentEvidenceTypeHoneytoken:
		if honeytokenID == nil {
			return fmt.Errorf(
				"%w: honeytoken_id is required",
				ErrInvalidIncidentEvidence,
			)
		}

	case IncidentEvidenceTypeCanaryFile:
		if canaryFileID == nil {
			return fmt.Errorf(
				"%w: canary_file_id is required",
				ErrInvalidIncidentEvidence,
			)
		}
	}

	return nil
}

func isSupportedIncidentEvidenceType(
	value string,
) bool {
	switch value {
	case IncidentEvidenceTypeFileEvent,
		IncidentEvidenceTypeProtectedFile,
		IncidentEvidenceTypeHoneytoken,
		IncidentEvidenceTypeCanaryFile,
		IncidentEvidenceTypeFileCopy,
		IncidentEvidenceTypeLog,
		IncidentEvidenceTypeScreenshot,
		IncidentEvidenceTypeMemoryDump,
		IncidentEvidenceTypeProcessInformation,
		IncidentEvidenceTypeSystemArtifact,
		IncidentEvidenceTypeMedia,
		IncidentEvidenceTypeReport,
		IncidentEvidenceTypeOther:
		return true

	default:
		return false
	}
}

func isSupportedIncidentEvidenceHashAlgorithm(
	value string,
) bool {
	switch value {
	case IncidentEvidenceHashAlgorithmSHA256,
		IncidentEvidenceHashAlgorithmSHA384,
		IncidentEvidenceHashAlgorithmSHA512:
		return true

	default:
		return false
	}
}

func isSupportedIncidentEvidenceIntegrityStatus(
	value string,
) bool {
	switch value {
	case IncidentEvidenceIntegrityPending,
		IncidentEvidenceIntegrityVerified,
		IncidentEvidenceIntegrityMismatch,
		IncidentEvidenceIntegrityUnavailable:
		return true

	default:
		return false
	}
}
