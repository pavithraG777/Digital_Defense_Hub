package honeytoken

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrHoneytokenServiceUnavailable = errors.New(
	"honeytoken service is unavailable",
)

// HoneytokenService manages organization-owned honeytokens.
type HoneytokenService struct {
	repository *Repository
	generator  *HoneytokenGenerator
}

// NewHoneytokenService creates the honeytoken business service.
func NewHoneytokenService(
	repository *Repository,
	generator *HoneytokenGenerator,
) (*HoneytokenService, error) {
	if repository == nil {
		return nil, fmt.Errorf(
			"honeytoken repository is required",
		)
	}

	if generator == nil {
		return nil, fmt.Errorf(
			"honeytoken generator is required",
		)
	}

	return &HoneytokenService{
		repository: repository,
		generator:  generator,
	}, nil
}

// CreateHoneytoken creates, encrypts and stores one decoy value.
// The generated plaintext value is returned exactly once.
func (s *HoneytokenService) CreateHoneytoken(
	ctx context.Context,
	organizationID uuid.UUID,
	createdBy uuid.UUID,
	req *CreateHoneytokenRequest,
) (*CreateHoneytokenResponse, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	if err := validateHoneytokenServiceContext(ctx); err != nil {
		return nil, err
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"organization ID is required",
		)
	}

	if createdBy == uuid.Nil {
		return nil, fmt.Errorf(
			"creator user ID is required",
		)
	}

	if req == nil {
		return nil, fmt.Errorf(
			"create honeytoken request is required",
		)
	}

	normalizeCreateHoneytokenRequest(req)

	if err := validateCreateHoneytokenRequest(req); err != nil {
		return nil, err
	}

	departmentID, err := parseOptionalHoneytokenUUID(
		req.DepartmentID,
		"department ID",
	)
	if err != nil {
		return nil, err
	}

	policyID, err := parseOptionalHoneytokenUUID(
		req.PolicyID,
		"policy ID",
	)
	if err != nil {
		return nil, err
	}

	ownerUserID, err := parseOptionalHoneytokenUUID(
		req.OwnerUserID,
		"owner user ID",
	)
	if err != nil {
		return nil, err
	}

	createdByCopy := createdBy

	if ownerUserID == nil {
		ownerUserID = &createdByCopy
	}

	expiresAt, err := parseHoneytokenExpiration(
		req.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}

	if err := s.repository.ValidateHoneytokenRelations(
		ctx,
		organizationID,
		createdBy,
		departmentID,
		policyID,
		ownerUserID,
	); err != nil {
		return nil, fmt.Errorf(
			"invalid honeytoken relation: %w",
			err,
		)
	}

	honeytokenID := uuid.New()

	generatedValue, err := s.generator.Generate(
		ctx,
		organizationID,
		honeytokenID,
		req.HoneytokenType,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate honeytoken value: %w",
			err,
		)
	}

	if generatedValue == nil {
		return nil, fmt.Errorf(
			"honeytoken generator returned an empty result",
		)
	}
	defer generatedValue.destroy()

	encryptedValue := generatedValue.encryptedValue
	valueHash := generatedValue.valueHash
	valuePrefix := generatedValue.valuePrefix

	token := &Honeytoken{
		ID:             honeytokenID,
		OrganizationID: organizationID,
		DepartmentID:   departmentID,
		PolicyID:       policyID,

		HoneytokenCode: buildHoneytokenCode(
			honeytokenID,
		),
		HoneytokenName: req.HoneytokenName,
		HoneytokenType: req.HoneytokenType,

		Description: optionalHoneytokenString(
			req.Description,
		),

		DecoyUsername: optionalHoneytokenString(
			req.DecoyUsername,
		),
		DecoyEmail: optionalHoneytokenString(
			req.DecoyEmail,
		),

		DecoyValueEncrypted: &encryptedValue,
		DecoyValueHash:      &valueHash,
		ValuePrefix:         &valuePrefix,

		TargetSystem: optionalHoneytokenString(
			req.TargetSystem,
		),

		Classification: req.Classification,
		AccessCount:    0,

		OwnerUserID: ownerUserID,
		CreatedBy:   &createdByCopy,

		ExpiresAt: expiresAt,
		Status:    HoneytokenStatusDraft,
	}

	if err := s.repository.CreateHoneytoken(
		ctx,
		token,
	); err != nil {
		return nil, fmt.Errorf(
			"failed to store honeytoken: %w",
			err,
		)
	}

	return buildCreateHoneytokenResponse(
		token,
		string(generatedValue.plainValue),
	), nil
}

// GetHoneytoken returns safe metadata without exposing encrypted
// or hashed decoy values.
func (s *HoneytokenService) GetHoneytoken(
	ctx context.Context,
	organizationID uuid.UUID,
	honeytokenID uuid.UUID,
) (*GetHoneytokenResponse, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	if err := validateHoneytokenServiceContext(ctx); err != nil {
		return nil, err
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"organization ID is required",
		)
	}

	if honeytokenID == uuid.Nil {
		return nil, fmt.Errorf(
			"honeytoken ID is required",
		)
	}

	token, err := s.repository.FindHoneytokenByID(
		ctx,
		organizationID,
		honeytokenID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get honeytoken: %w",
			err,
		)
	}

	if token == nil {
		return nil, ErrHoneytokenNotFound
	}

	return buildGetHoneytokenResponse(token), nil
}

// ListHoneytokens returns paginated organization-owned metadata.
func (s *HoneytokenService) ListHoneytokens(
	ctx context.Context,
	organizationID uuid.UUID,
	req ListHoneytokensRequest,
) (*ListHoneytokensResponse, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	if err := validateHoneytokenServiceContext(ctx); err != nil {
		return nil, err
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"organization ID is required",
		)
	}

	normalizeListHoneytokensRequest(&req)

	if err := validateListHoneytokensRequest(req); err != nil {
		return nil, err
	}

	departmentID, err := parseOptionalHoneytokenUUID(
		req.DepartmentID,
		"department ID",
	)
	if err != nil {
		return nil, err
	}

	tokens, total, err := s.repository.ListHoneytokens(
		ctx,
		organizationID,
		HoneytokenListFilter{
			Page:           req.Page,
			Limit:          req.Limit,
			Search:         req.Search,
			HoneytokenType: req.HoneytokenType,
			Classification: req.Classification,
			Status:         req.Status,
			DepartmentID:   departmentID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to list honeytokens: %w",
			err,
		)
	}

	items := make(
		[]GetHoneytokenResponse,
		0,
		len(tokens),
	)

	for _, token := range tokens {
		if token == nil {
			continue
		}

		responseItem := buildGetHoneytokenResponse(
			token,
		)
		if responseItem == nil {
			continue
		}

		items = append(
			items,
			*responseItem,
		)
	}

	totalPages := 0

	if total > 0 {
		totalPages = (total +
			req.Limit -
			1) /
			req.Limit
	}

	return &ListHoneytokensResponse{
		Honeytokens: items,
		Total:       total,
		Page:        req.Page,
		Limit:       req.Limit,
		TotalPages:  totalPages,
	}, nil
}

func (s *HoneytokenService) validate() error {
	if s == nil ||
		s.repository == nil ||
		s.generator == nil {
		return ErrHoneytokenServiceUnavailable
	}

	return nil
}

func validateHoneytokenServiceContext(
	ctx context.Context,
) error {
	if ctx == nil {
		return fmt.Errorf(
			"context is required",
		)
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"request context is not active: %w",
			err,
		)
	}

	return nil
}

func normalizeCreateHoneytokenRequest(
	req *CreateHoneytokenRequest,
) {
	if req == nil {
		return
	}

	req.DepartmentID = strings.TrimSpace(
		req.DepartmentID,
	)
	req.PolicyID = strings.TrimSpace(
		req.PolicyID,
	)
	req.OwnerUserID = strings.TrimSpace(
		req.OwnerUserID,
	)

	req.HoneytokenName = strings.TrimSpace(
		req.HoneytokenName,
	)
	req.HoneytokenType = strings.ToUpper(
		strings.TrimSpace(req.HoneytokenType),
	)

	req.Description = strings.TrimSpace(
		req.Description,
	)
	req.DecoyUsername = strings.TrimSpace(
		req.DecoyUsername,
	)
	req.DecoyEmail = strings.ToLower(
		strings.TrimSpace(req.DecoyEmail),
	)
	req.TargetSystem = strings.TrimSpace(
		req.TargetSystem,
	)

	req.Classification = strings.ToUpper(
		strings.TrimSpace(req.Classification),
	)
	req.ExpiresAt = strings.TrimSpace(
		req.ExpiresAt,
	)
}

func validateCreateHoneytokenRequest(
	req *CreateHoneytokenRequest,
) error {
	if req == nil {
		return fmt.Errorf(
			"create honeytoken request is required",
		)
	}

	if len(req.HoneytokenName) < 3 {
		return fmt.Errorf(
			"honeytoken name must contain at least 3 characters",
		)
	}

	if len(req.HoneytokenName) > 100 {
		return fmt.Errorf(
			"honeytoken name must not exceed 100 characters",
		)
	}

	if !isSupportedHoneytokenType(
		req.HoneytokenType,
	) {
		return fmt.Errorf(
			"unsupported honeytoken type: %s",
			req.HoneytokenType,
		)
	}

	if len(req.Description) > 1000 {
		return fmt.Errorf(
			"honeytoken description must not exceed 1000 characters",
		)
	}

	if len(req.DecoyUsername) > 100 {
		return fmt.Errorf(
			"decoy username must not exceed 100 characters",
		)
	}

	if req.DecoyEmail != "" {
		parsedAddress, err := mail.ParseAddress(
			req.DecoyEmail,
		)
		if err != nil ||
			!strings.EqualFold(
				parsedAddress.Address,
				req.DecoyEmail,
			) {
			return fmt.Errorf(
				"decoy email address is invalid",
			)
		}
	}

	if len(req.TargetSystem) > 100 {
		return fmt.Errorf(
			"target system must not exceed 100 characters",
		)
	}

	if !isSupportedHoneytokenClassification(
		req.Classification,
	) {
		return fmt.Errorf(
			"unsupported honeytoken classification: %s",
			req.Classification,
		)
	}

	return nil
}

func normalizeListHoneytokensRequest(
	req *ListHoneytokensRequest,
) {
	if req.Page < 1 {
		req.Page = 1
	}

	if req.Limit < 1 {
		req.Limit = 20
	}

	if req.Limit > 100 {
		req.Limit = 100
	}

	req.Search = strings.TrimSpace(
		req.Search,
	)
	req.HoneytokenType = strings.ToUpper(
		strings.TrimSpace(req.HoneytokenType),
	)
	req.Classification = strings.ToUpper(
		strings.TrimSpace(req.Classification),
	)
	req.Status = strings.ToUpper(
		strings.TrimSpace(req.Status),
	)
	req.DepartmentID = strings.TrimSpace(
		req.DepartmentID,
	)
}

func validateListHoneytokensRequest(
	req ListHoneytokensRequest,
) error {
	if req.HoneytokenType != "" &&
		!isSupportedHoneytokenType(req.HoneytokenType) {
		return fmt.Errorf(
			"unsupported honeytoken type filter: %s",
			req.HoneytokenType,
		)
	}

	if req.Classification != "" &&
		!isSupportedHoneytokenClassification(
			req.Classification,
		) {
		return fmt.Errorf(
			"unsupported classification filter: %s",
			req.Classification,
		)
	}

	if req.Status != "" &&
		!isSupportedHoneytokenStatus(req.Status) {
		return fmt.Errorf(
			"unsupported honeytoken status filter: %s",
			req.Status,
		)
	}

	return nil
}

func parseOptionalHoneytokenUUID(
	value string,
	fieldName string,
) (*uuid.UUID, error) {
	value = strings.TrimSpace(value)

	if value == "" {
		return nil, nil
	}

	parsedValue, err := uuid.Parse(value)
	if err != nil || parsedValue == uuid.Nil {
		return nil, fmt.Errorf(
			"invalid %s",
			fieldName,
		)
	}

	return &parsedValue, nil
}

func parseHoneytokenExpiration(
	value string,
) (*time.Time, error) {
	value = strings.TrimSpace(value)

	if value == "" {
		return nil, nil
	}

	expiresAt, err := time.Parse(
		time.RFC3339,
		value,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"expires_at must use RFC3339 format: %w",
			err,
		)
	}

	expiresAt = expiresAt.UTC()

	if !expiresAt.After(time.Now().UTC()) {
		return nil, fmt.Errorf(
			"honeytoken expiration must be in the future",
		)
	}

	return &expiresAt, nil
}

func isSupportedHoneytokenClassification(
	classification string,
) bool {
	switch strings.ToUpper(
		strings.TrimSpace(classification),
	) {
	case SensitivityPublic,
		SensitivityInternal,
		SensitivityConfidential,
		SensitivityRestricted,
		SensitivityCritical:
		return true

	default:
		return false
	}
}

func isSupportedHoneytokenStatus(
	status string,
) bool {
	switch strings.ToUpper(
		strings.TrimSpace(status),
	) {
	case HoneytokenStatusDraft,
		HoneytokenStatusActive,
		HoneytokenStatusTriggered,
		HoneytokenStatusInactive,
		HoneytokenStatusExpired,
		HoneytokenStatusRevoked,
		HoneytokenStatusArchived:
		return true

	default:
		return false
	}
}

func buildHoneytokenCode(
	honeytokenID uuid.UUID,
) string {
	return "HT-" + strings.ToUpper(
		honeytokenID.String(),
	)
}

func optionalHoneytokenString(
	value string,
) *string {
	value = strings.TrimSpace(value)

	if value == "" {
		return nil
	}

	return &value
}

func buildCreateHoneytokenResponse(
	token *Honeytoken,
	generatedValue string,
) *CreateHoneytokenResponse {
	response := &CreateHoneytokenResponse{
		ID: token.ID.String(),

		HoneytokenCode: token.HoneytokenCode,
		HoneytokenName: token.HoneytokenName,
		HoneytokenType: token.HoneytokenType,

		GeneratedValue: generatedValue,

		Classification: token.Classification,
		Status:         token.Status,

		CreatedAt: token.CreatedAt.
			UTC().
			Format(time.RFC3339),
	}

	if token.ValuePrefix != nil {
		response.ValuePrefix = *token.ValuePrefix
	}

	if token.ExpiresAt != nil {
		response.ExpiresAt = token.ExpiresAt.
			UTC().
			Format(time.RFC3339)
	}

	return response
}

func buildGetHoneytokenResponse(
	token *Honeytoken,
) *GetHoneytokenResponse {
	if token == nil {
		return nil
	}

	response := &GetHoneytokenResponse{
		ID: token.ID.String(),

		OrganizationID: token.OrganizationID.String(),

		HoneytokenCode: token.HoneytokenCode,
		HoneytokenName: token.HoneytokenName,
		HoneytokenType: token.HoneytokenType,

		Classification: token.Classification,
		AccessCount:    token.AccessCount,

		DeploymentConfigured: token.DeploymentLocation != nil &&
			strings.TrimSpace(
				*token.DeploymentLocation,
			) != "",

		Status: token.Status,

		CreatedAt: token.CreatedAt.
			UTC().
			Format(time.RFC3339),

		UpdatedAt: token.UpdatedAt.
			UTC().
			Format(time.RFC3339),
	}

	if token.DepartmentID != nil {
		response.DepartmentID = token.DepartmentID.String()
	}

	if token.PolicyID != nil {
		response.PolicyID = token.PolicyID.String()
	}

	if token.Description != nil {
		response.Description = *token.Description
	}

	if token.DecoyUsername != nil {
		response.DecoyUsername = *token.DecoyUsername
	}

	if token.DecoyEmail != nil {
		response.DecoyEmail = *token.DecoyEmail
	}

	if token.ValuePrefix != nil {
		response.ValuePrefix = *token.ValuePrefix
	}

	if token.TargetSystem != nil {
		response.TargetSystem = *token.TargetSystem
	}

	if token.OwnerUserID != nil {
		response.OwnerUserID = token.OwnerUserID.String()
	}

	if token.CreatedBy != nil {
		response.CreatedBy = token.CreatedBy.String()
	}

	if token.LastTriggeredAt != nil {
		response.LastTriggeredAt = token.LastTriggeredAt.
			UTC().
			Format(time.RFC3339)
	}

	if token.DeployedAt != nil {
		response.DeployedAt = token.DeployedAt.
			UTC().
			Format(time.RFC3339)
	}

	if token.ExpiresAt != nil {
		response.ExpiresAt = token.ExpiresAt.
			UTC().
			Format(time.RFC3339)
	}

	return response
}

var ErrHoneytokenExpired = errors.New(
	"honeytoken has expired",
)

// DeployHoneytoken registers an authorized deployment location
// and activates a DRAFT or INACTIVE honeytoken.
func (s *HoneytokenService) DeployHoneytoken(
	ctx context.Context,
	organizationID uuid.UUID,
	honeytokenID uuid.UUID,
	req *DeployHoneytokenRequest,
) (*DeployHoneytokenResponse, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	if err := validateHoneytokenServiceContext(ctx); err != nil {
		return nil, err
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"organization ID is required",
		)
	}

	if honeytokenID == uuid.Nil {
		return nil, fmt.Errorf(
			"honeytoken ID is required",
		)
	}

	if err := validateDeployHoneytokenRequest(req); err != nil {
		return nil, err
	}

	token, err := s.repository.FindHoneytokenByID(
		ctx,
		organizationID,
		honeytokenID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to find honeytoken for deployment: %w",
			err,
		)
	}

	if token == nil {
		return nil, ErrHoneytokenNotFound
	}

	if isHoneytokenExpired(token) {
		return nil, ErrHoneytokenExpired
	}

	status := strings.ToUpper(
		strings.TrimSpace(token.Status),
	)

	if status != HoneytokenStatusDraft &&
		status != HoneytokenStatusInactive {
		return nil, ErrHoneytokenNotDeployable
	}

	if token.DecoyValueEncrypted == nil ||
		strings.TrimSpace(*token.DecoyValueEncrypted) == "" {
		return nil, fmt.Errorf(
			"honeytoken encrypted value is missing",
		)
	}

	if token.DecoyValueHash == nil ||
		strings.TrimSpace(*token.DecoyValueHash) == "" {
		return nil, fmt.Errorf(
			"honeytoken validation hash is missing",
		)
	}

	deployedToken, err := s.repository.DeployHoneytoken(
		ctx,
		organizationID,
		honeytokenID,
		req.DeploymentLocation,
		req.TargetSystem,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to deploy honeytoken: %w",
			err,
		)
	}

	if deployedToken == nil {
		return nil, fmt.Errorf(
			"honeytoken deployment returned an empty result",
		)
	}

	return buildDeployHoneytokenResponse(
		deployedToken,
	), nil
}

// ValidateHoneytoken checks an observed value and records a trigger
// only when the value matches an ACTIVE or already TRIGGERED token.
func (s *HoneytokenService) ValidateHoneytoken(
	ctx context.Context,
	organizationID uuid.UUID,
	honeytokenID uuid.UUID,
	req *ValidateHoneytokenRequest,
) (*ValidateHoneytokenResponse, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	if err := validateHoneytokenServiceContext(ctx); err != nil {
		return nil, err
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"organization ID is required",
		)
	}

	if honeytokenID == uuid.Nil {
		return nil, fmt.Errorf(
			"honeytoken ID is required",
		)
	}

	if err := validateHoneytokenValidationRequest(
		req,
	); err != nil {
		return nil, err
	}

	token, err := s.repository.FindHoneytokenByID(
		ctx,
		organizationID,
		honeytokenID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to find honeytoken for validation: %w",
			err,
		)
	}

	if token == nil {
		return nil, ErrHoneytokenNotFound
	}

	if isHoneytokenExpired(token) {
		return nil, ErrHoneytokenExpired
	}

	status := strings.ToUpper(
		strings.TrimSpace(token.Status),
	)

	if status != HoneytokenStatusActive &&
		status != HoneytokenStatusTriggered {
		return nil, ErrHoneytokenNotActive
	}

	valid, err := s.generator.ValidateValue(
		ctx,
		token,
		req.ObservedValue,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to validate honeytoken value: %w",
			err,
		)
	}

	if !valid {
		return buildValidateHoneytokenResponse(
			token,
			false,
			false,
		), nil
	}

	triggeredToken, err := s.repository.RecordHoneytokenTrigger(
		ctx,
		organizationID,
		honeytokenID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to record honeytoken trigger: %w",
			err,
		)
	}

	if triggeredToken == nil {
		return nil, fmt.Errorf(
			"honeytoken trigger returned an empty result",
		)
	}

	return buildValidateHoneytokenResponse(
		triggeredToken,
		true,
		true,
	), nil
}

func validateDeployHoneytokenRequest(
	req *DeployHoneytokenRequest,
) error {
	if req == nil {
		return fmt.Errorf(
			"deploy honeytoken request is required",
		)
	}

	req.DeploymentLocation = strings.TrimSpace(
		req.DeploymentLocation,
	)
	req.TargetSystem = strings.TrimSpace(
		req.TargetSystem,
	)

	if req.DeploymentLocation == "" {
		return fmt.Errorf(
			"deployment location is required",
		)
	}

	if len(req.DeploymentLocation) > 4096 {
		return fmt.Errorf(
			"deployment location must not exceed 4096 characters",
		)
	}

	if len(req.TargetSystem) > 100 {
		return fmt.Errorf(
			"target system must not exceed 100 characters",
		)
	}

	return nil
}

func validateHoneytokenValidationRequest(
	req *ValidateHoneytokenRequest,
) error {
	if req == nil {
		return fmt.Errorf(
			"validate honeytoken request is required",
		)
	}

	if strings.TrimSpace(req.ObservedValue) == "" {
		return fmt.Errorf(
			"observed honeytoken value is required",
		)
	}

	if len(req.ObservedValue) > 8192 {
		return fmt.Errorf(
			"observed honeytoken value must not exceed 8192 characters",
		)
	}

	return nil
}

func isHoneytokenExpired(
	token *Honeytoken,
) bool {
	if token == nil || token.ExpiresAt == nil {
		return false
	}

	return !token.ExpiresAt.After(
		time.Now().UTC(),
	)
}

func buildDeployHoneytokenResponse(
	token *Honeytoken,
) *DeployHoneytokenResponse {
	response := &DeployHoneytokenResponse{
		ID: token.ID.String(),

		HoneytokenCode: token.HoneytokenCode,
		HoneytokenName: token.HoneytokenName,

		DeploymentConfigured: token.DeploymentLocation != nil &&
			strings.TrimSpace(
				*token.DeploymentLocation,
			) != "",

		Status: token.Status,
	}

	if token.TargetSystem != nil {
		response.TargetSystem = *token.TargetSystem
	}

	if token.DeployedAt != nil {
		response.DeployedAt = token.DeployedAt.
			UTC().
			Format(time.RFC3339)
	}

	return response
}

func buildValidateHoneytokenResponse(
	token *Honeytoken,
	valid bool,
	triggered bool,
) *ValidateHoneytokenResponse {
	if token == nil {
		return nil
	}

	response := &ValidateHoneytokenResponse{
		ID: token.ID.String(),

		HoneytokenCode: token.HoneytokenCode,

		Valid:     valid,
		Triggered: triggered,

		Status:      token.Status,
		AccessCount: token.AccessCount,
	}

	if token.LastTriggeredAt != nil {
		response.TriggeredAt = token.LastTriggeredAt.
			UTC().
			Format(time.RFC3339)
	}

	return response
}
