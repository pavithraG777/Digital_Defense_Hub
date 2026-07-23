package honeytoken

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

const protectedFileStorageDirectory = "./storage/protected-files"

type Service struct {
	repository     *Repository
	encryptionKeys *EncryptionKeyService
}

// NewProtectedFileService creates a protected-file service backed by
// organization-specific encryption keys.
func NewProtectedFileService(
	repository *Repository,
	encryptionKeys *EncryptionKeyService,
) *Service {
	return &Service{
		repository:     repository,
		encryptionKeys: encryptionKeys,
	}
}

// RegisterProtectedFile protects the original file and registers
// the generated package and metadata details in PostgreSQL.
func (s *Service) RegisterProtectedFile(
	ctx context.Context,
	req *RegisterProtectedFileRequest,
) (*RegisterProtectedFileResponse, error) {
	if err := s.validateDependencies(); err != nil {
		return nil, err
	}

	if err := validateServiceContext(ctx); err != nil {
		return nil, err
	}

	if err := validateRegisterProtectedFileRequest(req); err != nil {
		return nil, err
	}

	organizationID, err := uuid.Parse(
		strings.TrimSpace(req.OrganizationID),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid organization ID: %w",
			err,
		)
	}

	ownerUserID, err := uuid.Parse(
		strings.TrimSpace(req.OwnerUserID),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid owner user ID: %w",
			err,
		)
	}

	departmentID, err := parseOptionalDepartmentID(
		req.DepartmentID,
	)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	file := &ProtectedFile{
		ID:             uuid.New(),
		OrganizationID: organizationID,
		DepartmentID:   departmentID,
		OwnerUserID:    ownerUserID,

		OriginalFilePath: strings.TrimSpace(
			req.OriginalFilePath,
		),

		Category: strings.ToUpper(
			strings.TrimSpace(req.Category),
		),
		Sensitivity: strings.ToUpper(
			strings.TrimSpace(req.Sensitivity),
		),
		Classification: strings.TrimSpace(
			req.Classification,
		),
		RetentionPolicy: strings.TrimSpace(
			req.RetentionPolicy,
		),

		MonitoringEnabled: req.EnableMonitoring,
		HoneytokenEnabled: req.EnableHoneytoken,
		CanaryEnabled:     req.EnableCanary,

		Status:    FileStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}

	resolvedKey, err := s.encryptionKeys.resolveActiveFileEncryptionKey(
		ctx,
		file.OrganizationID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to resolve active encryption key: %w",
			err,
		)
	}

	if resolvedKey == nil {
		return nil, fmt.Errorf(
			"active encryption key resolution returned an empty result",
		)
	}
	defer resolvedKey.destroy()

	fileProtection, err := NewFileProtectionService(
		resolvedKey.keyMaterial,
		resolvedKey.id.String(),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to initialize organization file protection: %w",
			err,
		)
	}

	result, err := fileProtection.ProtectFile(
		ctx,
		FileProtectionInput{
			ProtectedFileID: file.ID,
			OrganizationID:  file.OrganizationID,
			DepartmentID:    file.DepartmentID,
			OwnerUserID:     file.OwnerUserID,

			SourceFilePath:  file.OriginalFilePath,
			OutputDirectory: protectedFileStorageDirectory,

			Category:        file.Category,
			Sensitivity:     file.Sensitivity,
			Classification:  file.Classification,
			RetentionPolicy: file.RetentionPolicy,
			RetentionUntil:  file.RetentionUntil,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to protect file: %w",
			err,
		)
	}

	if result == nil {
		return nil, fmt.Errorf(
			"file protection returned an empty result",
		)
	}

	applyFileProtectionResult(
		file,
		result,
	)

	if err := s.repository.CreateProtectedFile(
		ctx,
		file,
	); err != nil {
		registrationError := fmt.Errorf(
			"failed to register protected file: %w",
			err,
		)

		cleanupError := cleanupProtectedFileArtifacts(
			result,
		)
		if cleanupError != nil {
			return nil, errors.Join(
				registrationError,
				cleanupError,
			)
		}

		return nil, registrationError
	}

	return buildRegisterProtectedFileResponse(file), nil
}

// GetProtectedFile returns one non-deleted protected file.
func (s *Service) GetProtectedFile(
	ctx context.Context,
	id uuid.UUID,
) (*ProtectedFile, error) {
	if err := s.validateDependencies(); err != nil {
		return nil, err
	}

	if err := validateServiceContext(ctx); err != nil {
		return nil, err
	}

	if id == uuid.Nil {
		return nil, fmt.Errorf(
			"protected file ID is required",
		)
	}

	file, err := s.repository.FindProtectedFileByID(
		ctx,
		id,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get protected file: %w",
			err,
		)
	}

	return file, nil
}

func (s *Service) validateDependencies() error {
	if s == nil {
		return fmt.Errorf("protected file service is required")
	}

	if s.repository == nil {
		return fmt.Errorf("protected file repository is required")
	}

	if s.encryptionKeys == nil {
		return fmt.Errorf(
			"encryption key service is required",
		)
	}

	return nil
}

func validateServiceContext(
	ctx context.Context,
) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"request context is not active: %w",
			err,
		)
	}

	return nil
}

func validateRegisterProtectedFileRequest(
	req *RegisterProtectedFileRequest,
) error {
	if req == nil {
		return fmt.Errorf("request is required")
	}

	if strings.TrimSpace(req.OrganizationID) == "" {
		return fmt.Errorf("organization ID is required")
	}

	if strings.TrimSpace(req.OwnerUserID) == "" {
		return fmt.Errorf("owner user ID is required")
	}

	if strings.TrimSpace(req.OriginalFilePath) == "" {
		return fmt.Errorf("original file path is required")
	}

	category := strings.ToUpper(
		strings.TrimSpace(req.Category),
	)

	if category == "" {
		return fmt.Errorf("file category is required")
	}

	if !isSupportedFileCategory(category) {
		return fmt.Errorf(
			"unsupported file category: %s",
			category,
		)
	}

	sensitivity := strings.ToUpper(
		strings.TrimSpace(req.Sensitivity),
	)

	if sensitivity == "" {
		return fmt.Errorf("file sensitivity is required")
	}

	if !isSupportedFileSensitivity(sensitivity) {
		return fmt.Errorf(
			"unsupported file sensitivity: %s",
			sensitivity,
		)
	}

	if strings.TrimSpace(req.Classification) == "" {
		return fmt.Errorf("file classification is required")
	}

	return nil
}

func parseOptionalDepartmentID(
	value string,
) (*uuid.UUID, error) {
	value = strings.TrimSpace(value)

	if value == "" {
		return nil, nil
	}

	departmentID, err := uuid.Parse(value)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid department ID: %w",
			err,
		)
	}

	return &departmentID, nil
}

func isSupportedFileCategory(
	category string,
) bool {
	switch category {
	case FileCategoryCredentials,
		FileCategoryFinancial,
		FileCategoryEmployee,
		FileCategoryCustomer,
		FileCategoryMedical,
		FileCategoryLegal,
		FileCategorySourceCode,
		FileCategoryContract,
		FileCategoryEvidence,
		FileCategoryOther:
		return true
	default:
		return false
	}
}

func isSupportedFileSensitivity(
	sensitivity string,
) bool {
	switch sensitivity {
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

func applyFileProtectionResult(
	file *ProtectedFile,
	result *FileProtectionResult,
) {
	file.OriginalFileName = result.OriginalFileName
	file.OriginalExtension = result.OriginalExtension
	file.OriginalFilePath = result.OriginalFilePath

	file.ProtectedFileName = result.ProtectedFileName
	file.ProtectedFilePath = result.ProtectedFilePath

	file.MetadataFileName = result.MetadataFileName
	file.MetadataFilePath = result.MetadataFilePath

	file.FileSizeBytes = result.FileSizeBytes
	file.MimeType = result.MimeType
	file.SHA256Hash = result.SHA256Hash

	file.EncryptionAlgorithm = result.EncryptionAlgorithm
	file.EncryptionKeyID = result.EncryptionKeyID

	file.ProtectedAt = &result.ProtectedAt
	file.Status = FileStatusProtected
	file.UpdatedAt = time.Now().UTC()
}

func cleanupProtectedFileArtifacts(
	result *FileProtectionResult,
) error {
	if result == nil {
		return nil
	}

	var cleanupErrors []error

	if err := removeProtectedFileArtifact(
		result.ProtectedFilePath,
		"protected package",
	); err != nil {
		cleanupErrors = append(
			cleanupErrors,
			err,
		)
	}

	if err := removeProtectedFileArtifact(
		result.MetadataFilePath,
		"metadata file",
	); err != nil {
		cleanupErrors = append(
			cleanupErrors,
			err,
		)
	}

	if len(cleanupErrors) == 0 {
		return nil
	}

	return fmt.Errorf(
		"failed to clean generated protected-file artifacts: %w",
		errors.Join(cleanupErrors...),
	)
}

func removeProtectedFileArtifact(
	path string,
	artifactName string,
) error {
	path = strings.TrimSpace(path)

	if path == "" {
		return nil
	}

	if err := os.Remove(path); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf(
			"failed to remove %s: %w",
			artifactName,
			err,
		)
	}

	return nil
}

func buildRegisterProtectedFileResponse(
	file *ProtectedFile,
) *RegisterProtectedFileResponse {
	return &RegisterProtectedFileResponse{
		ProtectedFileID:   file.ID.String(),
		OriginalFileName:  file.OriginalFileName,
		ProtectedFileName: file.ProtectedFileName,
		Status:            file.Status,
		MonitoringEnabled: file.MonitoringEnabled,
		HoneytokenEnabled: file.HoneytokenEnabled,
		CanaryEnabled:     file.CanaryEnabled,
	}
}

const protectedFileRestoreStorageDirectory = "./storage/restored-files"

var ErrProtectedFileNotRestorable = errors.New(
	"protected file cannot be restored",
)

// RestoreProtectedFile loads trusted file metadata from PostgreSQL,
// validates organization ownership and restores the original file
// inside a server-controlled storage directory.
func (s *Service) RestoreProtectedFile(
	ctx context.Context,
	protectedFileID uuid.UUID,
	organizationID uuid.UUID,
	req *RestoreProtectedFileRequest,
) (*RestoreProtectedFileResponse, error) {
	if err := s.validateDependencies(); err != nil {
		return nil, err
	}

	if err := validateServiceContext(ctx); err != nil {
		return nil, err
	}

	if protectedFileID == uuid.Nil {
		return nil, fmt.Errorf(
			"protected file ID is required",
		)
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"organization ID is required",
		)
	}

	if err := validateRestoreProtectedFileRequest(req); err != nil {
		return nil, err
	}

	file, err := s.repository.FindProtectedFileByID(
		ctx,
		protectedFileID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to find protected file for restoration: %w",
			err,
		)
	}

	if file == nil {
		return nil, ErrProtectedFileNotFound
	}

	// Return Not Found instead of exposing another organization's record.
	if file.OrganizationID != organizationID {
		return nil, ErrProtectedFileNotFound
	}

	if file.Status != FileStatusProtected {
		return nil, fmt.Errorf(
			"%w: current status is %s",
			ErrProtectedFileNotRestorable,
			file.Status,
		)
	}

	if !strings.EqualFold(
		file.EncryptionAlgorithm,
		EncryptionAlgorithmAES256,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported encryption algorithm",
			ErrProtectedFileNotRestorable,
		)
	}

	if strings.TrimSpace(file.ProtectedFilePath) == "" {
		return nil, fmt.Errorf(
			"%w: protected package path is missing",
			ErrProtectedFileNotRestorable,
		)
	}

	if strings.TrimSpace(file.OriginalFileName) == "" {
		return nil, fmt.Errorf(
			"%w: original file name is missing",
			ErrProtectedFileNotRestorable,
		)
	}

	if strings.TrimSpace(file.SHA256Hash) == "" {
		return nil, fmt.Errorf(
			"%w: SHA-256 hash is missing",
			ErrProtectedFileNotRestorable,
		)
	}

	if strings.TrimSpace(file.EncryptionKeyID) == "" {
		return nil, fmt.Errorf(
			"%w: encryption key ID is missing",
			ErrProtectedFileNotRestorable,
		)
	}

	encryptionKeyID, err := uuid.Parse(
		strings.TrimSpace(file.EncryptionKeyID),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: encryption key ID is invalid",
			ErrProtectedFileNotRestorable,
		)
	}

	resolvedKey, err := s.encryptionKeys.resolveFileEncryptionKeyByID(
		ctx,
		organizationID,
		encryptionKeyID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to resolve protected file encryption key: %w",
			err,
		)
	}

	if resolvedKey == nil {
		return nil, fmt.Errorf(
			"file encryption key resolution returned an empty result",
		)
	}
	defer resolvedKey.destroy()

	fileDecryption, err := NewFileDecryptionService(
		resolvedKey.keyMaterial,
		resolvedKey.id.String(),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to initialize file decryption service: %w",
			err,
		)
	}
	defer clear(fileDecryption.encryptionKey)

	outputDirectory := protectedFileRestoreStorageDirectory +
		string(os.PathSeparator) +
		organizationID.String() +
		string(os.PathSeparator) +
		protectedFileID.String()

	result, err := fileDecryption.DecryptFile(
		ctx,
		FileDecryptionInput{
			ProtectedFilePath: file.ProtectedFilePath,
			OutputDirectory:   outputDirectory,
			OriginalFileName:  file.OriginalFileName,

			ExpectedSHA256Hash: file.SHA256Hash,
			EncryptionKeyID:    file.EncryptionKeyID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to restore protected file: %w",
			err,
		)
	}

	if result == nil {
		return nil, fmt.Errorf(
			"file decryption returned an empty result",
		)
	}

	return buildRestoreProtectedFileResponse(
		file,
		result,
	), nil
}

func validateRestoreProtectedFileRequest(
	req *RestoreProtectedFileRequest,
) error {
	if req == nil {
		return fmt.Errorf(
			"restore request is required",
		)
	}

	restoreReason := strings.TrimSpace(
		req.RestoreReason,
	)

	if restoreReason == "" {
		return fmt.Errorf(
			"restore reason is required",
		)
	}

	if len(restoreReason) < 3 {
		return fmt.Errorf(
			"restore reason must contain at least 3 characters",
		)
	}

	if len(restoreReason) > 500 {
		return fmt.Errorf(
			"restore reason must not exceed 500 characters",
		)
	}

	req.RestoreReason = restoreReason

	return nil
}

func buildRestoreProtectedFileResponse(
	file *ProtectedFile,
	result *FileDecryptionResult,
) *RestoreProtectedFileResponse {
	return &RestoreProtectedFileResponse{
		ProtectedFileID: file.ID.String(),

		RestoredFileName: result.RestoredFileName,
		FileSizeBytes:    result.FileSizeBytes,

		IntegrityVerified: true,
		RestoredAt: result.RestoredAt.Format(
			time.RFC3339,
		),
	}
}
