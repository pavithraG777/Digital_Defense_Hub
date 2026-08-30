package honeytoken

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrCanaryHoneytokenRequired          = errors.New("honeytoken ID is required")
	ErrCanaryUnexpectedHoneytoken        = errors.New("honeytoken ID requires contains_honeytoken to be true")
	ErrCanaryLinkedHoneytokenUnavailable = errors.New("linked honeytoken is unavailable")
	ErrCanaryFileExpired                 = errors.New("canary file has expired")
	ErrCanaryDeploymentOutsideRoot       = errors.New("canary deployment is outside configured root")
	ErrCanaryDeploymentFileExists        = errors.New("canary deployment file already exists")
	ErrCanaryIntegrityVerificationFailed = errors.New("canary file integrity verification failed")
)

type CanaryService struct {
	repository     *Repository
	generator      *CanaryGenerator
	deploymentRoot string
}

func NewCanaryService(
	repository *Repository,
	generator *CanaryGenerator,
	deploymentRoot string,
) (*CanaryService, error) {
	if repository == nil {
		return nil, errors.New("canary repository is required")
	}

	if generator == nil {
		return nil, errors.New("canary generator is required")
	}

	deploymentRoot = strings.TrimSpace(deploymentRoot)
	if deploymentRoot == "" {
		return nil, errors.New("canary deployment root is required")
	}

	absoluteRoot, err := filepath.Abs(deploymentRoot)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to resolve canary deployment root: %w",
			err,
		)
	}

	absoluteRoot = filepath.Clean(absoluteRoot)

	if err = os.MkdirAll(absoluteRoot, 0750); err != nil {
		return nil, fmt.Errorf(
			"failed to create canary deployment root: %w",
			err,
		)
	}

	resolvedRoot, err := filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to validate canary deployment root: %w",
			err,
		)
	}

	return &CanaryService{
		repository:     repository,
		generator:      generator,
		deploymentRoot: filepath.Clean(resolvedRoot),
	}, nil
}

func (s *CanaryService) CreateCanaryFile(
	ctx context.Context,
	organizationID uuid.UUID,
	createdBy uuid.UUID,
	request CreateCanaryFileRequest,
) (*CreateCanaryFileResponse, error) {
	return s.createCanaryFile(
		ctx,
		organizationID,
		createdBy,
		request,
		s.generator.Generate,
		"generate",
	)
}

// ImportCanaryFile validates and stages a byte-for-byte copy of an uploaded
// file. It deliberately does not mutate or embed identifiers into the source
// content; monitoring starts only after the resulting DRAFT is deployed.
func (s *CanaryService) ImportCanaryFile(
	ctx context.Context,
	organizationID uuid.UUID,
	createdBy uuid.UUID,
	request ImportCanaryFileRequest,
	originalFileName string,
	source io.Reader,
) (*CreateCanaryFileResponse, error) {
	if source == nil {
		return nil, ErrCanaryImportEmpty
	}

	request.CanaryType = strings.ToUpper(
		strings.TrimSpace(request.CanaryType),
	)
	if request.CanaryType == "" {
		inferredType, err := inferImportedCanaryType(originalFileName)
		if err != nil {
			return nil, err
		}

		request.CanaryType = inferredType
	}

	createRequest := CreateCanaryFileRequest{
		DepartmentID: request.DepartmentID,
		PolicyID:     request.PolicyID,
		OwnerUserID:  request.OwnerUserID,
		FileName:     originalFileName,
		CanaryType:   request.CanaryType,
		Description:  request.Description,
		ExpiresAt:    request.ExpiresAt,
	}

	return s.createCanaryFile(
		ctx,
		organizationID,
		createdBy,
		createRequest,
		func(
			materializeContext context.Context,
			input canaryGenerationInput,
		) (*canaryGenerationResult, error) {
			return s.generator.Import(
				materializeContext,
				input,
				source,
			)
		},
		"import",
	)
}

type canaryFileMaterializer func(
	context.Context,
	canaryGenerationInput,
) (*canaryGenerationResult, error)

func (s *CanaryService) createCanaryFile(
	ctx context.Context,
	organizationID uuid.UUID,
	createdBy uuid.UUID,
	request CreateCanaryFileRequest,
	materialize canaryFileMaterializer,
	materializationAction string,
) (*CreateCanaryFileResponse, error) {
	if organizationID == uuid.Nil {
		return nil, errors.New("organization ID is required")
	}

	if createdBy == uuid.Nil {
		return nil, errors.New("creator user ID is required")
	}

	request.FileName = strings.TrimSpace(request.FileName)
	request.CanaryType = strings.ToUpper(
		strings.TrimSpace(request.CanaryType),
	)
	request.Description = normalizeCanaryOptionalString(
		request.Description,
	)

	if request.FileName == "" {
		return nil, ErrInvalidCanaryFileName
	}

	if !isSupportedCanaryType(request.CanaryType) {
		return nil, ErrUnsupportedCanaryType
	}

	departmentID, err := parseCanaryOptionalUUID(
		request.DepartmentID,
		"department ID",
	)
	if err != nil {
		return nil, err
	}

	policyID, err := parseCanaryOptionalUUID(
		request.PolicyID,
		"policy ID",
	)
	if err != nil {
		return nil, err
	}

	ownerUserID, err := parseCanaryOptionalUUID(
		request.OwnerUserID,
		"owner user ID",
	)
	if err != nil {
		return nil, err
	}

	honeytokenID, err := parseCanaryOptionalUUID(
		request.HoneytokenID,
		"honeytoken ID",
	)
	if err != nil {
		return nil, err
	}

	switch {
	case request.ContainsHoneytoken && honeytokenID == nil:
		return nil, ErrCanaryHoneytokenRequired

	case !request.ContainsHoneytoken && honeytokenID != nil:
		return nil, ErrCanaryUnexpectedHoneytoken
	}

	expiresAt, err := parseCanaryExpiration(request.ExpiresAt)
	if err != nil {
		return nil, err
	}

	creatorID := createdBy

	if err = s.repository.ValidateCanaryFileRelations(
		ctx,
		organizationID,
		departmentID,
		policyID,
		honeytokenID,
		ownerUserID,
		&creatorID,
	); err != nil {
		return nil, err
	}

	var linkedHoneytokenCode *string

	if honeytokenID != nil {
		linkedHoneytoken, findErr :=
			s.repository.FindHoneytokenByID(
				ctx,
				organizationID,
				*honeytokenID,
			)
		if findErr != nil {
			if errors.Is(findErr, ErrHoneytokenNotFound) {
				return nil, ErrCanaryHoneytokenNotFound
			}

			return nil, fmt.Errorf(
				"failed to load linked honeytoken: %w",
				findErr,
			)
		}

		if !isCanaryLinkedHoneytokenUsable(linkedHoneytoken) {
			return nil, ErrCanaryLinkedHoneytokenUnavailable
		}

		honeytokenCode := linkedHoneytoken.HoneytokenCode
		linkedHoneytokenCode = &honeytokenCode
	}

	canaryID := uuid.New()

	generatedFile, err := materialize(
		ctx,
		canaryGenerationInput{
			ID:                   canaryID,
			OrganizationID:       organizationID,
			FileName:             request.FileName,
			CanaryType:           request.CanaryType,
			LinkedHoneytokenCode: linkedHoneytokenCode,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to %s canary file: %w",
			materializationAction,
			err,
		)
	}

	fileExtension := generatedFile.FileExtension
	mimeType := generatedFile.MimeType
	fileSize := generatedFile.FileSizeBytes

	canary := &CanaryFile{
		ID:                       canaryID,
		OrganizationID:           organizationID,
		DepartmentID:             departmentID,
		PolicyID:                 policyID,
		CanaryCode:               generatedFile.CanaryCode,
		FileName:                 generatedFile.FileName,
		FilePath:                 generatedFile.FilePath,
		FileExtension:            &fileExtension,
		MimeType:                 &mimeType,
		CanaryType:               request.CanaryType,
		Description:              request.Description,
		OriginalFileHash:         generatedFile.OriginalFileHash,
		HashAlgorithm:            generatedFile.HashAlgorithm,
		FileSizeBytes:            &fileSize,
		TrackingIdentifier:       generatedFile.TrackingIdentifier,
		ContainsHoneytoken:       request.ContainsHoneytoken,
		HoneytokenID:             honeytokenID,
		DeployedDeviceName:       nil,
		DeployedDeviceIdentifier: nil,
		OwnerUserID:              ownerUserID,
		CreatedBy:                &creatorID,
		AccessCount:              0,
		LastTriggeredAt:          nil,
		DeployedAt:               nil,
		ExpiresAt:                expiresAt,
		Status:                   CanaryStatusDraft,
	}

	if err = s.repository.CreateCanaryFile(ctx, canary); err != nil {
		cleanupErr := s.generator.RemoveGeneratedFile(
			generatedFile.FilePath,
		)
		if cleanupErr != nil {
			return nil, errors.Join(err, cleanupErr)
		}

		return nil, err
	}

	return buildCreateCanaryFileResponse(canary), nil
}

func (s *CanaryService) GetCanaryFile(
	ctx context.Context,
	organizationID uuid.UUID,
	canaryID string,
) (*GetCanaryFileResponse, error) {
	parsedCanaryID, err := parseCanaryRequiredUUID(
		canaryID,
		"canary file ID",
	)
	if err != nil {
		return nil, err
	}

	canary, err := s.repository.FindCanaryFileByID(
		ctx,
		organizationID,
		parsedCanaryID,
	)
	if err != nil {
		return nil, err
	}

	response := buildGetCanaryFileResponse(canary)

	return &response, nil
}

func (s *CanaryService) ListCanaryFiles(
	ctx context.Context,
	organizationID uuid.UUID,
	request ListCanaryFilesRequest,
) (*ListCanaryFilesResponse, error) {
	if organizationID == uuid.Nil {
		return nil, errors.New("organization ID is required")
	}

	departmentID, err := parseCanaryOptionalUUID(
		request.DepartmentID,
		"department ID",
	)
	if err != nil {
		return nil, err
	}

	canaryType := strings.ToUpper(
		strings.TrimSpace(request.CanaryType),
	)
	status := strings.ToUpper(
		strings.TrimSpace(request.Status),
	)

	if canaryType != "" &&
		!isSupportedCanaryType(canaryType) {
		return nil, ErrUnsupportedCanaryType
	}

	if status != "" && !isSupportedCanaryStatus(status) {
		return nil, errors.New("unsupported canary file status")
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

	canaryFiles, total, err :=
		s.repository.ListCanaryFiles(
			ctx,
			CanaryFileListFilter{
				OrganizationID: organizationID,
				DepartmentID:   departmentID,
				CanaryType:     canaryType,
				Status:         status,
				Limit:          pageSize,
				Offset:         (page - 1) * pageSize,
			},
		)
	if err != nil {
		return nil, err
	}

	items := make(
		[]GetCanaryFileResponse,
		0,
		len(canaryFiles),
	)

	for index := range canaryFiles {
		items = append(
			items,
			buildGetCanaryFileResponse(&canaryFiles[index]),
		)
	}

	totalPages := 0
	if total > 0 {
		totalPages = int(
			(total + int64(pageSize) - 1) /
				int64(pageSize),
		)
	}

	return &ListCanaryFilesResponse{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

func (s *CanaryService) DeployCanaryFile(
	ctx context.Context,
	organizationID uuid.UUID,
	canaryID string,
	request DeployCanaryFileRequest,
) (*DeployCanaryFileResponse, error) {
	parsedCanaryID, err := parseCanaryRequiredUUID(
		canaryID,
		"canary file ID",
	)
	if err != nil {
		return nil, err
	}

	canary, err := s.repository.FindCanaryFileByID(
		ctx,
		organizationID,
		parsedCanaryID,
	)
	if err != nil {
		return nil, err
	}

	if canary.ExpiresAt != nil &&
		!canary.ExpiresAt.After(time.Now().UTC()) {
		return nil, ErrCanaryFileExpired
	}

	if !isCanaryDeployableStatus(canary.Status) {
		return nil, ErrCanaryFileNotDeployable
	}

	var destinationPath string
	if request.OriginalFilePath != nil && strings.TrimSpace(*request.OriginalFilePath) != "" {
		destinationPath, err = resolveCanarySiblingDestination(canary.FileName, *request.OriginalFilePath)
	} else {
		var deploymentDirectory string
		deploymentDirectory, err = s.resolveDeploymentDirectory(request.DeploymentDirectory)
		if err == nil {
			destinationPath = filepath.Join(deploymentDirectory, canarySiblingFileName(canary.FileName))
		}
	}
	if err != nil {
		return nil, err
	}

	if err = copyCanaryFileAtomically(
		ctx,
		canary.FilePath,
		destinationPath,
	); err != nil {
		return nil, err
	}

	cleanupDestination := true

	defer func() {
		if cleanupDestination {
			_ = os.Remove(destinationPath)
		}
	}()

	deployedHash, err :=
		calculateCanaryFileSHA256(destinationPath)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(
		[]byte(strings.ToLower(deployedHash)),
		[]byte(strings.ToLower(canary.OriginalFileHash)),
	) != 1 {
		return nil, ErrCanaryIntegrityVerificationFailed
	}

	deviceName := normalizeCanaryOptionalString(
		request.DeviceName,
	)
	deviceIdentifier := normalizeCanaryOptionalString(
		request.DeviceIdentifier,
	)

	// A local Canary deployment should identify the machine without asking the
	// operator to copy a hostname into the UI. Explicit agent-supplied values
	// still take precedence for managed/remote deployments.
	if deviceName == nil {
		if hostname, hostnameErr := os.Hostname(); hostnameErr == nil {
			deviceName = normalizeCanaryOptionalString(&hostname)
		}
	}
	if deviceIdentifier == nil && deviceName != nil {
		identifier := *deviceName
		deviceIdentifier = &identifier
	}

	deployedCanary, err :=
		s.repository.DeployCanaryFile(
			ctx,
			organizationID,
			parsedCanaryID,
			destinationPath,
			deviceName,
			deviceIdentifier,
		)
	if err != nil {
		return nil, err
	}

	cleanupDestination = false

	if canary.FilePath != destinationPath {
		_ = s.generator.RemoveGeneratedFile(
			canary.FilePath,
		)
	}

	return buildDeployCanaryFileResponse(
		deployedCanary,
	), nil
}

// canarySiblingFileName keeps the original extension and uses a single
// leading dot so the monitored decoy is visibly related to its source while
// remaining a distinct, Windows-compatible filename (report.pdf -> .report.pdf).
func canarySiblingFileName(original string) string {
	name := strings.TrimSpace(filepath.Base(original))
	if name == "" || name == "." {
		return ".canary"
	}
	if strings.HasPrefix(name, ".") {
		return name
	}
	return "." + name
}

func resolveCanarySiblingDestination(canaryFileName, originalFilePath string) (string, error) {
	originalFilePath = strings.TrimSpace(originalFilePath)
	if originalFilePath == "" || !filepath.IsAbs(originalFilePath) {
		return "", errors.New("original file path must be an absolute path")
	}
	absoluteOriginal, err := filepath.Abs(filepath.Clean(originalFilePath))
	if err != nil {
		return "", fmt.Errorf("failed to resolve original file path: %w", err)
	}
	info, err := os.Stat(absoluteOriginal)
	if err != nil {
		return "", fmt.Errorf("original file is unavailable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("original file path must identify a regular file")
	}
	if !strings.EqualFold(filepath.Base(absoluteOriginal), filepath.Base(canaryFileName)) {
		return "", errors.New("original file name does not match the Canary source filename")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absoluteOriginal))
	if err != nil {
		return "", fmt.Errorf("failed to validate original file directory: %w", err)
	}
	destination := filepath.Join(parent, canarySiblingFileName(canaryFileName))
	if _, statErr := os.Lstat(destination); statErr == nil {
		return "", ErrCanaryDeploymentFileExists
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("failed to inspect Canary sibling path: %w", statErr)
	}
	return destination, nil
}

// DeactivateCanaryFile disarms a canary while preserving its physical and
// database evidence. It must be explicitly deployed again to be monitored.
func (s *CanaryService) DeactivateCanaryFile(ctx context.Context, organizationID uuid.UUID, canaryID string) (*GetCanaryFileResponse, error) {
	parsedCanaryID, err := parseCanaryRequiredUUID(canaryID, "canary file ID")
	if err != nil {
		return nil, err
	}
	canary, err := s.repository.DeactivateCanaryFile(ctx, organizationID, parsedCanaryID)
	if err != nil {
		return nil, err
	}
	response := buildGetCanaryFileResponse(canary)
	return &response, nil
}

func (s *CanaryService) resolveDeploymentDirectory(
	requestedDirectory string,
) (string, error) {
	requestedDirectory = strings.TrimSpace(
		requestedDirectory,
	)
	if requestedDirectory == "" {
		return "", errors.New(
			"deployment directory is required",
		)
	}

	var candidatePath string

	if filepath.IsAbs(requestedDirectory) {
		candidatePath = filepath.Clean(
			requestedDirectory,
		)
	} else {
		candidatePath = filepath.Join(
			s.deploymentRoot,
			requestedDirectory,
		)
	}

	absolutePath, err := filepath.Abs(candidatePath)
	if err != nil {
		return "", fmt.Errorf(
			"failed to resolve deployment directory: %w",
			err,
		)
	}

	if !isPathWithinCanaryRoot(
		s.deploymentRoot,
		absolutePath,
	) {
		return "", ErrCanaryDeploymentOutsideRoot
	}

	if err = os.MkdirAll(absolutePath, 0750); err != nil {
		return "", fmt.Errorf(
			"failed to create deployment directory: %w",
			err,
		)
	}

	resolvedPath, err := filepath.EvalSymlinks(
		absolutePath,
	)
	if err != nil {
		return "", fmt.Errorf(
			"failed to validate deployment directory: %w",
			err,
		)
	}

	resolvedPath = filepath.Clean(resolvedPath)

	if !isPathWithinCanaryRoot(
		s.deploymentRoot,
		resolvedPath,
	) {
		return "", ErrCanaryDeploymentOutsideRoot
	}

	return resolvedPath, nil
}

func buildCreateCanaryFileResponse(
	canary *CanaryFile,
) *CreateCanaryFileResponse {
	return &CreateCanaryFileResponse{
		ID:                 canary.ID,
		CanaryCode:         canary.CanaryCode,
		FileName:           canary.FileName,
		FileExtension:      canary.FileExtension,
		MimeType:           canary.MimeType,
		CanaryType:         canary.CanaryType,
		HashAlgorithm:      canary.HashAlgorithm,
		FileSizeBytes:      canary.FileSizeBytes,
		ContainsHoneytoken: canary.ContainsHoneytoken,
		HoneytokenID:       canary.HoneytokenID,
		Status:             canary.Status,
		CreatedAt:          canary.CreatedAt,
	}
}

func buildGetCanaryFileResponse(
	canary *CanaryFile,
) GetCanaryFileResponse {
	var deployedFilePath *string
	if canary.DeployedAt != nil {
		path := canary.FilePath
		deployedFilePath = &path
	}
	return GetCanaryFileResponse{
		ID:                       canary.ID,
		OrganizationID:           canary.OrganizationID,
		DepartmentID:             canary.DepartmentID,
		PolicyID:                 canary.PolicyID,
		CanaryCode:               canary.CanaryCode,
		FileName:                 canary.FileName,
		FileExtension:            canary.FileExtension,
		MimeType:                 canary.MimeType,
		CanaryType:               canary.CanaryType,
		Description:              canary.Description,
		OriginalFileHash:         canary.OriginalFileHash,
		HashAlgorithm:            canary.HashAlgorithm,
		FileSizeBytes:            canary.FileSizeBytes,
		ContainsHoneytoken:       canary.ContainsHoneytoken,
		HoneytokenID:             canary.HoneytokenID,
		DeployedDeviceName:       canary.DeployedDeviceName,
		DeployedDeviceIdentifier: canary.DeployedDeviceIdentifier,
		DeployedFilePath:         deployedFilePath,
		OwnerUserID:              canary.OwnerUserID,
		AccessCount:              canary.AccessCount,
		LastTriggeredAt:          canary.LastTriggeredAt,
		DeployedAt:               canary.DeployedAt,
		ExpiresAt:                canary.ExpiresAt,
		Status:                   canary.Status,
		CreatedAt:                canary.CreatedAt,
		UpdatedAt:                canary.UpdatedAt,
	}
}

func buildDeployCanaryFileResponse(
	canary *CanaryFile,
) *DeployCanaryFileResponse {
	deployedAt := time.Now().UTC()

	if canary.DeployedAt != nil {
		deployedAt = canary.DeployedAt.UTC()
	}

	return &DeployCanaryFileResponse{
		ID:                       canary.ID,
		FileName:                 canary.FileName,
		DeployedDeviceName:       canary.DeployedDeviceName,
		DeployedDeviceIdentifier: canary.DeployedDeviceIdentifier,
		DeployedFilePath:         canary.FilePath,
		Status:                   canary.Status,
		DeployedAt:               deployedAt,
	}
}

func parseCanaryRequiredUUID(
	value string,
	fieldName string,
) (uuid.UUID, error) {
	value = strings.TrimSpace(value)

	parsedValue, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, fmt.Errorf(
			"%s must be a valid UUID",
			fieldName,
		)
	}

	return parsedValue, nil
}

func parseCanaryOptionalUUID(
	value *string,
	fieldName string,
) (*uuid.UUID, error) {
	if value == nil {
		return nil, nil
	}

	trimmedValue := strings.TrimSpace(*value)
	if trimmedValue == "" {
		return nil, nil
	}

	parsedValue, err := uuid.Parse(trimmedValue)
	if err != nil {
		return nil, fmt.Errorf(
			"%s must be a valid UUID",
			fieldName,
		)
	}

	return &parsedValue, nil
}

func parseCanaryExpiration(
	value *string,
) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}

	trimmedValue := strings.TrimSpace(*value)
	if trimmedValue == "" {
		return nil, nil
	}

	parsedValue, err := time.Parse(
		time.RFC3339,
		trimmedValue,
	)
	if err != nil {
		return nil, errors.New(
			"expires_at must use RFC3339 format",
		)
	}

	parsedValue = parsedValue.UTC()

	if !parsedValue.After(time.Now().UTC()) {
		return nil, ErrCanaryFileExpired
	}

	return &parsedValue, nil
}

func normalizeCanaryOptionalString(
	value *string,
) *string {
	if value == nil {
		return nil
	}

	trimmedValue := strings.TrimSpace(*value)
	if trimmedValue == "" {
		return nil
	}

	return &trimmedValue
}

func isCanaryLinkedHoneytokenUsable(
	honeytoken *Honeytoken,
) bool {
	if honeytoken == nil {
		return false
	}

	if honeytoken.ExpiresAt != nil &&
		!honeytoken.ExpiresAt.After(time.Now().UTC()) {
		return false
	}

	switch honeytoken.Status {
	case HoneytokenStatusDraft,
		HoneytokenStatusActive,
		HoneytokenStatusTriggered:
		return true

	default:
		return false
	}
}

func isSupportedCanaryStatus(
	status string,
) bool {
	switch status {
	case CanaryStatusDraft,
		CanaryStatusDeployed,
		CanaryStatusActive,
		CanaryStatusTriggered,
		CanaryStatusTampered,
		CanaryStatusMissing,
		CanaryStatusInactive,
		CanaryStatusExpired,
		CanaryStatusArchived:
		return true

	default:
		return false
	}
}

func isCanaryDeployableStatus(
	status string,
) bool {
	switch status {
	case CanaryStatusDraft,
		CanaryStatusDeployed,
		CanaryStatusInactive:
		return true

	default:
		return false
	}
}

func isPathWithinCanaryRoot(
	rootPath string,
	targetPath string,
) bool {
	relativePath, err := filepath.Rel(
		filepath.Clean(rootPath),
		filepath.Clean(targetPath),
	)
	if err != nil {
		return false
	}

	return relativePath != ".." &&
		!strings.HasPrefix(
			relativePath,
			".."+string(filepath.Separator),
		)
}

func copyCanaryFileAtomically(
	ctx context.Context,
	sourcePath string,
	destinationPath string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf(
			"failed to open generated canary file: %w",
			err,
		)
	}
	defer sourceFile.Close()

	sourceInfo, err := sourceFile.Stat()
	if err != nil {
		return fmt.Errorf(
			"failed to inspect generated canary file: %w",
			err,
		)
	}

	if !sourceInfo.Mode().IsRegular() {
		return errors.New(
			"generated canary source is not a regular file",
		)
	}

	if _, err = os.Lstat(destinationPath); err == nil {
		return ErrCanaryDeploymentFileExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf(
			"failed to inspect canary destination: %w",
			err,
		)
	}

	destinationDirectory := filepath.Dir(
		destinationPath,
	)

	temporaryFile, err := os.CreateTemp(
		destinationDirectory,
		".ddh-deploy-*",
	)
	if err != nil {
		return fmt.Errorf(
			"failed to create deployment file: %w",
			err,
		)
	}

	temporaryPath := temporaryFile.Name()
	closed := false

	defer func() {
		if !closed {
			_ = temporaryFile.Close()
		}

		_ = os.Remove(temporaryPath)
	}()

	if err = temporaryFile.Chmod(0640); err != nil {
		return fmt.Errorf(
			"failed to secure deployment file: %w",
			err,
		)
	}

	_, err = io.Copy(
		temporaryFile,
		&canaryContextReader{
			ctx:    ctx,
			reader: sourceFile,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"failed to copy canary file: %w",
			err,
		)
	}

	if err = temporaryFile.Sync(); err != nil {
		return fmt.Errorf(
			"failed to synchronize deployed canary file: %w",
			err,
		)
	}

	if err = temporaryFile.Close(); err != nil {
		return fmt.Errorf(
			"failed to close deployed canary file: %w",
			err,
		)
	}

	closed = true

	if _, err = os.Lstat(destinationPath); err == nil {
		return ErrCanaryDeploymentFileExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf(
			"failed to validate canary destination: %w",
			err,
		)
	}

	if err = os.Rename(
		temporaryPath,
		destinationPath,
	); err != nil {
		return fmt.Errorf(
			"failed to finalize canary deployment: %w",
			err,
		)
	}

	return nil
}

func calculateCanaryFileSHA256(
	filePath string,
) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf(
			"failed to open canary file for hashing: %w",
			err,
		)
	}
	defer file.Close()

	hash := sha256.New()

	if _, err = io.Copy(hash, file); err != nil {
		return "", fmt.Errorf(
			"failed to calculate canary file hash: %w",
			err,
		)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

type canaryContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *canaryContextReader) Read(
	buffer []byte,
) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()

	default:
		return r.reader.Read(buffer)
	}
}
