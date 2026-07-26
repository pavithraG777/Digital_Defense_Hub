package adaptivedeception

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	honeytoken "github.com/pavithraG777/cyber-security-platform/backend/internal/HoneyToken"
)

var ErrInvalidCanaryRotationRequest = errors.New(
	"invalid canary rotation request",
)

const defaultRotatedCanaryValidity = 30 * 24 * time.Hour

// RotationCommand controls one manual or automatic
// adaptive canary rotation.
type RotationCommand struct {
	RotationReason   string
	RotationStrategy string
	NewFileName      string

	RequestedBy *uuid.UUID
}

// CanaryMonitorRefresher reloads monitored canary paths
// after a successful adaptive rotation.
type CanaryMonitorRefresher interface {
	Refresh(ctx context.Context) error
}

// RotationService performs controlled dynamic canary
// regeneration, evidence preservation and redeployment.
type RotationService struct {
	repository       *Repository
	generator        *honeytoken.CanaryGenerator
	fileManager      *RotationFileManager
	healthService    *HealthService
	monitorRefresher CanaryMonitorRefresher
}

func NewRotationService(
	repository *Repository,
	generator *honeytoken.CanaryGenerator,
	fileManager *RotationFileManager,
	healthService *HealthService,
	monitorRefresher CanaryMonitorRefresher,
) (*RotationService, error) {
	if repository == nil {
		return nil, errors.New(
			"adaptive deception repository is required",
		)
	}

	if generator == nil {
		return nil, errors.New(
			"canary generator is required",
		)
	}

	if fileManager == nil {
		return nil, errors.New(
			"rotation file manager is required",
		)
	}

	if healthService == nil {
		return nil, errors.New(
			"canary health service is required",
		)
	}

	if monitorRefresher == nil {
		return nil, errors.New(
			"canary file monitor refresher is required",
		)
	}

	return &RotationService{
		repository:       repository,
		generator:        generator,
		fileManager:      fileManager,
		healthService:    healthService,
		monitorRefresher: monitorRefresher,
	}, nil
}

func (s *RotationService) RotateCanary(
	ctx context.Context,
	organizationID uuid.UUID,
	canaryFileID uuid.UUID,
	command RotationCommand,
) (*CanaryRotation, error) {
	if s == nil ||
		s.repository == nil ||
		s.generator == nil ||
		s.fileManager == nil ||
		s.healthService == nil ||
		s.monitorRefresher == nil {
		return nil, errors.New(
			"canary rotation service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: organization ID is required",
			ErrInvalidCanaryRotationRequest,
		)
	}

	if canaryFileID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: canary file ID is required",
			ErrInvalidCanaryRotationRequest,
		)
	}

	command.RotationReason =
		NormalizeConstant(
			command.RotationReason,
		)

	if command.RotationReason == "" {
		command.RotationReason =
			RotationReasonManual
	}

	if !IsSupportedRotationReason(
		command.RotationReason,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported rotation reason",
			ErrInvalidCanaryRotationRequest,
		)
	}

	command.RotationStrategy =
		NormalizeConstant(
			command.RotationStrategy,
		)

	if command.RotationStrategy == "" {
		command.RotationStrategy =
			RotationStrategyRegenerateAndRelocate
	}

	if !IsSupportedRotationStrategy(
		command.RotationStrategy,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported rotation strategy",
			ErrInvalidCanaryRotationRequest,
		)
	}

	command.NewFileName =
		strings.TrimSpace(
			command.NewFileName,
		)

	snapshot, err :=
		s.repository.GetCanaryFileSnapshot(
			ctx,
			organizationID,
			canaryFileID,
		)
	if err != nil {
		return nil, err
	}

	if !isCanaryRotatableStatus(
		snapshot.Status,
	) {
		return nil, fmt.Errorf(
			"%w: canary status %s cannot be rotated",
			ErrInvalidCanaryRotationRequest,
			snapshot.Status,
		)
	}

	now := time.Now().UTC()
	rotationID := uuid.New()

	rotationMetadata := map[string]any{
		"adaptive_rotation":    true,
		"source_canary_code":   snapshot.CanaryCode,
		"source_canary_status": snapshot.Status,
		"contains_honeytoken":  snapshot.ContainsHoneytoken,
	}

	if observedOldHash, hashErr :=
		calculateFileHash(
			snapshot.FilePath,
			snapshot.HashAlgorithm,
		); hashErr == nil {
		rotationMetadata["observed_old_file_hash"] =
			observedOldHash
	}

	rotation, err :=
		s.repository.CreateRotation(
			ctx,
			&CanaryRotation{
				ID:             rotationID,
				OrganizationID: organizationID,
				CanaryFileID:   canaryFileID,
				PolicyID:       snapshot.PolicyID,

				RotationReason: command.RotationReason,

				RotationStrategy: command.RotationStrategy,

				OldFileName: stringPointer(
					snapshot.FileName,
				),

				OldFilePath: stringPointer(
					snapshot.FilePath,
				),

				OldFileHash: stringPointer(
					snapshot.OriginalFileHash,
				),

				OldTrackingIdentifier: stringPointer(
					snapshot.TrackingIdentifier,
				),

				Status: RotationStatusPending,

				RequestedBy: command.RequestedBy,

				Metadata: rotationMetadata,

				RequestedAt: now,
			},
		)
	if err != nil {
		return nil, err
	}

	rotation, err =
		s.repository.MarkRotationProcessing(
			ctx,
			organizationID,
			rotation.ID,
		)
	if err != nil {
		return nil, err
	}

	evidence, err :=
		s.fileManager.PreserveEvidence(
			ctx,
			snapshot,
			rotation.ID,
		)
	if err != nil {
		return nil,
			s.failRotation(
				ctx,
				rotation,
				"evidence_preservation",
				err,
				nil,
			)
	}

	proposedDestination, err :=
		s.fileManager.ResolveDestination(
			snapshot,
			rotation.ID,
			rotation.RotationStrategy,
			command.NewFileName,
			now,
		)
	if err != nil {
		return nil,
			s.failRotation(
				ctx,
				rotation,
				"destination_resolution",
				err,
				evidence,
			)
	}

	generatedCanary, err :=
		s.generator.GenerateForRotation(
			ctx,
			honeytoken.CanaryRotationGenerationInput{
				ID: snapshot.ID,

				OrganizationID: snapshot.OrganizationID,

				FileName: proposedDestination.FileName,

				CanaryType: snapshot.CanaryType,

				LinkedHoneytokenCode: snapshot.LinkedHoneytokenCode,
			},
		)
	if err != nil {
		return nil,
			s.failRotation(
				ctx,
				rotation,
				"canary_generation",
				err,
				evidence,
			)
	}

	cleanupGeneratedFile := true

	defer func() {
		if cleanupGeneratedFile {
			_ = s.generator.
				RemoveRotationGeneratedFile(
					generatedCanary.FilePath,
				)
		}
	}()

	finalDestination, err :=
		s.fileManager.ResolveDestination(
			snapshot,
			rotation.ID,
			rotation.RotationStrategy,
			generatedCanary.FileName,
			now,
		)
	if err != nil {
		return nil,
			s.failRotation(
				ctx,
				rotation,
				"generated_destination_resolution",
				err,
				evidence,
			)
	}

	err = s.fileManager.DeployGeneratedFile(
		ctx,
		generatedCanary.FilePath,
		finalDestination.FilePath,
	)
	if err != nil {
		return nil,
			s.failRotation(
				ctx,
				rotation,
				"canary_deployment",
				err,
				evidence,
			)
	}

	deployedHash, err :=
		calculateFileHash(
			finalDestination.FilePath,
			generatedCanary.HashAlgorithm,
		)
	if err != nil {
		rollbackErr :=
			s.rollbackDeployment(
				ctx,
				snapshot.FilePath,
				finalDestination.FilePath,
				evidence,
			)

		return nil,
			s.failRotation(
				ctx,
				rotation,
				"deployment_hash_verification",
				combineRotationErrors(
					err,
					rollbackErr,
				),
				evidence,
			)
	}

	if !strings.EqualFold(
		deployedHash,
		generatedCanary.OriginalFileHash,
	) {
		rollbackErr :=
			s.rollbackDeployment(
				ctx,
				snapshot.FilePath,
				finalDestination.FilePath,
				evidence,
			)

		return nil,
			s.failRotation(
				ctx,
				rotation,
				"deployment_integrity_mismatch",
				combineRotationErrors(
					errors.New(
						"deployed canary hash does not match generated baseline",
					),
					rollbackErr,
				),
				evidence,
			)
	}

	completionMetadata := map[string]any{
		"dynamic_file_name":             finalDestination.FileName,
		"dynamic_file_path":             finalDestination.FilePath,
		"evidence_preserved":            evidence.Exists,
		"generation_hash_algorithm":     generatedCanary.HashAlgorithm,
		"embedded_honeytoken_preserved": snapshot.LinkedHoneytokenCode != nil,
	}

	if evidence.Exists {
		completionMetadata["evidence_path"] =
			evidence.EvidencePath
	}

	newExpiresAt :=
		calculateRotatedExpiration(
			snapshot,
			now,
		)

	completedRotation, err :=
		s.repository.CompleteRotation(
			ctx,
			organizationID,
			rotation.ID,
			canaryFileID,
			RotationCompletion{
				NewFileName: finalDestination.FileName,

				NewFilePath: finalDestination.FilePath,

				NewFileHash: generatedCanary.OriginalFileHash,

				NewTrackingIdentifier: generatedCanary.TrackingIdentifier,

				NewFileSizeBytes: generatedCanary.FileSizeBytes,

				NewExpiresAt: newExpiresAt,

				Metadata: completionMetadata,
			},
		)
	if err != nil {
		rollbackErr :=
			s.rollbackDeployment(
				ctx,
				snapshot.FilePath,
				finalDestination.FilePath,
				evidence,
			)

		return nil,
			s.failRotation(
				ctx,
				rotation,
				"database_completion",
				combineRotationErrors(
					err,
					rollbackErr,
				),
				evidence,
			)
	}

	// Reload monitored paths before removing the old file.
	// This prevents the old-path deletion event from marking
	// the newly rotated canary as MISSING.
	if err = s.monitorRefresher.Refresh(
		ctx,
	); err != nil {
		return completedRotation, fmt.Errorf(
			"canary rotation completed but file monitor refresh failed: %w",
			err,
		)
	}

	if !pathsEqual(
		snapshot.FilePath,
		finalDestination.FilePath,
	) {
		_ = s.fileManager.RemoveManagedFile(
			snapshot.FilePath,
		)
	}

	_ = s.generator.
		RemoveRotationGeneratedFile(
			generatedCanary.FilePath,
		)

	cleanupGeneratedFile = false

	_, _ = s.healthService.CheckCanaryHealth(
		ctx,
		organizationID,
		canaryFileID,
		HealthCheckTypePostRotation,
	)

	return completedRotation, nil
}

func (s *RotationService) GetRotation(
	ctx context.Context,
	organizationID uuid.UUID,
	rotationID uuid.UUID,
) (*CanaryRotation, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New(
			"canary rotation service is unavailable",
		)
	}

	return s.repository.GetRotation(
		ctx,
		organizationID,
		rotationID,
	)
}

func (s *RotationService) failRotation(
	ctx context.Context,
	rotation *CanaryRotation,
	failureStage string,
	failure error,
	evidence *PreservedCanaryEvidence,
) error {
	if failure == nil {
		failure = errors.New(
			"canary rotation failed",
		)
	}

	metadata := map[string]any{
		"failure_stage": failureStage,
	}

	if evidence != nil {
		metadata["evidence_preserved"] =
			evidence.Exists

		if evidence.Exists {
			metadata["evidence_path"] =
				evidence.EvidencePath
		}
	}

	if rotation != nil {
		_, persistenceErr :=
			s.repository.FailRotation(
				ctx,
				rotation.OrganizationID,
				rotation.ID,
				failure.Error(),
				metadata,
			)
		if persistenceErr != nil {
			return fmt.Errorf(
				"%v; persist rotation failure: %w",
				failure,
				persistenceErr,
			)
		}
	}

	return failure
}

func (s *RotationService) rollbackDeployment(
	ctx context.Context,
	originalPath string,
	deployedPath string,
	evidence *PreservedCanaryEvidence,
) error {
	if pathsEqual(
		originalPath,
		deployedPath,
	) {
		if evidence != nil &&
			evidence.Exists {
			return s.fileManager.RestoreEvidence(
				ctx,
				evidence,
				originalPath,
			)
		}

		return s.fileManager.RemoveManagedFile(
			deployedPath,
		)
	}

	return s.fileManager.RemoveManagedFile(
		deployedPath,
	)
}

func isCanaryRotatableStatus(
	status string,
) bool {
	switch NormalizeConstant(status) {
	case CanaryFileStatusDeployed,
		CanaryFileStatusActive,
		CanaryFileStatusTriggered,
		CanaryFileStatusTampered,
		CanaryFileStatusMissing,
		CanaryFileStatusExpired:
		return true

	default:
		return false
	}
}

func calculateRotatedExpiration(
	snapshot *CanaryFileSnapshot,
	rotatedAt time.Time,
) *time.Time {
	if snapshot == nil ||
		snapshot.ExpiresAt == nil {
		return nil
	}

	referenceTime :=
		snapshot.CreatedAt

	if snapshot.DeployedAt != nil {
		referenceTime =
			snapshot.DeployedAt.UTC()
	}

	validity :=
		snapshot.ExpiresAt.Sub(
			referenceTime,
		)

	if validity <= 0 {
		validity =
			defaultRotatedCanaryValidity
	}

	expiresAt :=
		rotatedAt.UTC().Add(
			validity,
		)

	return &expiresAt
}

func combineRotationErrors(
	primaryError error,
	rollbackError error,
) error {
	if primaryError == nil {
		return rollbackError
	}

	if rollbackError == nil {
		return primaryError
	}

	return fmt.Errorf(
		"%v; filesystem rollback failed: %w",
		primaryError,
		rollbackError,
	)
}
