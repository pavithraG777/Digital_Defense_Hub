package adaptivedeception

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidCanaryHealthRequest = errors.New(
	"invalid canary health check request",
)

const defaultCanaryHealthCheckInterval = 5 * time.Minute

// HealthService verifies persisted canary metadata
// against the actual deployed file.
type HealthService struct {
	repository    *Repository
	checkInterval time.Duration
}

func NewHealthService(
	repository *Repository,
	checkInterval time.Duration,
) (*HealthService, error) {
	if repository == nil {
		return nil, errors.New(
			"adaptive deception repository is required",
		)
	}

	if checkInterval <= 0 {
		checkInterval =
			defaultCanaryHealthCheckInterval
	}

	return &HealthService{
		repository:    repository,
		checkInterval: checkInterval,
	}, nil
}

func (s *HealthService) CheckCanaryHealth(
	ctx context.Context,
	organizationID uuid.UUID,
	canaryFileID uuid.UUID,
	checkType string,
) (*CanaryHealthCheck, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New(
			"canary health service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: organization ID is required",
			ErrInvalidCanaryHealthRequest,
		)
	}

	if canaryFileID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: canary file ID is required",
			ErrInvalidCanaryHealthRequest,
		)
	}

	checkType =
		NormalizeConstant(checkType)

	if checkType == "" {
		checkType =
			HealthCheckTypeManual
	}

	if !IsSupportedHealthCheckType(
		checkType,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported health check type",
			ErrInvalidCanaryHealthRequest,
		)
	}

	snapshot, err :=
		s.repository.GetCanaryFileSnapshot(
			ctx,
			organizationID,
			canaryFileID,
		)
	if err != nil {
		return nil, err
	}

	if !IsSupportedHashAlgorithm(
		snapshot.HashAlgorithm,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported canary hash algorithm",
			ErrInvalidCanaryHealthRequest,
		)
	}

	checkedAt := time.Now().UTC()
	nextCheckAt := checkedAt.Add(
		s.checkInterval,
	)

	healthCheck := &CanaryHealthCheck{
		ID:             uuid.New(),
		OrganizationID: snapshot.OrganizationID,
		CanaryFileID:   snapshot.ID,
		PolicyID:       snapshot.PolicyID,
		CheckType:      checkType,

		ExpectedFilePath: strings.TrimSpace(
			snapshot.FilePath,
		),
		ExpectedHash: strings.ToLower(
			strings.TrimSpace(
				snapshot.OriginalFileHash,
			),
		),
		HashAlgorithm: snapshot.HashAlgorithm,

		ExpectedSizeBytes: snapshot.FileSizeBytes,

		HealthStatus: CanaryHealthStatusUnknown,

		Metadata: map[string]any{
			"canary_code":         snapshot.CanaryCode,
			"canary_type":         snapshot.CanaryType,
			"canary_status":       snapshot.Status,
			"tracking_identifier": snapshot.TrackingIdentifier,
		},

		CheckedAt:   checkedAt,
		NextCheckAt: &nextCheckAt,
	}

	addOptionalSnapshotMetadata(
		healthCheck.Metadata,
		snapshot,
	)

	s.evaluateCanaryHealth(
		healthCheck,
		snapshot,
	)

	result, err :=
		s.repository.CreateHealthCheck(
			ctx,
			healthCheck,
		)
	if err != nil {
		return nil, err
	}

	_, err =
		s.repository.SyncCanaryStatusWithHealth(
			ctx,
			organizationID,
			canaryFileID,
			result.HealthStatus,
		)
	if err != nil {
		return result, fmt.Errorf(
			"persisted health check but failed to synchronize canary status: %w",
			err,
		)
	}

	return result, nil
}

func (s *HealthService) GetLatestHealthCheck(
	ctx context.Context,
	organizationID uuid.UUID,
	canaryFileID uuid.UUID,
) (*CanaryHealthCheck, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New(
			"canary health service is unavailable",
		)
	}

	return s.repository.GetLatestHealthCheck(
		ctx,
		organizationID,
		canaryFileID,
	)
}

func (s *HealthService) evaluateCanaryHealth(
	healthCheck *CanaryHealthCheck,
	snapshot *CanaryFileSnapshot,
) {
	if healthCheck == nil ||
		snapshot == nil {
		return
	}

	if snapshot.ExpiresAt != nil &&
		!snapshot.ExpiresAt.After(
			healthCheck.CheckedAt,
		) {
		healthCheck.HealthStatus =
			CanaryHealthStatusExpired

		healthCheck.HealthScore = 0
		healthCheck.IsHealthy = false

		healthCheck.FailureReason =
			stringPointer(
				"Canary file has expired",
			)

		healthCheck.Metadata["expired_at"] =
			snapshot.ExpiresAt.UTC()

		return
	}

	expectedPath, pathErr :=
		normalizedAbsolutePath(
			healthCheck.ExpectedFilePath,
		)
	if pathErr != nil {
		healthCheck.HealthStatus =
			CanaryHealthStatusError

		healthCheck.HealthScore = 0
		healthCheck.IsHealthy = false

		healthCheck.FailureReason =
			stringPointer(
				"Unable to normalize canary file path",
			)

		healthCheck.Metadata["path_error"] =
			pathErr.Error()

		return
	}

	healthCheck.ExpectedFilePath =
		expectedPath

	fileInfo, statErr := os.Stat(
		expectedPath,
	)
	if statErr != nil {
		healthCheck.FileExists = false
		healthCheck.PathMatches = false
		healthCheck.HashMatches = false
		healthCheck.SizeMatches = false
		healthCheck.PermissionsValid = false
		healthCheck.IsHealthy = false
		healthCheck.HealthScore = 0

		if errors.Is(
			statErr,
			os.ErrNotExist,
		) {
			healthCheck.HealthStatus =
				CanaryHealthStatusMissing

			healthCheck.FailureReason =
				stringPointer(
					"Canary file is missing",
				)
		} else {
			healthCheck.HealthStatus =
				CanaryHealthStatusError

			healthCheck.FailureReason =
				stringPointer(
					"Unable to inspect canary file",
				)

			healthCheck.Metadata["filesystem_error"] =
				statErr.Error()
		}

		return
	}

	if fileInfo.IsDir() {
		healthCheck.FileExists = false
		healthCheck.PathMatches = false
		healthCheck.HashMatches = false
		healthCheck.SizeMatches = false
		healthCheck.PermissionsValid = false
		healthCheck.IsHealthy = false
		healthCheck.HealthScore = 0
		healthCheck.HealthStatus =
			CanaryHealthStatusError

		healthCheck.FailureReason =
			stringPointer(
				"Canary path points to a directory",
			)

		return
	}

	observedPath := expectedPath
	observedSize := fileInfo.Size()

	healthCheck.ObservedFilePath =
		&observedPath

	healthCheck.ObservedSizeBytes =
		&observedSize

	healthCheck.FileExists = true

	healthCheck.PathMatches =
		pathsEqual(
			healthCheck.ExpectedFilePath,
			observedPath,
		)

	if healthCheck.ExpectedSizeBytes == nil {
		healthCheck.SizeMatches = true
	} else {
		healthCheck.SizeMatches =
			*healthCheck.ExpectedSizeBytes ==
				observedSize
	}

	observedHash, hashErr :=
		calculateFileHash(
			expectedPath,
			healthCheck.HashAlgorithm,
		)
	if hashErr != nil {
		healthCheck.HashMatches = false
		healthCheck.PermissionsValid = false
		healthCheck.IsHealthy = false

		healthCheck.HealthScore =
			calculateHealthScore(
				healthCheck,
			)

		healthCheck.HealthStatus =
			CanaryHealthStatusError

		healthCheck.FailureReason =
			stringPointer(
				"Unable to read or hash canary file",
			)

		healthCheck.Metadata["hash_error"] =
			hashErr.Error()

		return
	}

	healthCheck.ObservedHash =
		&observedHash

	healthCheck.PermissionsValid = true

	healthCheck.HashMatches =
		strings.EqualFold(
			healthCheck.ExpectedHash,
			observedHash,
		)

	healthCheck.HealthScore =
		calculateHealthScore(
			healthCheck,
		)

	healthCheck.IsHealthy =
		healthCheck.FileExists &&
			healthCheck.PathMatches &&
			healthCheck.HashMatches &&
			healthCheck.SizeMatches &&
			healthCheck.PermissionsValid

	switch {
	case healthCheck.IsHealthy:
		healthCheck.HealthStatus =
			CanaryHealthStatusHealthy

		healthCheck.FailureReason = nil

	case !healthCheck.HashMatches:
		healthCheck.HealthStatus =
			CanaryHealthStatusTampered

		healthCheck.FailureReason =
			stringPointer(
				"Canary file content hash has changed",
			)

	case !healthCheck.PathMatches:
		healthCheck.HealthStatus =
			CanaryHealthStatusDegraded

		healthCheck.FailureReason =
			stringPointer(
				"Canary file path does not match the expected path",
			)

	case !healthCheck.SizeMatches:
		healthCheck.HealthStatus =
			CanaryHealthStatusDegraded

		healthCheck.FailureReason =
			stringPointer(
				"Canary file size does not match the expected size",
			)

	case !healthCheck.PermissionsValid:
		healthCheck.HealthStatus =
			CanaryHealthStatusDegraded

		healthCheck.FailureReason =
			stringPointer(
				"Canary file cannot be read",
			)

	default:
		healthCheck.HealthStatus =
			CanaryHealthStatusUnknown

		healthCheck.FailureReason =
			stringPointer(
				"Canary file health could not be determined",
			)
	}
}

func calculateHealthScore(
	healthCheck *CanaryHealthCheck,
) float64 {
	if healthCheck == nil {
		return 0
	}

	score := 0.0

	if healthCheck.FileExists {
		score += 30
	}

	if healthCheck.PathMatches {
		score += 15
	}

	if healthCheck.HashMatches {
		score += 35
	}

	if healthCheck.SizeMatches {
		score += 10
	}

	if healthCheck.PermissionsValid {
		score += 10
	}

	if score < MinimumScore {
		return MinimumScore
	}

	if score > MaximumScore {
		return MaximumScore
	}

	return score
}

func calculateFileHash(
	filePath string,
	algorithm string,
) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf(
			"open canary file: %w",
			err,
		)
	}
	defer file.Close()

	var hashWriter hash.Hash

	switch NormalizeConstant(algorithm) {
	case HashAlgorithmSHA256:
		hashWriter = sha256.New()

	case HashAlgorithmSHA384:
		hashWriter = sha512.New384()

	case HashAlgorithmSHA512:
		hashWriter = sha512.New()

	default:
		return "", errors.New(
			"unsupported hash algorithm",
		)
	}

	if _, err = io.Copy(
		hashWriter,
		file,
	); err != nil {
		return "", fmt.Errorf(
			"hash canary file: %w",
			err,
		)
	}

	return hex.EncodeToString(
		hashWriter.Sum(nil),
	), nil
}

func normalizedAbsolutePath(
	value string,
) (string, error) {
	value = strings.TrimSpace(value)

	if value == "" {
		return "", errors.New(
			"file path is required",
		)
	}

	absolutePath, err :=
		filepath.Abs(value)
	if err != nil {
		return "", err
	}

	return filepath.Clean(
		absolutePath,
	), nil
}

func pathsEqual(
	first string,
	second string,
) bool {
	first = filepath.Clean(
		strings.TrimSpace(first),
	)

	second = filepath.Clean(
		strings.TrimSpace(second),
	)

	return strings.EqualFold(
		first,
		second,
	)
}

func stringPointer(
	value string,
) *string {
	value = strings.TrimSpace(value)

	if value == "" {
		return nil
	}

	return &value
}

func addOptionalSnapshotMetadata(
	metadata map[string]any,
	snapshot *CanaryFileSnapshot,
) {
	if metadata == nil ||
		snapshot == nil {
		return
	}

	if snapshot.DepartmentID != nil {
		metadata["department_id"] =
			snapshot.DepartmentID.String()
	}

	if snapshot.DeployedDeviceName != nil {
		metadata["deployed_device_name"] =
			*snapshot.DeployedDeviceName
	}

	if snapshot.DeployedDeviceIdentifier != nil {
		metadata["deployed_device_identifier"] = *snapshot.DeployedDeviceIdentifier
	}

	if snapshot.DeployedAt != nil {
		metadata["deployed_at"] =
			snapshot.DeployedAt.UTC()
	}

	if snapshot.LastTriggeredAt != nil {
		metadata["last_triggered_at"] =
			snapshot.LastTriggeredAt.UTC()
	}
}
