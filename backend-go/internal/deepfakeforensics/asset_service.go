package deepfakeforensics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const maximumMediaUploadMetadataBytes = 64 * 1024

// AssetService coordinates validated local file storage
// with organization-scoped database registration.
type AssetService struct {
	repository  *Repository
	fileManager *AssetFileManager
}

func NewAssetService(
	repository *Repository,
	fileManager *AssetFileManager,
) (*AssetService, error) {
	if repository == nil ||
		!repository.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}
	if fileManager == nil ||
		strings.TrimSpace(
			fileManager.rootPath,
		) == "" {
		return nil, errors.New(
			"media asset file manager is required",
		)
	}

	return &AssetService{
		repository:  repository,
		fileManager: fileManager,
	}, nil
}

// UploadMediaAsset stores one direct organization upload
// and creates its database asset. A failed database write
// removes the newly stored file.
func (s *AssetService) UploadMediaAsset(
	ctx context.Context,
	organizationID uuid.UUID,
	uploadedBy uuid.UUID,
	originalFileName string,
	declaredMimeType string,
	source io.Reader,
	request UploadMediaAssetRequest,
) (*MediaAnalysisAsset, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		uploadedBy == uuid.Nil ||
		source == nil {
		return nil, ErrInvalidMediaUpload
	}

	departmentID, err := parseOptionalUploadUUID(
		request.DepartmentID,
		"department ID",
	)
	if err != nil {
		return nil, err
	}

	incidentID, err := parseOptionalUploadUUID(
		request.IncidentID,
		"incident ID",
	)
	if err != nil {
		return nil, err
	}

	sourceType := NormalizeConstant(
		request.SourceType,
	)
	if sourceType == "" {
		sourceType =
			mediaAssetSourceDirectUpload
	}
	if sourceType !=
		mediaAssetSourceDirectUpload {
		return nil, fmt.Errorf(
			"%w: direct upload source type is required",
			ErrInvalidMediaUpload,
		)
	}

	metadata, err := decodeUploadMetadata(
		request.Metadata,
	)
	if err != nil {
		return nil, err
	}

	if err = s.repository.
		validateMediaUploadReferences(
			ctx,
			organizationID,
			departmentID,
			incidentID,
		); err != nil {
		return nil, err
	}

	storedFile, storeErr := s.fileManager.Store(
		ctx,
		organizationID,
		originalFileName,
		declaredMimeType,
		source,
	)
	if storeErr != nil &&
		storedFile == nil {
		return nil, storeErr
	}
	quarantined := errors.Is(
		storeErr,
		ErrMediaUploadQuarantined,
	)

	metadata["upload_source"] =
		mediaAssetSourceDirectUpload
	metadata["declared_mime_type"] =
		normalizeMimeType(declaredMimeType)
	metadata["detected_media_type"] =
		storedFile.MediaType
	metadata["storage_encrypted"] =
		storedFile.IsEncrypted
	if quarantined {
		metadata["quarantined_at"] =
			time.Now().UTC()
		metadata["quarantine_reason"] =
			storedFile.QuarantineReason
		metadata["quarantine_source"] =
			"AUTOMATIC_UPLOAD_VALIDATION"
	}

	fileExtension :=
		storedFile.FileExtension

	asset, createErr :=
		s.repository.CreateMediaAsset(
			ctx,
			CreateMediaAssetInput{
				OrganizationID: organizationID,
				DepartmentID:   departmentID,
				IncidentID:     incidentID,

				OriginalFileName: storedFile.OriginalFileName,
				StoredFileName:   storedFile.StoredFileName,
				StoragePath:      storedFile.StoragePath,

				MediaType:     storedFile.MediaType,
				MimeType:      storedFile.MimeType,
				FileExtension: &fileExtension,
				FileSizeBytes: storedFile.FileSizeBytes,

				FileHash: storedFile.FileHash,

				IsEncrypted: storedFile.IsEncrypted,
				EncryptionAlgorithm: storedFile.
					EncryptionAlgorithm,

				SourceType: sourceType,
				Status:     storedFile.Status,
				UploadedBy: uploadedBy,

				Metadata: metadata,
			},
		)
	if createErr != nil {
		cleanupErr := s.fileManager.Remove(
			storedFile.StoragePath,
		)
		if cleanupErr != nil {
			return nil, fmt.Errorf(
				"create media asset: %w; rollback stored file: %v",
				createErr,
				cleanupErr,
			)
		}

		return nil, createErr
	}

	if quarantined {
		eventErr :=
			s.repository.RecordMediaSecurityEvent(
				ctx,
				organizationID,
				asset.ID,
				&uploadedBy,
				"QUARANTINED",
				storedFile.QuarantineReason,
				map[string]any{
					"automatic": true,
					"source":    "UPLOAD_VALIDATION",
				},
			)
		if eventErr != nil {
			return asset, fmt.Errorf(
				"%w: record quarantine event: %v",
				storeErr,
				eventErr,
			)
		}
		return asset, storeErr
	}

	return asset, nil
}

func (s *AssetService) isAvailable() bool {
	return s != nil &&
		s.repository != nil &&
		s.repository.IsAvailable() &&
		s.fileManager != nil
}

func parseOptionalUploadUUID(
	value string,
	fieldName string,
) (*uuid.UUID, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	parsedValue, err := uuid.Parse(value)
	if err != nil ||
		parsedValue == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: invalid %s",
			ErrInvalidMediaUpload,
			fieldName,
		)
	}

	return &parsedValue, nil
}

func decodeUploadMetadata(
	value string,
) (map[string]any, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return map[string]any{}, nil
	}
	if len(value) >
		maximumMediaUploadMetadataBytes {
		return nil, fmt.Errorf(
			"%w: upload metadata is too large",
			ErrInvalidMediaUpload,
		)
	}

	decoder := json.NewDecoder(
		bytes.NewBufferString(value),
	)
	decoder.UseNumber()

	metadata := map[string]any{}
	if err := decoder.Decode(
		&metadata,
	); err != nil {
		return nil, fmt.Errorf(
			"%w: upload metadata must be a JSON object",
			ErrInvalidMediaUpload,
		)
	}

	var trailingValue any
	if err := decoder.Decode(
		&trailingValue,
	); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf(
			"%w: upload metadata contains trailing data",
			ErrInvalidMediaUpload,
		)
	}

	if metadata == nil {
		return map[string]any{}, nil
	}

	return metadata, nil
}

func (r *Repository) validateMediaUploadReferences(
	ctx context.Context,
	organizationID uuid.UUID,
	departmentID *uuid.UUID,
	incidentID *uuid.UUID,
) error {
	if err := r.validateAvailable(); err != nil {
		return err
	}
	if ctx == nil ||
		organizationID == uuid.Nil {
		return ErrInvalidRepositoryInput
	}
	if departmentID == nil &&
		incidentID == nil {
		return nil
	}

	var departmentValid bool
	var incidentValid bool

	err := r.databasePool.QueryRow(
		ctx,
		`
			SELECT
				(
					$2::uuid IS NULL
					OR EXISTS (
						SELECT 1
						FROM departments
						WHERE id = $2
							AND organization_id = $1
					)
				),
				(
					$3::uuid IS NULL
					OR EXISTS (
						SELECT 1
						FROM incidents
						WHERE id = $3
							AND organization_id = $1
					)
				)
		`,
		organizationID,
		departmentID,
		incidentID,
	).Scan(
		&departmentValid,
		&incidentValid,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidMediaUpload
	}
	if err != nil {
		return fmt.Errorf(
			"validate media upload references: %w",
			err,
		)
	}

	if !departmentValid {
		return fmt.Errorf(
			"%w: department does not belong to organization",
			ErrInvalidMediaUpload,
		)
	}
	if !incidentValid {
		return fmt.Errorf(
			"%w: incident does not belong to organization",
			ErrInvalidMediaUpload,
		)
	}

	return nil
}
