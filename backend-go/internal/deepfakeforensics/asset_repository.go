package deepfakeforensics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	mediaAssetHashAlgorithmSHA256 = "SHA256"
	mediaAssetSourceDirectUpload  = "DIRECT_UPLOAD"
	mediaAssetStatusAvailable     = "AVAILABLE"
)

type databaseRowScanner interface {
	Scan(destinations ...any) error
}

// CreateMediaAsset persists one securely stored,
// organization-scoped media asset.
func (r *Repository) CreateMediaAsset(
	ctx context.Context,
	input CreateMediaAssetInput,
) (*MediaAnalysisAsset, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}

	if err := validateCreateMediaAssetInput(
		ctx,
		input,
	); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	assetID := uuid.New()
	sourceType := NormalizeConstant(
		input.SourceType,
	)
	if sourceType == "" {
		sourceType = mediaAssetSourceDirectUpload
	}

	metadata := input.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: encode media asset metadata: %v",
			ErrInvalidRepositoryInput,
			err,
		)
	}

	query := `
		INSERT INTO media_analysis_assets (
			id,
			asset_code,
			organization_id,
			department_id,
			incident_id,
			evidence_id,
			evidence_file_id,
			original_file_name,
			stored_file_name,
			storage_path,
			media_type,
			mime_type,
			file_extension,
			file_size_bytes,
			file_hash,
			hash_algorithm,
			is_encrypted,
			encryption_algorithm,
			source_type,
			status,
			uploaded_by,
			metadata,
			uploaded_at,
			created_at,
			updated_at
		)
		VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15,
			$16, $17, $18, $19, $20,
			$21, $22, $23, $23, $23
		)
		RETURNING
			id,
			asset_sequence,
			asset_code,
			organization_id,
			department_id,
			incident_id,
			evidence_id,
			evidence_file_id,
			original_file_name,
			stored_file_name,
			storage_path,
			media_type,
			mime_type,
			file_extension,
			file_size_bytes,
			file_hash,
			hash_algorithm,
			is_encrypted,
			encryption_algorithm,
			source_type,
			status,
			uploaded_by,
			metadata,
			uploaded_at,
			analyzed_at,
			created_at,
			updated_at,
			deleted_at
	`

	row := r.databasePool.QueryRow(
		ctx,
		query,
		assetID,
		buildMediaAssetCode(assetID, now),
		input.OrganizationID,
		input.DepartmentID,
		input.IncidentID,
		nil,
		nil,
		strings.TrimSpace(input.OriginalFileName),
		strings.TrimSpace(input.StoredFileName),
		strings.TrimSpace(input.StoragePath),
		NormalizeConstant(input.MediaType),
		strings.TrimSpace(input.MimeType),
		input.FileExtension,
		input.FileSizeBytes,
		strings.ToLower(
			strings.TrimSpace(input.FileHash),
		),
		mediaAssetHashAlgorithmSHA256,
		input.IsEncrypted,
		input.EncryptionAlgorithm,
		sourceType,
		mediaAssetStatusAvailable,
		input.UploadedBy,
		metadataJSON,
		now,
	)

	asset, err := scanMediaAnalysisAsset(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrMediaAssetConflict
		}

		return nil, fmt.Errorf(
			"create media analysis asset: %w",
			err,
		)
	}

	return asset, nil
}

// GetMediaAsset returns one non-deleted media asset
// belonging to the supplied organization.
func (r *Repository) GetMediaAsset(
	ctx context.Context,
	organizationID uuid.UUID,
	assetID uuid.UUID,
) (*MediaAnalysisAsset, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}

	if ctx == nil ||
		organizationID == uuid.Nil ||
		assetID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	query := `
		SELECT
			id,
			asset_sequence,
			asset_code,
			organization_id,
			department_id,
			incident_id,
			evidence_id,
			evidence_file_id,
			original_file_name,
			stored_file_name,
			storage_path,
			media_type,
			mime_type,
			file_extension,
			file_size_bytes,
			file_hash,
			hash_algorithm,
			is_encrypted,
			encryption_algorithm,
			source_type,
			status,
			uploaded_by,
			metadata,
			uploaded_at,
			analyzed_at,
			created_at,
			updated_at,
			deleted_at
		FROM media_analysis_assets
		WHERE organization_id = $1
			AND id = $2
			AND deleted_at IS NULL
	`

	asset, err := scanMediaAnalysisAsset(
		r.databasePool.QueryRow(
			ctx,
			query,
			organizationID,
			assetID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrMediaAssetNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"get media analysis asset: %w",
			err,
		)
	}

	return asset, nil
}

// ListMediaAssets returns organization-scoped media
// assets and their total count using safe fixed filters.
func (r *Repository) ListMediaAssets(
	ctx context.Context,
	organizationID uuid.UUID,
	filter MediaAssetListFilter,
) ([]MediaAnalysisAsset, int64, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, 0, err
	}

	if ctx == nil || organizationID == uuid.Nil {
		return nil, 0, ErrInvalidRepositoryInput
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	conditions := []string{
		"organization_id = $1",
		"deleted_at IS NULL",
	}
	arguments := []any{
		organizationID,
	}

	addFilter := func(
		condition string,
		value any,
	) {
		arguments = append(arguments, value)
		conditions = append(
			conditions,
			fmt.Sprintf(
				condition,
				len(arguments),
			),
		)
	}

	if mediaType := NormalizeConstant(
		filter.MediaType,
	); mediaType != "" {
		addFilter(
			"media_type = $%d",
			mediaType,
		)
	}

	if status := NormalizeConstant(
		filter.Status,
	); status != "" {
		addFilter(
			"status = $%d",
			status,
		)
	}

	if sourceType := NormalizeConstant(
		filter.SourceType,
	); sourceType != "" {
		addFilter(
			"source_type = $%d",
			sourceType,
		)
	}

	if filter.IncidentID != nil {
		addFilter(
			"incident_id = $%d",
			*filter.IncidentID,
		)
	}

	if filter.UploadedBy != nil {
		addFilter(
			"uploaded_by = $%d",
			*filter.UploadedBy,
		)
	}

	if filter.CreatedFrom != nil {
		addFilter(
			"created_at >= $%d",
			filter.CreatedFrom.UTC(),
		)
	}

	if filter.CreatedTo != nil {
		addFilter(
			"created_at <= $%d",
			filter.CreatedTo.UTC(),
		)
	}

	arguments = append(arguments, limit)
	limitPlaceholder := len(arguments)
	arguments = append(arguments, offset)
	offsetPlaceholder := len(arguments)

	query := fmt.Sprintf(
		`
			SELECT
				id,
				asset_sequence,
				asset_code,
				organization_id,
				department_id,
				incident_id,
				evidence_id,
				evidence_file_id,
				original_file_name,
				stored_file_name,
				storage_path,
				media_type,
				mime_type,
				file_extension,
				file_size_bytes,
				file_hash,
				hash_algorithm,
				is_encrypted,
				encryption_algorithm,
				source_type,
				status,
				uploaded_by,
				metadata,
				uploaded_at,
				analyzed_at,
				created_at,
				updated_at,
				deleted_at,
				COUNT(*) OVER()
			FROM media_analysis_assets
			WHERE %s
			ORDER BY created_at DESC, id DESC
			LIMIT $%d
			OFFSET $%d
		`,
		strings.Join(conditions, " AND "),
		limitPlaceholder,
		offsetPlaceholder,
	)

	rows, err := r.databasePool.Query(
		ctx,
		query,
		arguments...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"list media analysis assets: %w",
			err,
		)
	}
	defer rows.Close()

	items := make(
		[]MediaAnalysisAsset,
		0,
		limit,
	)
	var total int64

	for rows.Next() {
		var rowTotal int64

		asset, scanErr := scanMediaAnalysisAsset(
			rows,
			&rowTotal,
		)
		if scanErr != nil {
			return nil, 0, fmt.Errorf(
				"scan media analysis asset: %w",
				scanErr,
			)
		}

		total = rowTotal
		items = append(items, *asset)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"iterate media analysis assets: %w",
			err,
		)
	}

	return items, total, nil
}

func validateCreateMediaAssetInput(
	ctx context.Context,
	input CreateMediaAssetInput,
) error {
	if ctx == nil ||
		input.OrganizationID == uuid.Nil ||
		input.UploadedBy == uuid.Nil ||
		strings.TrimSpace(input.OriginalFileName) == "" ||
		strings.TrimSpace(input.StoredFileName) == "" ||
		strings.TrimSpace(input.StoragePath) == "" ||
		!IsSupportedMediaType(input.MediaType) ||
		strings.TrimSpace(input.MimeType) == "" ||
		input.FileSizeBytes <= 0 ||
		strings.TrimSpace(input.FileHash) == "" {
		return ErrInvalidRepositoryInput
	}

	return nil
}

func buildMediaAssetCode(
	assetID uuid.UUID,
	now time.Time,
) string {
	return fmt.Sprintf(
		"DDH-MEDIA-%s-%s",
		now.UTC().Format("20060102"),
		strings.ToUpper(
			strings.ReplaceAll(
				assetID.String()[:8],
				"-",
				"",
			),
		),
	)
}

func scanMediaAnalysisAsset(
	scanner databaseRowScanner,
	additionalDestinations ...any,
) (*MediaAnalysisAsset, error) {
	if scanner == nil {
		return nil, ErrRepositoryUnavailable
	}

	asset := &MediaAnalysisAsset{}
	var metadataJSON []byte

	destinations := []any{
		&asset.ID,
		&asset.AssetSequence,
		&asset.AssetCode,
		&asset.OrganizationID,
		&asset.DepartmentID,
		&asset.IncidentID,
		&asset.EvidenceID,
		&asset.EvidenceFileID,
		&asset.OriginalFileName,
		&asset.StoredFileName,
		&asset.StoragePath,
		&asset.MediaType,
		&asset.MimeType,
		&asset.FileExtension,
		&asset.FileSizeBytes,
		&asset.FileHash,
		&asset.HashAlgorithm,
		&asset.IsEncrypted,
		&asset.EncryptionAlgorithm,
		&asset.SourceType,
		&asset.Status,
		&asset.UploadedBy,
		&metadataJSON,
		&asset.UploadedAt,
		&asset.AnalyzedAt,
		&asset.CreatedAt,
		&asset.UpdatedAt,
		&asset.DeletedAt,
	}
	destinations = append(
		destinations,
		additionalDestinations...,
	)

	if err := scanner.Scan(
		destinations...,
	); err != nil {
		return nil, err
	}

	asset.Metadata = map[string]any{}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(
			metadataJSON,
			&asset.Metadata,
		); err != nil {
			return nil, fmt.Errorf(
				"decode media asset metadata: %w",
				err,
			)
		}
	}

	return asset, nil
}

func isUniqueViolation(err error) bool {
	var postgresError *pgconn.PgError

	return errors.As(err, &postgresError) &&
		postgresError.Code == "23505"
}
