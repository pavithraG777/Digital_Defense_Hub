package honeytoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrIncidentEvidenceNotFound = errors.New(
		"incident evidence not found",
	)
	ErrIncidentEvidenceCodeExists = errors.New(
		"incident evidence code already exists",
	)
	ErrIncidentEvidenceReferenceNotFound = errors.New(
		"incident evidence reference not found",
	)
)

const incidentEvidenceSelectColumns = `
	id,
	incident_id,
	organization_id,
	evidence_code,
	evidence_type,
	evidence_name,
	description,
	threat_id,
	file_event_id,
	protected_file_id,
	honeytoken_id,
	canary_file_id,
	storage_path,
	original_file_name,
	mime_type,
	file_size_bytes,
	evidence_hash,
	hash_algorithm,
	integrity_status,
	is_immutable,
	collected_by,
	verified_by,
	collected_at,
	verified_at,
	metadata,
	created_at,
	updated_at,
	deleted_at
`

// CreateEvidence inserts forensic evidence, marks evidence as preserved and
// adds an immutable incident timeline entry in one transaction.
func (r *IncidentRepository) CreateEvidence(
	ctx context.Context,
	evidence *IncidentEvidence,
	actorUserID uuid.UUID,
) error {
	if r == nil || r.db == nil {
		return errors.New(
			"incident repository is unavailable",
		)
	}

	if evidence == nil {
		return errors.New(
			"incident evidence is required",
		)
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"begin incident evidence transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	_, err = findIncidentForUpdateTx(
		ctx,
		tx,
		evidence.OrganizationID,
		evidence.IncidentID,
	)
	if err != nil {
		return err
	}

	err = validateIncidentEvidenceReferencesTx(
		ctx,
		tx,
		evidence,
	)
	if err != nil {
		return err
	}

	metadata := evidence.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}

	const query = `
		INSERT INTO incident_evidence (
			id,
			incident_id,
			organization_id,
			evidence_code,
			evidence_type,
			evidence_name,
			description,
			threat_id,
			file_event_id,
			protected_file_id,
			honeytoken_id,
			canary_file_id,
			storage_path,
			original_file_name,
			mime_type,
			file_size_bytes,
			evidence_hash,
			hash_algorithm,
			integrity_status,
			is_immutable,
			collected_by,
			verified_by,
			collected_at,
			verified_at,
			metadata
		)
		VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
			$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
			$21,$22,$23,$24,$25
		)
		RETURNING
			created_at,
			updated_at;
	`

	err = tx.QueryRow(
		ctx,
		query,
		evidence.ID,
		evidence.IncidentID,
		evidence.OrganizationID,
		evidence.EvidenceCode,
		evidence.EvidenceType,
		evidence.EvidenceName,
		evidence.Description,
		evidence.ThreatID,
		evidence.FileEventID,
		evidence.ProtectedFileID,
		evidence.HoneytokenID,
		evidence.CanaryFileID,
		evidence.StoragePath,
		evidence.OriginalFileName,
		evidence.MimeType,
		evidence.FileSizeBytes,
		evidence.EvidenceHash,
		evidence.HashAlgorithm,
		evidence.IntegrityStatus,
		evidence.IsImmutable,
		evidence.CollectedBy,
		evidence.VerifiedBy,
		evidence.CollectedAt,
		evidence.VerifiedAt,
		metadata,
	).Scan(
		&evidence.CreatedAt,
		&evidence.UpdatedAt,
	)
	if err != nil {
		if isIncidentConstraintViolation(
			err,
			"uq_incident_evidence_code",
		) {
			return ErrIncidentEvidenceCodeExists
		}

		return fmt.Errorf(
			"create incident evidence: %w",
			err,
		)
	}

	_, err = tx.Exec(
		ctx,
		`
			UPDATE incidents
			SET
				evidence_preserved = true,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = $1
			  AND organization_id = $2
			  AND deleted_at IS NULL;
		`,
		evidence.IncidentID,
		evidence.OrganizationID,
	)
	if err != nil {
		return fmt.Errorf(
			"mark incident evidence preserved: %w",
			err,
		)
	}

	timelineMetadata, err := json.Marshal(
		map[string]any{
			"evidence_id":   evidence.ID.String(),
			"evidence_code": evidence.EvidenceCode,
			"evidence_type": evidence.EvidenceType,
			"evidence_name": evidence.EvidenceName,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"build evidence timeline metadata: %w",
			err,
		)
	}

	err = insertIncidentTimelineTx(
		ctx,
		tx,
		&IncidentTimelineEntry{
			ID:             uuid.New(),
			IncidentID:     evidence.IncidentID,
			OrganizationID: evidence.OrganizationID,
			EventType:      IncidentTimelineEventEvidenceAdded,
			Title:          "Incident evidence added",
			Description:    evidence.Description,
			ActorUserID: incidentUUIDPointer(
				actorUserID,
			),
			Metadata:   timelineMetadata,
			OccurredAt: evidence.CollectedAt,
		},
	)
	if err != nil {
		return err
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit incident evidence transaction: %w",
			err,
		)
	}

	evidence.Metadata = metadata

	return nil
}

// FindEvidenceByID returns organization-scoped evidence.
func (r *IncidentRepository) FindEvidenceByID(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
	evidenceID uuid.UUID,
) (*IncidentEvidence, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"incident repository is unavailable",
		)
	}

	query := `
		SELECT ` + incidentEvidenceSelectColumns + `
		FROM incident_evidence
		WHERE id = $1
		  AND incident_id = $2
		  AND organization_id = $3
		  AND deleted_at IS NULL;
	`

	evidence, err := scanIncidentEvidence(
		r.db.QueryRow(
			ctx,
			query,
			evidenceID,
			incidentID,
			organizationID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrIncidentEvidenceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"find incident evidence: %w",
			err,
		)
	}

	return evidence, nil
}

// ListEvidence returns paginated evidence belonging to an incident.
func (r *IncidentRepository) ListEvidence(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
	evidenceType string,
	integrityStatus string,
	limit int,
	offset int,
) ([]IncidentEvidence, int64, error) {
	if r == nil || r.db == nil {
		return nil, 0, errors.New(
			"incident repository is unavailable",
		)
	}

	if _, err := r.FindByID(
		ctx,
		organizationID,
		incidentID,
	); err != nil {
		return nil, 0, err
	}

	args := []any{
		incidentID,
		organizationID,
	}

	conditions := `
		incident_id = $1
		AND organization_id = $2
		AND deleted_at IS NULL
	`

	if evidenceType != "" {
		args = append(
			args,
			evidenceType,
		)

		conditions += fmt.Sprintf(
			" AND evidence_type = $%d",
			len(args),
		)
	}

	if integrityStatus != "" {
		args = append(
			args,
			integrityStatus,
		)

		conditions += fmt.Sprintf(
			" AND integrity_status = $%d",
			len(args),
		)
	}

	countQuery := `
		SELECT COUNT(*)
		FROM incident_evidence
		WHERE ` + conditions + `;
	`

	var total int64

	err := r.db.QueryRow(
		ctx,
		countQuery,
		args...,
	).Scan(
		&total,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"count incident evidence: %w",
			err,
		)
	}

	listArgs := append(
		[]any(nil),
		args...,
	)

	listArgs = append(
		listArgs,
		limit,
		offset,
	)

	limitPosition := len(listArgs) - 1
	offsetPosition := len(listArgs)

	listQuery := `
		SELECT ` + incidentEvidenceSelectColumns + `
		FROM incident_evidence
		WHERE ` + conditions + `
		ORDER BY collected_at DESC, created_at DESC
		LIMIT $` + fmt.Sprint(limitPosition) + `
		OFFSET $` + fmt.Sprint(offsetPosition) + `;
	`

	rows, err := r.db.Query(
		ctx,
		listQuery,
		listArgs...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"list incident evidence: %w",
			err,
		)
	}
	defer rows.Close()

	evidenceItems := make(
		[]IncidentEvidence,
		0,
	)

	for rows.Next() {
		evidence, scanErr := scanIncidentEvidence(
			rows,
		)
		if scanErr != nil {
			return nil, 0, fmt.Errorf(
				"scan incident evidence: %w",
				scanErr,
			)
		}

		evidenceItems = append(
			evidenceItems,
			*evidence,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"iterate incident evidence: %w",
			err,
		)
	}

	return evidenceItems, total, nil
}

// VerifyEvidence records the latest evidence integrity verification result.
func (r *IncidentRepository) VerifyEvidence(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
	evidenceID uuid.UUID,
	integrityStatus string,
	verifiedBy uuid.UUID,
) (*IncidentEvidence, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"incident repository is unavailable",
		)
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"begin evidence verification transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	evidence, err := findIncidentEvidenceForUpdateTx(
		ctx,
		tx,
		organizationID,
		incidentID,
		evidenceID,
	)
	if err != nil {
		return nil, err
	}

	query := `
		UPDATE incident_evidence
		SET
			integrity_status = $4::varchar,
			verified_by = $5,
			verified_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
		  AND incident_id = $2
		  AND organization_id = $3
		  AND deleted_at IS NULL
		RETURNING ` + incidentEvidenceSelectColumns + `;
	`

	verifiedEvidence, err := scanIncidentEvidence(
		tx.QueryRow(
			ctx,
			query,
			evidenceID,
			incidentID,
			organizationID,
			integrityStatus,
			verifiedBy,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrIncidentEvidenceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"verify incident evidence: %w",
			err,
		)
	}

	timelineMetadata, err := json.Marshal(
		map[string]any{
			"evidence_id":      evidence.ID.String(),
			"evidence_code":    evidence.EvidenceCode,
			"integrity_status": integrityStatus,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"build verification timeline metadata: %w",
			err,
		)
	}

	title := "Evidence integrity verified"

	if integrityStatus ==
		IncidentEvidenceIntegrityMismatch {
		title = "Evidence integrity mismatch detected"
	}

	err = insertIncidentTimelineTx(
		ctx,
		tx,
		&IncidentTimelineEntry{
			ID:             uuid.New(),
			IncidentID:     incidentID,
			OrganizationID: organizationID,
			EventType:      IncidentTimelineEventSystemAction,
			Title:          title,
			ActorUserID: incidentUUIDPointer(
				verifiedBy,
			),
			Metadata:   timelineMetadata,
			OccurredAt: time.Now().UTC(),
		},
	)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit evidence verification transaction: %w",
			err,
		)
	}

	return verifiedEvidence, nil
}

func validateIncidentEvidenceReferencesTx(
	ctx context.Context,
	tx pgx.Tx,
	evidence *IncidentEvidence,
) error {
	var (
		threatValid        bool
		fileEventValid     bool
		protectedFileValid bool
		honeytokenValid    bool
		canaryFileValid    bool
	)

	const query = `
		SELECT
			(
				$1::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM threats
					WHERE id = $1
					  AND organization_id = $6
					  AND deleted_at IS NULL
				)
			),
			(
				$2::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM file_events
					WHERE id = $2
					  AND organization_id = $6
				)
			),
			(
				$3::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM protected_files
					WHERE id = $3
					  AND organization_id = $6
				)
			),
			(
				$4::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM honeytokens
					WHERE id = $4
					  AND organization_id = $6
					  AND deleted_at IS NULL
				)
			),
			(
				$5::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM canary_files
					WHERE id = $5
					  AND organization_id = $6
					  AND deleted_at IS NULL
				)
			);
	`

	err := tx.QueryRow(
		ctx,
		query,
		evidence.ThreatID,
		evidence.FileEventID,
		evidence.ProtectedFileID,
		evidence.HoneytokenID,
		evidence.CanaryFileID,
		evidence.OrganizationID,
	).Scan(
		&threatValid,
		&fileEventValid,
		&protectedFileValid,
		&honeytokenValid,
		&canaryFileValid,
	)
	if err != nil {
		return fmt.Errorf(
			"validate incident evidence references: %w",
			err,
		)
	}

	if !threatValid ||
		!fileEventValid ||
		!protectedFileValid ||
		!honeytokenValid ||
		!canaryFileValid {
		return ErrIncidentEvidenceReferenceNotFound
	}

	return nil
}

func findIncidentEvidenceForUpdateTx(
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
	evidenceID uuid.UUID,
) (*IncidentEvidence, error) {
	query := `
		SELECT ` + incidentEvidenceSelectColumns + `
		FROM incident_evidence
		WHERE id = $1
		  AND incident_id = $2
		  AND organization_id = $3
		  AND deleted_at IS NULL
		FOR UPDATE;
	`

	evidence, err := scanIncidentEvidence(
		tx.QueryRow(
			ctx,
			query,
			evidenceID,
			incidentID,
			organizationID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrIncidentEvidenceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"lock incident evidence: %w",
			err,
		)
	}

	return evidence, nil
}

func scanIncidentEvidence(
	scanner incidentScanner,
) (*IncidentEvidence, error) {
	evidence := &IncidentEvidence{}

	err := scanner.Scan(
		&evidence.ID,
		&evidence.IncidentID,
		&evidence.OrganizationID,
		&evidence.EvidenceCode,
		&evidence.EvidenceType,
		&evidence.EvidenceName,
		&evidence.Description,
		&evidence.ThreatID,
		&evidence.FileEventID,
		&evidence.ProtectedFileID,
		&evidence.HoneytokenID,
		&evidence.CanaryFileID,
		&evidence.StoragePath,
		&evidence.OriginalFileName,
		&evidence.MimeType,
		&evidence.FileSizeBytes,
		&evidence.EvidenceHash,
		&evidence.HashAlgorithm,
		&evidence.IntegrityStatus,
		&evidence.IsImmutable,
		&evidence.CollectedBy,
		&evidence.VerifiedBy,
		&evidence.CollectedAt,
		&evidence.VerifiedAt,
		&evidence.Metadata,
		&evidence.CreatedAt,
		&evidence.UpdatedAt,
		&evidence.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	return evidence, nil
}
