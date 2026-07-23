package honeytoken

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrEncryptionKeyNotFound = errors.New("encryption key not found")
)

func (r *Repository) CreateEncryptionKey(
	ctx context.Context,
	key *EncryptionKey,
) error {

	if key == nil {
		return fmt.Errorf("encryption key is required")
	}

	if key.ID == uuid.Nil {
		return fmt.Errorf("encryption key ID is required")
	}

	if key.OrganizationID == uuid.Nil {
		return fmt.Errorf("organization ID is required")
	}

	if key.KeyName == "" {
		return fmt.Errorf("key name is required")
	}

	if key.KeyIdentifier == "" {
		return fmt.Errorf("key identifier is required")
	}

	if len(key.EncryptedKey) == 0 {
		return fmt.Errorf("encrypted key is required")
	}

	const query = `
	INSERT INTO encryption_keys (
		id,
		organization_id,
		key_name,
		key_identifier,
		encrypted_key,
		algorithm,
		key_size,
		purpose,
		status,
		activated_at,
		created_at,
		updated_at
	)
	VALUES (
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
		CURRENT_TIMESTAMP,
		CURRENT_TIMESTAMP
	);
	`

	_, err := r.db.Exec(
		ctx,
		query,
		key.ID,
		key.OrganizationID,
		key.KeyName,
		key.KeyIdentifier,
		key.EncryptedKey,
		key.Algorithm,
		key.KeySize,
		key.Purpose,
		key.Status,
		key.ActivatedAt,
	)

	if err != nil {
		return fmt.Errorf(
			"failed to create encryption key: %w",
			err,
		)
	}

	return nil
}

func (r *Repository) FindActiveEncryptionKey(
	ctx context.Context,
	organizationID uuid.UUID,
) (*EncryptionKey, error) {

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf("organization ID is required")
	}

	const query = `
	SELECT
		id,
		organization_id,
		key_name,
		key_identifier,
		encrypted_key,
		algorithm,
		key_size,
		purpose,
		status,
		activated_at,
		expired_at,
		created_at,
		updated_at,
		deleted_at
	FROM encryption_keys
	WHERE
		organization_id = $1
		AND status = 'ACTIVE'
		AND deleted_at IS NULL
	ORDER BY
		activated_at DESC
	LIMIT 1;
	`

	var key EncryptionKey

	err := r.db.QueryRow(
		ctx,
		query,
		organizationID,
	).Scan(
		&key.ID,
		&key.OrganizationID,
		&key.KeyName,
		&key.KeyIdentifier,
		&key.EncryptedKey,
		&key.Algorithm,
		&key.KeySize,
		&key.Purpose,
		&key.Status,
		&key.ActivatedAt,
		&key.ExpiredAt,
		&key.CreatedAt,
		&key.UpdatedAt,
		&key.DeletedAt,
	)

	if err != nil {

		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrEncryptionKeyNotFound
		}

		return nil, fmt.Errorf(
			"failed to fetch active encryption key: %w",
			err,
		)
	}

	return &key, nil
}

func (r *Repository) DeactivateEncryptionKeys(
	ctx context.Context,
	organizationID uuid.UUID,
) error {

	if organizationID == uuid.Nil {
		return fmt.Errorf("organization ID is required")
	}

	const query = `
	UPDATE encryption_keys
	SET
		status='INACTIVE',
		expired_at=CURRENT_TIMESTAMP,
		updated_at=CURRENT_TIMESTAMP
	WHERE
		organization_id=$1
		AND status='ACTIVE';
	`

	_, err := r.db.Exec(
		ctx,
		query,
		organizationID,
	)

	if err != nil {
		return fmt.Errorf(
			"failed to deactivate encryption keys: %w",
			err,
		)
	}

	return nil
}

// FindEncryptionKeyByID returns one organization-owned encryption key.
//
// The query intentionally allows ACTIVE and INACTIVE keys because files
// encrypted before key rotation must still be restorable with their
// original encryption key.
func (r *Repository) FindEncryptionKeyByID(
	ctx context.Context,
	organizationID uuid.UUID,
	encryptionKeyID uuid.UUID,
) (*EncryptionKey, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf(
			"encryption key repository is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"organization ID is required",
		)
	}

	if encryptionKeyID == uuid.Nil {
		return nil, fmt.Errorf(
			"encryption key ID is required",
		)
	}

	const query = `
	SELECT
		id,
		organization_id,
		key_name,
		key_identifier,
		encrypted_key,
		algorithm,
		key_size,
		purpose,
		status,
		activated_at,
		expired_at,
		created_at,
		updated_at,
		deleted_at
	FROM encryption_keys
	WHERE
		id = $1
		AND organization_id = $2
		AND deleted_at IS NULL
	LIMIT 1;
	`

	var key EncryptionKey

	err := r.db.QueryRow(
		ctx,
		query,
		encryptionKeyID,
		organizationID,
	).Scan(
		&key.ID,
		&key.OrganizationID,
		&key.KeyName,
		&key.KeyIdentifier,
		&key.EncryptedKey,
		&key.Algorithm,
		&key.KeySize,
		&key.Purpose,
		&key.Status,
		&key.ActivatedAt,
		&key.ExpiredAt,
		&key.CreatedAt,
		&key.UpdatedAt,
		&key.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrEncryptionKeyNotFound
		}

		return nil, fmt.Errorf(
			"failed to fetch encryption key: %w",
			err,
		)
	}

	return &key, nil
}
