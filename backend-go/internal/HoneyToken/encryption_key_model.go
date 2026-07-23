package honeytoken

import (
	"time"

	"github.com/google/uuid"
)

// EncryptionKey stores the metadata and encrypted form of
// an AES encryption key used for protected files.
type EncryptionKey struct {
	ID uuid.UUID `json:"id"`

	OrganizationID uuid.UUID `json:"organization_id"`

	KeyName       string `json:"key_name"`
	KeyIdentifier string `json:"key_identifier"`

	// EncryptedKey contains the encrypted AES key.
	// The raw encryption key must never be stored directly.
	EncryptedKey []byte `json:"-"`

	Algorithm string `json:"algorithm"`
	KeySize   int    `json:"key_size"`
	Purpose   string `json:"purpose"`
	Status    string `json:"status"`

	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	ExpiredAt   *time.Time `json:"expired_at,omitempty"`

	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}
