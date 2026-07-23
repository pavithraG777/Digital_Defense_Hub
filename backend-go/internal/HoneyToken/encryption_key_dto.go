package honeytoken

// CreateEncryptionKeyRequest represents a request to create
// a new encryption key.
type CreateEncryptionKeyRequest struct {
	KeyName string `json:"key_name" binding:"required"`
	Purpose string `json:"purpose" binding:"required"`
}

// CreateEncryptionKeyResponse represents the response after
// successfully creating an encryption key.
type CreateEncryptionKeyResponse struct {
	ID            string `json:"id"`
	KeyName       string `json:"key_name"`
	KeyIdentifier string `json:"key_identifier"`

	Algorithm string `json:"algorithm"`
	KeySize   int    `json:"key_size"`
	Purpose   string `json:"purpose"`
	Status    string `json:"status"`

	ActivatedAt string `json:"activated_at,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// GetEncryptionKeyResponse represents one encryption key.
type GetEncryptionKeyResponse struct {
	ID            string `json:"id"`
	KeyName       string `json:"key_name"`
	KeyIdentifier string `json:"key_identifier"`

	Algorithm string `json:"algorithm"`
	KeySize   int    `json:"key_size"`
	Purpose   string `json:"purpose"`
	Status    string `json:"status"`

	ActivatedAt string `json:"activated_at,omitempty"`
	ExpiredAt   string `json:"expired_at,omitempty"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}
