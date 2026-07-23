package honeytoken

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	managedEncryptionKeySize       = 32
	managedEncryptionKeySizeInBits = 256
	encryptedKeyEnvelopeVersion    = byte(1)
	encryptionKeyStatusActive      = "ACTIVE"
)

var (
	ErrEncryptionKeyServiceUnavailable = errors.New(
		"encryption key service is unavailable",
	)
	ErrInvalidMasterEncryptionKey = errors.New(
		"master encryption key must contain exactly 32 bytes",
	)
	ErrManagedEncryptionKeyCorrupted = errors.New(
		"managed encryption key data is invalid or corrupted",
	)
)

// EncryptionKeyService creates and resolves organization-specific
// AES-256 keys without exposing their raw values through API responses.
type EncryptionKeyService struct {
	repository *Repository
	masterKey  []byte
}

func NewEncryptionKeyService(
	repository *Repository,
	masterKey []byte,
) (*EncryptionKeyService, error) {
	if repository == nil {
		return nil, fmt.Errorf(
			"encryption key repository is required",
		)
	}

	if len(masterKey) != managedEncryptionKeySize {
		return nil, ErrInvalidMasterEncryptionKey
	}

	masterKeyCopy := make(
		[]byte,
		len(masterKey),
	)

	copy(
		masterKeyCopy,
		masterKey,
	)

	return &EncryptionKeyService{
		repository: repository,
		masterKey:  masterKeyCopy,
	}, nil
}

// CreateEncryptionKey generates a new organization-specific AES-256 key,
// encrypts it with the server master key and stores only the encrypted value.
func (s *EncryptionKeyService) CreateEncryptionKey(
	ctx context.Context,
	organizationID uuid.UUID,
	req CreateEncryptionKeyRequest,
) (*CreateEncryptionKeyResponse, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	if err := validateEncryptionKeyContext(ctx); err != nil {
		return nil, err
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf("organization ID is required")
	}

	if err := validateCreateEncryptionKeyRequest(req); err != nil {
		return nil, err
	}

	keyID := uuid.New()
	keyIdentifier := "ddh-file-key-" + keyID.String()

	rawKey, err := generateManagedEncryptionKey()
	if err != nil {
		return nil, err
	}
	defer clear(rawKey)

	encryptedKey, err := s.encryptManagedKey(
		rawKey,
		organizationID,
		keyIdentifier,
	)
	if err != nil {
		return nil, err
	}
	defer clear(encryptedKey)

	now := time.Now().UTC()

	key := &EncryptionKey{
		ID:             keyID,
		OrganizationID: organizationID,
		KeyName: strings.TrimSpace(
			req.KeyName,
		),
		KeyIdentifier: keyIdentifier,
		EncryptedKey:  encryptedKey,
		Algorithm:     EncryptionAlgorithmAES256,
		KeySize:       managedEncryptionKeySizeInBits,
		Purpose: strings.ToUpper(
			strings.TrimSpace(req.Purpose),
		),
		Status:      encryptionKeyStatusActive,
		ActivatedAt: &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.repository.CreateEncryptionKey(
		ctx,
		key,
	); err != nil {
		return nil, fmt.Errorf(
			"failed to create encryption key: %w",
			err,
		)
	}

	return buildCreateEncryptionKeyResponse(key), nil
}

// GetActiveEncryptionKey returns safe metadata for the organization's
// currently active key. The encrypted and raw key values are never returned.
func (s *EncryptionKeyService) GetActiveEncryptionKey(
	ctx context.Context,
	organizationID uuid.UUID,
) (*GetEncryptionKeyResponse, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	if err := validateEncryptionKeyContext(ctx); err != nil {
		return nil, err
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf("organization ID is required")
	}

	key, err := s.repository.FindActiveEncryptionKey(
		ctx,
		organizationID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get active encryption key: %w",
			err,
		)
	}

	if key == nil {
		return nil, ErrEncryptionKeyNotFound
	}

	return buildGetEncryptionKeyResponse(key), nil
}

// ResolveActiveEncryptionKey decrypts the organization's active key for
// internal file-protection use. Callers must clear the returned byte slice
// immediately after constructing the required encryption operation.
func (s *EncryptionKeyService) ResolveActiveEncryptionKey(
	ctx context.Context,
	organizationID uuid.UUID,
) ([]byte, string, error) {
	if err := s.validate(); err != nil {
		return nil, "", err
	}

	if err := validateEncryptionKeyContext(ctx); err != nil {
		return nil, "", err
	}

	if organizationID == uuid.Nil {
		return nil, "", fmt.Errorf(
			"organization ID is required",
		)
	}

	key, err := s.repository.FindActiveEncryptionKey(
		ctx,
		organizationID,
	)
	if err != nil {
		return nil, "", fmt.Errorf(
			"failed to resolve active encryption key: %w",
			err,
		)
	}

	if key == nil {
		return nil, "", ErrEncryptionKeyNotFound
	}

	rawKey, err := s.decryptManagedKey(
		key.EncryptedKey,
		key.OrganizationID,
		key.KeyIdentifier,
	)
	if err != nil {
		return nil, "", err
	}

	return rawKey, key.KeyIdentifier, nil
}

func (s *EncryptionKeyService) validate() error {
	if s == nil || s.repository == nil {
		return ErrEncryptionKeyServiceUnavailable
	}

	if len(s.masterKey) != managedEncryptionKeySize {
		return ErrInvalidMasterEncryptionKey
	}

	return nil
}

func validateEncryptionKeyContext(
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

func validateCreateEncryptionKeyRequest(
	req CreateEncryptionKeyRequest,
) error {
	if strings.TrimSpace(req.KeyName) == "" {
		return fmt.Errorf("key name is required")
	}

	if strings.TrimSpace(req.Purpose) == "" {
		return fmt.Errorf("key purpose is required")
	}

	return nil
}

func generateManagedEncryptionKey() ([]byte, error) {
	key := make(
		[]byte,
		managedEncryptionKeySize,
	)

	if _, err := io.ReadFull(
		rand.Reader,
		key,
	); err != nil {
		clear(key)

		return nil, fmt.Errorf(
			"failed to generate encryption key: %w",
			err,
		)
	}

	return key, nil
}

func (s *EncryptionKeyService) encryptManagedKey(
	rawKey []byte,
	organizationID uuid.UUID,
	keyIdentifier string,
) ([]byte, error) {
	if len(rawKey) != managedEncryptionKeySize {
		return nil, ErrManagedEncryptionKeyCorrupted
	}

	gcm, err := newMasterKeyGCM(s.masterKey)
	if err != nil {
		return nil, err
	}

	nonce := make(
		[]byte,
		gcm.NonceSize(),
	)

	if _, err := io.ReadFull(
		rand.Reader,
		nonce,
	); err != nil {
		return nil, fmt.Errorf(
			"failed to generate encryption key nonce: %w",
			err,
		)
	}

	authenticatedData := buildEncryptionKeyAuthenticatedData(
		organizationID,
		keyIdentifier,
	)

	cipherText := gcm.Seal(
		nil,
		nonce,
		rawKey,
		authenticatedData,
	)

	envelope := make(
		[]byte,
		0,
		1+len(nonce)+len(cipherText),
	)

	envelope = append(
		envelope,
		encryptedKeyEnvelopeVersion,
	)

	envelope = append(
		envelope,
		nonce...,
	)

	envelope = append(
		envelope,
		cipherText...,
	)

	return envelope, nil
}

func (s *EncryptionKeyService) decryptManagedKey(
	envelope []byte,
	organizationID uuid.UUID,
	keyIdentifier string,
) ([]byte, error) {
	gcm, err := newMasterKeyGCM(s.masterKey)
	if err != nil {
		return nil, err
	}

	minimumEnvelopeSize := 1 +
		gcm.NonceSize() +
		gcm.Overhead()

	if len(envelope) < minimumEnvelopeSize ||
		envelope[0] != encryptedKeyEnvelopeVersion {
		return nil, ErrManagedEncryptionKeyCorrupted
	}

	nonceStart := 1
	nonceEnd := nonceStart + gcm.NonceSize()

	nonce := envelope[nonceStart:nonceEnd]
	cipherText := envelope[nonceEnd:]

	authenticatedData := buildEncryptionKeyAuthenticatedData(
		organizationID,
		keyIdentifier,
	)

	rawKey, err := gcm.Open(
		nil,
		nonce,
		cipherText,
		authenticatedData,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %v",
			ErrManagedEncryptionKeyCorrupted,
			err,
		)
	}

	if len(rawKey) != managedEncryptionKeySize {
		clear(rawKey)

		return nil, ErrManagedEncryptionKeyCorrupted
	}

	return rawKey, nil
}

func newMasterKeyGCM(
	masterKey []byte,
) (cipher.AEAD, error) {
	if len(masterKey) != managedEncryptionKeySize {
		return nil, ErrInvalidMasterEncryptionKey
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to initialize master key cipher: %w",
			err,
		)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to initialize master key GCM: %w",
			err,
		)
	}

	return gcm, nil
}

func buildEncryptionKeyAuthenticatedData(
	organizationID uuid.UUID,
	keyIdentifier string,
) []byte {
	return []byte(
		organizationID.String() +
			":" +
			strings.TrimSpace(keyIdentifier),
	)
}

func buildCreateEncryptionKeyResponse(
	key *EncryptionKey,
) *CreateEncryptionKeyResponse {
	response := &CreateEncryptionKeyResponse{
		ID:            key.ID.String(),
		KeyName:       key.KeyName,
		KeyIdentifier: key.KeyIdentifier,
		Algorithm:     key.Algorithm,
		KeySize:       key.KeySize,
		Purpose:       key.Purpose,
		Status:        key.Status,
		CreatedAt: key.CreatedAt.
			UTC().
			Format(time.RFC3339),
	}

	if key.ActivatedAt != nil {
		response.ActivatedAt = key.ActivatedAt.
			UTC().
			Format(time.RFC3339)
	}

	return response
}

func buildGetEncryptionKeyResponse(
	key *EncryptionKey,
) *GetEncryptionKeyResponse {
	response := &GetEncryptionKeyResponse{
		ID:            key.ID.String(),
		KeyName:       key.KeyName,
		KeyIdentifier: key.KeyIdentifier,
		Algorithm:     key.Algorithm,
		KeySize:       key.KeySize,
		Purpose:       key.Purpose,
		Status:        key.Status,
		CreatedAt: key.CreatedAt.
			UTC().
			Format(time.RFC3339),
		UpdatedAt: key.UpdatedAt.
			UTC().
			Format(time.RFC3339),
	}

	if key.ActivatedAt != nil {
		response.ActivatedAt = key.ActivatedAt.
			UTC().
			Format(time.RFC3339)
	}

	if key.ExpiredAt != nil {
		response.ExpiredAt = key.ExpiredAt.
			UTC().
			Format(time.RFC3339)
	}

	return response
}

// resolvedFileEncryptionKey contains decrypted key material for one
// short-lived internal file operation. It must never be returned by an API.
type resolvedFileEncryptionKey struct {
	id            uuid.UUID
	keyIdentifier string
	keyMaterial   []byte
}

// destroy clears decrypted key material immediately after use.
func (k *resolvedFileEncryptionKey) destroy() {
	if k == nil {
		return
	}

	clear(k.keyMaterial)
	k.keyMaterial = nil
}

// resolveActiveFileEncryptionKey returns the organization's active key
// for protecting a new file.
func (s *EncryptionKeyService) resolveActiveFileEncryptionKey(
	ctx context.Context,
	organizationID uuid.UUID,
) (*resolvedFileEncryptionKey, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	if err := validateEncryptionKeyContext(ctx); err != nil {
		return nil, err
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"organization ID is required",
		)
	}

	key, err := s.repository.FindActiveEncryptionKey(
		ctx,
		organizationID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to resolve active file encryption key: %w",
			err,
		)
	}

	return s.buildResolvedFileEncryptionKey(
		key,
		organizationID,
	)
}

// resolveFileEncryptionKeyByID resolves the exact key used by an
// existing protected file. Inactive historical keys remain usable
// for authorized restoration after key rotation.
func (s *EncryptionKeyService) resolveFileEncryptionKeyByID(
	ctx context.Context,
	organizationID uuid.UUID,
	encryptionKeyID uuid.UUID,
) (*resolvedFileEncryptionKey, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	if err := validateEncryptionKeyContext(ctx); err != nil {
		return nil, err
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

	key, err := s.repository.FindEncryptionKeyByID(
		ctx,
		organizationID,
		encryptionKeyID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to resolve file encryption key: %w",
			err,
		)
	}

	return s.buildResolvedFileEncryptionKey(
		key,
		organizationID,
	)
}

func (s *EncryptionKeyService) buildResolvedFileEncryptionKey(
	key *EncryptionKey,
	expectedOrganizationID uuid.UUID,
) (*resolvedFileEncryptionKey, error) {
	if key == nil {
		return nil, ErrEncryptionKeyNotFound
	}

	if key.ID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: encryption key ID is missing",
			ErrManagedEncryptionKeyCorrupted,
		)
	}

	if key.OrganizationID == uuid.Nil ||
		key.OrganizationID != expectedOrganizationID {
		return nil, fmt.Errorf(
			"%w: encryption key organization mismatch",
			ErrManagedEncryptionKeyCorrupted,
		)
	}

	keyIdentifier := strings.TrimSpace(
		key.KeyIdentifier,
	)
	if keyIdentifier == "" {
		return nil, fmt.Errorf(
			"%w: key identifier is missing",
			ErrManagedEncryptionKeyCorrupted,
		)
	}

	if !strings.EqualFold(
		strings.TrimSpace(key.Algorithm),
		EncryptionAlgorithmAES256,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported encryption algorithm",
			ErrManagedEncryptionKeyCorrupted,
		)
	}

	if key.KeySize != managedEncryptionKeySizeInBits {
		return nil, fmt.Errorf(
			"%w: invalid encryption key size",
			ErrManagedEncryptionKeyCorrupted,
		)
	}

	if len(key.EncryptedKey) == 0 {
		return nil, fmt.Errorf(
			"%w: encrypted key material is missing",
			ErrManagedEncryptionKeyCorrupted,
		)
	}

	rawKey, err := s.decryptManagedKey(
		key.EncryptedKey,
		key.OrganizationID,
		keyIdentifier,
	)
	if err != nil {
		return nil, err
	}

	return &resolvedFileEncryptionKey{
		id:            key.ID,
		keyIdentifier: keyIdentifier,
		keyMaterial:   rawKey,
	}, nil
}
