package honeytoken

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
)

const honeytokenValueEnvelopeVersion = "HT1"

var (
	ErrHoneytokenGeneratorUnavailable = errors.New(
		"honeytoken generator is unavailable",
	)
	ErrInvalidHoneytokenValueEnvelope = errors.New(
		"honeytoken value envelope is invalid",
	)
)

// HoneytokenGenerator creates, encrypts and validates decoy values.
type HoneytokenGenerator struct {
	encryptionKeys *EncryptionKeyService
}

// honeytokenGenerationResult contains short-lived generated material.
type honeytokenGenerationResult struct {
	plainValue []byte

	encryptedValue string
	valueHash      string
	valuePrefix    string
}

func (r *honeytokenGenerationResult) destroy() {
	if r == nil {
		return
	}

	clear(r.plainValue)
	r.plainValue = nil
}

// NewHoneytokenGenerator creates the decoy-value generation engine.
func NewHoneytokenGenerator(
	encryptionKeys *EncryptionKeyService,
) (*HoneytokenGenerator, error) {
	if encryptionKeys == nil {
		return nil, fmt.Errorf(
			"encryption key service is required",
		)
	}

	return &HoneytokenGenerator{
		encryptionKeys: encryptionKeys,
	}, nil
}

// Generate creates a convincing decoy value and protects it using the
// organization's currently active AES-256 encryption key.
func (g *HoneytokenGenerator) Generate(
	ctx context.Context,
	organizationID uuid.UUID,
	honeytokenID uuid.UUID,
	honeytokenType string,
) (*honeytokenGenerationResult, error) {
	if err := g.validate(); err != nil {
		return nil, err
	}

	if err := validateHoneytokenGeneratorContext(ctx); err != nil {
		return nil, err
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"organization ID is required",
		)
	}

	if honeytokenID == uuid.Nil {
		return nil, fmt.Errorf(
			"honeytoken ID is required",
		)
	}

	honeytokenType = strings.ToUpper(
		strings.TrimSpace(honeytokenType),
	)

	if !isSupportedHoneytokenType(honeytokenType) {
		return nil, fmt.Errorf(
			"unsupported honeytoken type: %s",
			honeytokenType,
		)
	}

	plainValue, err := generateHoneytokenPlainValue(
		honeytokenType,
	)
	if err != nil {
		return nil, err
	}

	resultCreated := false

	defer func() {
		if !resultCreated {
			clear(plainValue)
		}
	}()

	resolvedKey, err := g.encryptionKeys.
		resolveActiveFileEncryptionKey(
			ctx,
			organizationID,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to resolve honeytoken encryption key: %w",
			err,
		)
	}

	if resolvedKey == nil {
		return nil, fmt.Errorf(
			"honeytoken encryption key resolution returned an empty result",
		)
	}
	defer resolvedKey.destroy()

	authenticatedData := buildHoneytokenAuthenticatedData(
		organizationID,
		honeytokenID,
		honeytokenType,
		resolvedKey.id,
	)

	encryptedValue, err := encryptHoneytokenValue(
		resolvedKey.keyMaterial,
		resolvedKey.id,
		plainValue,
		authenticatedData,
	)
	if err != nil {
		return nil, err
	}

	valueHash := calculateHoneytokenValueHash(
		resolvedKey.keyMaterial,
		plainValue,
		authenticatedData,
	)

	result := &honeytokenGenerationResult{
		plainValue: plainValue,

		encryptedValue: encryptedValue,
		valueHash:      valueHash,
		valuePrefix: buildHoneytokenValuePrefix(
			plainValue,
		),
	}

	resultCreated = true

	return result, nil
}

// ValidateValue performs constant-time validation of a candidate value
// without decrypting or exposing the stored decoy value.
func (g *HoneytokenGenerator) ValidateValue(
	ctx context.Context,
	token *Honeytoken,
	candidateValue string,
) (bool, error) {
	if err := g.validate(); err != nil {
		return false, err
	}

	if err := validateHoneytokenGeneratorContext(ctx); err != nil {
		return false, err
	}

	if token == nil {
		return false, fmt.Errorf(
			"honeytoken is required",
		)
	}

	if token.ID == uuid.Nil {
		return false, fmt.Errorf(
			"honeytoken ID is required",
		)
	}

	if token.OrganizationID == uuid.Nil {
		return false, fmt.Errorf(
			"organization ID is required",
		)
	}

	if token.DecoyValueEncrypted == nil ||
		strings.TrimSpace(*token.DecoyValueEncrypted) == "" {
		return false, ErrInvalidHoneytokenValueEnvelope
	}

	if token.DecoyValueHash == nil ||
		strings.TrimSpace(*token.DecoyValueHash) == "" {
		return false, fmt.Errorf(
			"honeytoken value hash is missing",
		)
	}

	candidateValue = strings.TrimSpace(
		candidateValue,
	)
	if candidateValue == "" {
		return false, fmt.Errorf(
			"candidate honeytoken value is required",
		)
	}

	encryptionKeyID, err := parseHoneytokenValueEnvelope(
		*token.DecoyValueEncrypted,
	)
	if err != nil {
		return false, err
	}

	resolvedKey, err := g.encryptionKeys.
		resolveFileEncryptionKeyByID(
			ctx,
			token.OrganizationID,
			encryptionKeyID,
		)
	if err != nil {
		return false, fmt.Errorf(
			"failed to resolve honeytoken validation key: %w",
			err,
		)
	}

	if resolvedKey == nil {
		return false, fmt.Errorf(
			"honeytoken validation key resolution returned an empty result",
		)
	}
	defer resolvedKey.destroy()

	authenticatedData := buildHoneytokenAuthenticatedData(
		token.OrganizationID,
		token.ID,
		token.HoneytokenType,
		resolvedKey.id,
	)

	candidateBytes := []byte(candidateValue)
	defer clear(candidateBytes)

	calculatedHash := calculateHoneytokenValueHash(
		resolvedKey.keyMaterial,
		candidateBytes,
		authenticatedData,
	)

	expectedHash, err := hex.DecodeString(
		strings.TrimSpace(*token.DecoyValueHash),
	)
	if err != nil || len(expectedHash) != sha256.Size {
		return false, fmt.Errorf(
			"honeytoken value hash is invalid",
		)
	}

	calculatedHashBytes, err := hex.DecodeString(
		calculatedHash,
	)
	if err != nil {
		return false, fmt.Errorf(
			"failed to decode calculated honeytoken hash: %w",
			err,
		)
	}

	return hmac.Equal(
		expectedHash,
		calculatedHashBytes,
	), nil
}

func (g *HoneytokenGenerator) validate() error {
	if g == nil || g.encryptionKeys == nil {
		return ErrHoneytokenGeneratorUnavailable
	}

	return nil
}

func validateHoneytokenGeneratorContext(
	ctx context.Context,
) error {
	if ctx == nil {
		return fmt.Errorf(
			"context is required",
		)
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"request context is not active: %w",
			err,
		)
	}

	return nil
}

func isSupportedHoneytokenType(
	honeytokenType string,
) bool {
	switch strings.ToUpper(
		strings.TrimSpace(honeytokenType),
	) {
	case HoneytokenTypeUsername,
		HoneytokenTypePassword,
		HoneytokenTypeEmailAddress,
		HoneytokenTypeAPIKey,
		HoneytokenTypeAccessToken,
		HoneytokenTypeDatabaseRecord,
		HoneytokenTypeCloudCredential,
		HoneytokenTypeSSHKey,
		HoneytokenTypeDocumentData,
		HoneytokenTypeURL,
		HoneytokenTypeCustom:
		return true

	default:
		return false
	}
}

func generateHoneytokenPlainValue(
	honeytokenType string,
) ([]byte, error) {
	switch honeytokenType {
	case HoneytokenTypeUsername:
		randomValue, err := randomHex(6)
		if err != nil {
			return nil, err
		}

		return []byte(
			"svc_backup_" + randomValue,
		), nil

	case HoneytokenTypePassword:
		randomValue, err := randomBase64URL(24)
		if err != nil {
			return nil, err
		}

		return []byte(
			"Ddh!" + randomValue,
		), nil

	case HoneytokenTypeEmailAddress:
		randomValue, err := randomHex(6)
		if err != nil {
			return nil, err
		}

		return []byte(
			"finance.audit." +
				randomValue +
				"@example.invalid",
		), nil

	case HoneytokenTypeAPIKey:
		randomValue, err := randomHex(24)
		if err != nil {
			return nil, err
		}

		return []byte(
			"ddh_live_" + randomValue,
		), nil

	case HoneytokenTypeAccessToken:
		randomValue, err := randomBase64URL(32)
		if err != nil {
			return nil, err
		}

		return []byte(
			"ddh_at_" + randomValue,
		), nil

	case HoneytokenTypeDatabaseRecord:
		randomValue, err := randomHex(8)
		if err != nil {
			return nil, err
		}

		return []byte(
			fmt.Sprintf(
				`{"record_id":"CUST-%s","classification":"CONFIDENTIAL","status":"ACTIVE"}`,
				strings.ToUpper(randomValue),
			),
		), nil

	case HoneytokenTypeCloudCredential:
		randomValue, err := randomHex(8)
		if err != nil {
			return nil, err
		}

		return []byte(
			"AKIA" + strings.ToUpper(randomValue),
		), nil

	case HoneytokenTypeSSHKey:
		randomValue, err := randomBase64URL(64)
		if err != nil {
			return nil, err
		}

		return []byte(
			"-----BEGIN OPENSSH PRIVATE KEY-----\n" +
				randomValue +
				"\n-----END OPENSSH PRIVATE KEY-----",
		), nil

	case HoneytokenTypeDocumentData:
		randomValue, err := randomHex(10)
		if err != nil {
			return nil, err
		}

		return []byte(
			"CONFIDENTIAL-DDH-DOCUMENT-" +
				strings.ToUpper(randomValue),
		), nil

	case HoneytokenTypeURL:
		randomValue, err := randomBase64URL(18)
		if err != nil {
			return nil, err
		}

		return []byte(
			"https://secure-docs.example.invalid/access/" +
				randomValue,
		), nil

	case HoneytokenTypeCustom:
		randomValue, err := randomBase64URL(24)
		if err != nil {
			return nil, err
		}

		return []byte(
			"DDH-CUSTOM-" + randomValue,
		), nil

	default:
		return nil, fmt.Errorf(
			"unsupported honeytoken type: %s",
			honeytokenType,
		)
	}
}

func encryptHoneytokenValue(
	key []byte,
	encryptionKeyID uuid.UUID,
	plainValue []byte,
	authenticatedData []byte,
) (string, error) {
	if len(key) != aes256KeySize {
		return "", ErrInvalidEncryptionKey
	}

	if encryptionKeyID == uuid.Nil {
		return "", fmt.Errorf(
			"encryption key ID is required",
		)
	}

	if len(plainValue) == 0 {
		return "", fmt.Errorf(
			"honeytoken value is required",
		)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf(
			"failed to initialize honeytoken AES cipher: %w",
			err,
		)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf(
			"failed to initialize honeytoken AES-GCM: %w",
			err,
		)
	}

	nonce := make(
		[]byte,
		gcm.NonceSize(),
	)

	if _, err := io.ReadFull(
		rand.Reader,
		nonce,
	); err != nil {
		return "", fmt.Errorf(
			"failed to generate honeytoken nonce: %w",
			err,
		)
	}

	cipherText := gcm.Seal(
		nil,
		nonce,
		plainValue,
		authenticatedData,
	)

	payload := make(
		[]byte,
		0,
		len(nonce)+len(cipherText),
	)
	payload = append(payload, nonce...)
	payload = append(payload, cipherText...)

	encodedPayload := base64.RawURLEncoding.
		EncodeToString(payload)

	return honeytokenValueEnvelopeVersion +
		"." +
		encryptionKeyID.String() +
		"." +
		encodedPayload, nil
}

func parseHoneytokenValueEnvelope(
	envelope string,
) (uuid.UUID, error) {
	parts := strings.Split(
		strings.TrimSpace(envelope),
		".",
	)

	if len(parts) != 3 ||
		parts[0] != honeytokenValueEnvelopeVersion {
		return uuid.Nil, ErrInvalidHoneytokenValueEnvelope
	}

	encryptionKeyID, err := uuid.Parse(
		parts[1],
	)
	if err != nil || encryptionKeyID == uuid.Nil {
		return uuid.Nil, ErrInvalidHoneytokenValueEnvelope
	}

	payload, err := base64.RawURLEncoding.
		DecodeString(parts[2])
	if err != nil || len(payload) == 0 {
		return uuid.Nil, ErrInvalidHoneytokenValueEnvelope
	}
	clear(payload)

	return encryptionKeyID, nil
}

func calculateHoneytokenValueHash(
	key []byte,
	value []byte,
	authenticatedData []byte,
) string {
	hash := hmac.New(
		sha256.New,
		key,
	)

	_, _ = hash.Write(authenticatedData)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)

	return hex.EncodeToString(
		hash.Sum(nil),
	)
}

func buildHoneytokenAuthenticatedData(
	organizationID uuid.UUID,
	honeytokenID uuid.UUID,
	honeytokenType string,
	encryptionKeyID uuid.UUID,
) []byte {
	return []byte(
		strings.Join(
			[]string{
				honeytokenValueEnvelopeVersion,
				organizationID.String(),
				honeytokenID.String(),
				strings.ToUpper(
					strings.TrimSpace(honeytokenType),
				),
				encryptionKeyID.String(),
			},
			":",
		),
	)
}

func buildHoneytokenValuePrefix(
	value []byte,
) string {
	const maximumPrefixLength = 12

	safeValue := strings.ReplaceAll(
		string(value),
		"\n",
		"",
	)

	if len(safeValue) <= maximumPrefixLength {
		return safeValue
	}

	return safeValue[:maximumPrefixLength]
}

func randomHex(
	byteCount int,
) (string, error) {
	if byteCount < 1 {
		return "", fmt.Errorf(
			"random byte count must be greater than zero",
		)
	}

	value := make(
		[]byte,
		byteCount,
	)
	defer clear(value)

	if _, err := io.ReadFull(
		rand.Reader,
		value,
	); err != nil {
		return "", fmt.Errorf(
			"failed to generate random value: %w",
			err,
		)
	}

	return hex.EncodeToString(value), nil
}

func randomBase64URL(
	byteCount int,
) (string, error) {
	if byteCount < 1 {
		return "", fmt.Errorf(
			"random byte count must be greater than zero",
		)
	}

	value := make(
		[]byte,
		byteCount,
	)
	defer clear(value)

	if _, err := io.ReadFull(
		rand.Reader,
		value,
	); err != nil {
		return "", fmt.Errorf(
			"failed to generate random value: %w",
			err,
		)
	}

	return base64.RawURLEncoding.
		EncodeToString(value), nil
}
