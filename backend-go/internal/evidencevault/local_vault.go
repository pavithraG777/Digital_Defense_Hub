package evidencevault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
)

var (
	ErrVaultIntegrity = errors.New("evidence vault integrity verification failed")
	ErrVaultRetained  = errors.New("evidence object is retained and cannot be removed")
)

type LocalVault struct {
	root        string
	keyID       string
	aead        cipher.AEAD
	decryptKeys map[string]cipher.AEAD
	now         func() time.Time
}

func LoadLocalVaultFromEnvironment() (*LocalVault, error) {
	setting := func(name string) string {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
		return strings.TrimSpace(viper.GetString(name))
	}
	vault, err := NewLocalVault(setting("EVIDENCE_VAULT_STORAGE_PATH"), setting("EVIDENCE_VAULT_ENCRYPTION_KEY_ID"), setting("EVIDENCE_VAULT_ENCRYPTION_KEY_BASE64"))
	if err != nil {
		return nil, err
	}
	var retired map[string]string
	value := setting("EVIDENCE_VAULT_DECRYPT_KEYS_JSON")
	if value != "" && value != "{}" {
		if err = json.Unmarshal([]byte(value), &retired); err != nil {
			return nil, errors.New("invalid evidence vault decrypt key ring")
		}
		for id, encoded := range retired {
			if err = vault.AddDecryptionKey(id, encoded); err != nil {
				return nil, err
			}
		}
	}
	return vault, nil
}

func parseLocalVaultURI(uri string) (uuid.UUID, uuid.UUID, uuid.UUID, error) {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(uri), "local-vault://"), "/")
	if len(parts) != 3 {
		return uuid.Nil, uuid.Nil, uuid.Nil, errors.New("invalid local vault URI")
	}
	org, e1 := uuid.Parse(parts[0])
	object, e2 := uuid.Parse(parts[1])
	version, e3 := uuid.Parse(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, errors.New("invalid local vault URI")
	}
	return org, object, version, nil
}

type VaultObject struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	ObjectID       uuid.UUID `json:"object_id"`
	VersionID      uuid.UUID `json:"version_id"`
	ObjectURI      string    `json:"object_uri"`
	SHA256         string    `json:"sha256"`
	KeyID          string    `json:"key_id"`
	SizeBytes      int64     `json:"size_bytes"`
	RetainUntil    time.Time `json:"retain_until"`
	CreatedAt      time.Time `json:"created_at"`
}

type vaultEnvelope struct {
	Version    int         `json:"version"`
	Nonce      string      `json:"nonce"`
	Ciphertext string      `json:"ciphertext"`
	Object     VaultObject `json:"object"`
}

func NewLocalVault(root, keyID, encodedKey string) (*LocalVault, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedKey))
	if err != nil || len(key) != 32 {
		return nil, errors.New("evidence vault key must be a base64-encoded 32-byte key")
	}
	if strings.TrimSpace(keyID) == "" {
		return nil, errors.New("evidence vault key ID is required")
	}
	abs, err := filepath.Abs(strings.TrimSpace(root))
	if err != nil || strings.TrimSpace(root) == "" {
		return nil, errors.New("evidence vault storage root is required")
	}
	if err = os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create evidence vault root: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &LocalVault{root: filepath.Clean(abs), keyID: keyID, aead: aead, decryptKeys: map[string]cipher.AEAD{keyID: aead}, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (v *LocalVault) AddDecryptionKey(keyID, encodedKey string) error {
	keyID = strings.TrimSpace(keyID)
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedKey))
	if keyID == "" || err != nil || len(key) != 32 {
		return errors.New("retired evidence key must have an ID and decode to 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	v.decryptKeys[keyID] = aead
	return nil
}

func (v *LocalVault) Put(ctx context.Context, organizationID uuid.UUID, source io.Reader, retention time.Duration) (VaultObject, error) {
	if ctx == nil || organizationID == uuid.Nil || source == nil || retention <= 0 {
		return VaultObject{}, errors.New("invalid evidence vault request")
	}
	plaintext, err := io.ReadAll(io.LimitReader(source, 512*1024*1024+1))
	if err != nil {
		return VaultObject{}, err
	}
	if len(plaintext) == 0 || len(plaintext) > 512*1024*1024 {
		return VaultObject{}, errors.New("evidence object size is invalid")
	}
	select {
	case <-ctx.Done():
		return VaultObject{}, ctx.Err()
	default:
	}
	now := v.now()
	objectID, versionID := uuid.New(), uuid.New()
	sum := sha256.Sum256(plaintext)
	object := VaultObject{OrganizationID: organizationID, ObjectID: objectID, VersionID: versionID, ObjectURI: "local-vault://" + organizationID.String() + "/" + objectID.String() + "/" + versionID.String(), SHA256: hex.EncodeToString(sum[:]), KeyID: v.keyID, SizeBytes: int64(len(plaintext)), RetainUntil: now.Add(retention), CreatedAt: now}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return VaultObject{}, err
	}
	aad, _ := json.Marshal(object)
	envelope := vaultEnvelope{Version: 1, Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(v.aead.Seal(nil, nonce, plaintext, aad)), Object: object}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return VaultObject{}, err
	}
	directory := filepath.Join(v.root, organizationID.String(), objectID.String())
	if err = os.MkdirAll(directory, 0o700); err != nil {
		return VaultObject{}, err
	}
	path := filepath.Join(directory, versionID.String()+".vault")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return VaultObject{}, fmt.Errorf("create immutable evidence object: %w", err)
	}
	if _, err = file.Write(encoded); err != nil {
		file.Close()
		return VaultObject{}, err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return VaultObject{}, err
	}
	return object, file.Close()
}

func (v *LocalVault) Get(ctx context.Context, organizationID, objectID, versionID uuid.UUID) ([]byte, VaultObject, error) {
	if ctx == nil || organizationID == uuid.Nil || objectID == uuid.Nil || versionID == uuid.Nil {
		return nil, VaultObject{}, errors.New("invalid evidence vault identity")
	}
	path := filepath.Join(v.root, organizationID.String(), objectID.String(), versionID.String()+".vault")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, VaultObject{}, err
	}
	var envelope vaultEnvelope
	if json.Unmarshal(raw, &envelope) != nil || envelope.Version != 1 || envelope.Object.OrganizationID != organizationID || envelope.Object.ObjectID != objectID || envelope.Object.VersionID != versionID {
		return nil, VaultObject{}, ErrVaultIntegrity
	}
	aead, exists := v.decryptKeys[envelope.Object.KeyID]
	if !exists {
		return nil, VaultObject{}, errors.New("evidence decryption key is unavailable")
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, VaultObject{}, ErrVaultIntegrity
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, VaultObject{}, ErrVaultIntegrity
	}
	aad, _ := json.Marshal(envelope.Object)
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, VaultObject{}, ErrVaultIntegrity
	}
	sum := sha256.Sum256(plaintext)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), envelope.Object.SHA256) {
		return nil, VaultObject{}, ErrVaultIntegrity
	}
	return plaintext, envelope.Object, nil
}

func (v *LocalVault) Delete(organizationID, objectID, versionID uuid.UUID) error {
	_, object, err := v.Get(context.Background(), organizationID, objectID, versionID)
	if err != nil {
		return err
	}
	if v.now().Before(object.RetainUntil) {
		return ErrVaultRetained
	}
	return os.Remove(filepath.Join(v.root, organizationID.String(), objectID.String(), versionID.String()+".vault"))
}
