package evidencevault

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

type EvidenceManifest struct {
	EvidenceID             uuid.UUID `json:"evidence_id"`
	OrganizationID         uuid.UUID `json:"organization_id"`
	CaseID                 uuid.UUID `json:"case_id"`
	ObjectURI              string    `json:"object_uri"`
	ObjectVersionID        string    `json:"object_version_id"`
	EvidenceSHA256         string    `json:"evidence_sha256"`
	PreviousManifestSHA256 string    `json:"previous_manifest_sha256,omitempty"`
	EncryptionKeyID        string    `json:"encryption_key_id"`
	CollectedBy            uuid.UUID `json:"collected_by"`
	CollectedAt            time.Time `json:"collected_at"`
	SigningKeyID           string    `json:"signing_key_id"`
	ManifestSHA256         string    `json:"manifest_sha256"`
	Signature              string    `json:"signature"`
}
type manifestUnsigned struct {
	EvidenceID             uuid.UUID `json:"evidence_id"`
	OrganizationID         uuid.UUID `json:"organization_id"`
	CaseID                 uuid.UUID `json:"case_id"`
	ObjectURI              string    `json:"object_uri"`
	ObjectVersionID        string    `json:"object_version_id"`
	EvidenceSHA256         string    `json:"evidence_sha256"`
	PreviousManifestSHA256 string    `json:"previous_manifest_sha256,omitempty"`
	EncryptionKeyID        string    `json:"encryption_key_id"`
	CollectedBy            uuid.UUID `json:"collected_by"`
	CollectedAt            string    `json:"collected_at"`
	SigningKeyID           string    `json:"signing_key_id"`
}

func (m EvidenceManifest) canonical() ([]byte, error) {
	if m.EvidenceID == uuid.Nil || m.OrganizationID == uuid.Nil || m.CaseID == uuid.Nil {
		return nil, errors.New("manifest identity is incomplete")
	}
	if _, e := hex.DecodeString(m.EvidenceSHA256); e != nil || len(m.EvidenceSHA256) != 64 {
		return nil, errors.New("invalid evidence SHA-256")
	}
	if strings.TrimSpace(m.ObjectURI) == "" || strings.TrimSpace(m.ObjectVersionID) == "" || strings.TrimSpace(m.EncryptionKeyID) == "" || strings.TrimSpace(m.SigningKeyID) == "" {
		return nil, errors.New("immutable object, encryption, and signing metadata are required")
	}
	return json.Marshal(manifestUnsigned{m.EvidenceID, m.OrganizationID, m.CaseID, m.ObjectURI, m.ObjectVersionID, strings.ToLower(m.EvidenceSHA256), strings.ToLower(m.PreviousManifestSHA256), m.EncryptionKeyID, m.CollectedBy, m.CollectedAt.UTC().Format(time.RFC3339Nano), m.SigningKeyID})
}
func SignManifest(m *EvidenceManifest, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid Ed25519 private key")
	}
	raw, e := m.canonical()
	if e != nil {
		return e
	}
	sum := sha256.Sum256(raw)
	m.ManifestSHA256 = hex.EncodeToString(sum[:])
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, sum[:]))
	return nil
}
func VerifyManifest(m EvidenceManifest, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	raw, e := m.canonical()
	if e != nil {
		return e
	}
	sum := sha256.Sum256(raw)
	if !strings.EqualFold(m.ManifestSHA256, hex.EncodeToString(sum[:])) {
		return errors.New("manifest hash mismatch")
	}
	sig, e := base64.StdEncoding.DecodeString(m.Signature)
	if e != nil || !ed25519.Verify(key, sum[:], sig) {
		return errors.New("manifest signature invalid")
	}
	return nil
}
