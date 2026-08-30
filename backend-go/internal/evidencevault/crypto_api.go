package evidencevault

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
	"github.com/spf13/viper"
)

type SigningKeys struct {
	KeyID            string
	Private          ed25519.PrivateKey
	Public           ed25519.PublicKey
	VerificationKeys map[string]ed25519.PublicKey
}

func (h *Handler) PreserveObject(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	actor, actorOK := eid(c, "user_id")
	if !ok || !actorOK {
		response.Unauthorized(c, "Invalid authentication context", nil)
		return
	}
	if h.vault == nil || h.keys == nil || len(h.keys.Private) != ed25519.PrivateKeySize || h.keys.KeyID == "" {
		response.Error(c, http.StatusServiceUnavailable, "Local evidence vault keys are not configured", nil)
		return
	}
	caseID, err := uuid.Parse(c.PostForm("case_id"))
	if err != nil {
		response.BadRequest(c, "Valid case_id is required", nil)
		return
	}
	retentionDays, err := strconv.Atoi(c.PostForm("retention_days"))
	if err != nil || retentionDays < 1 || retentionDays > 3650 {
		response.BadRequest(c, "retention_days must be between 1 and 3650", nil)
		return
	}
	file, err := c.FormFile("file")
	if err != nil {
		response.BadRequest(c, "Evidence file is required", nil)
		return
	}
	source, err := file.Open()
	if err != nil {
		response.BadRequest(c, "Could not open evidence file", nil)
		return
	}
	defer source.Close()
	object, err := h.vault.Put(c, org, source, time.Duration(retentionDays)*24*time.Hour)
	if err != nil {
		response.BadRequest(c, "Could not preserve evidence content", err.Error())
		return
	}
	m := EvidenceManifest{EvidenceID: object.ObjectID, OrganizationID: org, CaseID: caseID, ObjectURI: object.ObjectURI, ObjectVersionID: object.VersionID.String(), EvidenceSHA256: object.SHA256, EncryptionKeyID: object.KeyID, CollectedBy: actor, CollectedAt: object.CreatedAt, SigningKeyID: h.keys.KeyID}
	if err = SignManifest(&m, h.keys.Private); err != nil {
		response.InternalServerError(c, "Could not sign evidence manifest", nil)
		return
	}
	_, err = h.repo.db.Exec(c, `INSERT INTO evidence_crypto_manifests(id,organization_id,case_id,evidence_id,object_uri,object_version_id,evidence_sha256,encryption_key_id,signing_key_id,manifest_sha256,signature,collected_by,collected_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, uuid.New(), org, caseID, m.EvidenceID, m.ObjectURI, m.ObjectVersionID, m.EvidenceSHA256, m.EncryptionKeyID, m.SigningKeyID, m.ManifestSHA256, m.Signature, actor, m.CollectedAt)
	if err != nil {
		response.InternalServerError(c, "Could not persist evidence manifest", err.Error())
		return
	}
	job := &PreservationJob{ID: uuid.New(), OrganizationID: org, CaseID: caseID, Items: []string{file.Filename}, Status: "PRESERVED", RetentionUntil: &object.RetainUntil, CreatedBy: actor, CreatedAt: object.CreatedAt, UpdatedAt: object.CreatedAt, ManifestEvidenceID: &m.EvidenceID}
	if err = h.repo.Create(c, job); err != nil {
		response.InternalServerError(c, "Could not create evidence preservation record", err.Error())
		return
	}
	_, _ = h.repo.Transition(c, org, job.ID, actor, "PRESERVED", "Original evidence encrypted, stored, and signed", &actor)
	response.Created(c, "Evidence encrypted and preserved", gin.H{"job": job, "manifest": m, "retain_until": object.RetainUntil, "size_bytes": object.SizeBytes})
}

func (h *Handler) GetObjectContent(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	evidenceID, err := uuid.Parse(c.Param("id"))
	if !ok || err != nil {
		response.BadRequest(c, "Invalid evidence context", nil)
		return
	}
	if h.vault == nil {
		response.Error(c, http.StatusServiceUnavailable, "Local evidence vault is not configured", nil)
		return
	}
	m, err := scanManifest(h.repo.db.QueryRow(c, manifestSelect+` WHERE organization_id=$1 AND evidence_id=$2`, org, evidenceID))
	if err != nil {
		response.NotFound(c, "Evidence manifest not found", nil)
		return
	}
	uriOrg, objectID, versionID, err := parseLocalVaultURI(m.ObjectURI)
	if err != nil || uriOrg != org || objectID != evidenceID || versionID.String() != m.ObjectVersionID {
		response.Error(c, http.StatusConflict, "Evidence object reference is invalid", nil)
		return
	}
	payload, object, err := h.vault.Get(c, org, objectID, versionID)
	if err != nil || !strings.EqualFold(object.SHA256, m.EvidenceSHA256) {
		response.Error(c, http.StatusConflict, "Evidence integrity verification failed", nil)
		return
	}
	c.Header("Content-Disposition", `attachment; filename="evidence-`+evidenceID.String()+`"`)
	c.Data(http.StatusOK, "application/octet-stream", payload)
}

func LoadSigningKeysFromEnvironment() *SigningKeys {
	setting := func(name string) string {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
		return strings.TrimSpace(viper.GetString(name))
	}
	k := &SigningKeys{KeyID: setting("EVIDENCE_SIGNING_KEY_ID"), VerificationKeys: map[string]ed25519.PublicKey{}}
	if raw, e := base64.StdEncoding.DecodeString(setting("EVIDENCE_SIGNING_PRIVATE_KEY_BASE64")); e == nil && len(raw) == ed25519.PrivateKeySize {
		k.Private = ed25519.PrivateKey(raw)
		k.Public = k.Private.Public().(ed25519.PublicKey)
		k.VerificationKeys[k.KeyID] = k.Public
	}
	if len(k.Public) == 0 {
		if raw, e := base64.StdEncoding.DecodeString(setting("EVIDENCE_SIGNING_PUBLIC_KEY_BASE64")); e == nil && len(raw) == ed25519.PublicKeySize {
			k.Public = ed25519.PublicKey(raw)
			k.VerificationKeys[k.KeyID] = k.Public
		}
	}
	var ring map[string]string
	if json.Unmarshal([]byte(setting("EVIDENCE_VERIFY_KEYS_JSON")), &ring) == nil {
		for id, encoded := range ring {
			if raw, e := base64.StdEncoding.DecodeString(encoded); e == nil && len(raw) == ed25519.PublicKeySize {
				k.VerificationKeys[id] = ed25519.PublicKey(raw)
			}
		}
	}
	return k
}
func (k *SigningKeys) VerificationKey(id string) ed25519.PublicKey {
	if k == nil {
		return nil
	}
	if key := k.VerificationKeys[id]; len(key) == ed25519.PublicKeySize {
		return key
	}
	if id == k.KeyID {
		return k.Public
	}
	return nil
}

type createManifestRequest struct {
	EvidenceID             uuid.UUID `json:"evidence_id" binding:"required"`
	CaseID                 uuid.UUID `json:"case_id" binding:"required"`
	ObjectURI              string    `json:"object_uri" binding:"required"`
	ObjectVersionID        string    `json:"object_version_id" binding:"required"`
	EvidenceSHA256         string    `json:"evidence_sha256" binding:"required,len=64,hexadecimal"`
	PreviousManifestSHA256 string    `json:"previous_manifest_sha256"`
	EncryptionKeyID        string    `json:"encryption_key_id" binding:"required"`
	CollectedAt            time.Time `json:"collected_at" binding:"required"`
}

func (h *Handler) CreateManifest(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	actor, aok := eid(c, "user_id")
	if !ok || !aok {
		response.Unauthorized(c, "Invalid authentication context", nil)
		return
	}
	if h.keys == nil || len(h.keys.Private) != ed25519.PrivateKeySize || h.keys.KeyID == "" {
		response.Error(c, http.StatusServiceUnavailable, "Evidence signing key is not configured", nil)
		return
	}
	var q createManifestRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid evidence manifest", e.Error())
		return
	}
	if q.PreviousManifestSHA256 != "" {
		var exists bool
		_ = h.repo.db.QueryRow(c, `SELECT EXISTS(SELECT 1 FROM evidence_crypto_manifests WHERE organization_id=$1 AND manifest_sha256=$2)`, org, strings.ToLower(q.PreviousManifestSHA256)).Scan(&exists)
		if !exists {
			response.BadRequest(c, "Previous manifest does not exist in this organization", nil)
			return
		}
	}
	m := EvidenceManifest{EvidenceID: q.EvidenceID, OrganizationID: org, CaseID: q.CaseID, ObjectURI: q.ObjectURI, ObjectVersionID: q.ObjectVersionID, EvidenceSHA256: strings.ToLower(q.EvidenceSHA256), PreviousManifestSHA256: strings.ToLower(q.PreviousManifestSHA256), EncryptionKeyID: q.EncryptionKeyID, CollectedBy: actor, CollectedAt: q.CollectedAt.UTC(), SigningKeyID: h.keys.KeyID}
	if e := SignManifest(&m, h.keys.Private); e != nil {
		response.BadRequest(c, "Could not sign evidence manifest", e.Error())
		return
	}
	_, e := h.repo.db.Exec(c, `INSERT INTO evidence_crypto_manifests(id,organization_id,case_id,evidence_id,object_uri,object_version_id,evidence_sha256,previous_manifest_sha256,encryption_key_id,signing_key_id,manifest_sha256,signature,collected_by,collected_at)VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9,$10,$11,$12,$13,$14)`, uuid.New(), org, m.CaseID, m.EvidenceID, m.ObjectURI, m.ObjectVersionID, m.EvidenceSHA256, m.PreviousManifestSHA256, m.EncryptionKeyID, m.SigningKeyID, m.ManifestSHA256, m.Signature, m.CollectedBy, m.CollectedAt)
	if e != nil {
		response.InternalServerError(c, "Could not persist evidence manifest", e.Error())
		return
	}
	response.Created(c, "Evidence manifest signed", m)
}
func scanManifest(row interface{ Scan(...any) error }) (EvidenceManifest, error) {
	var m EvidenceManifest
	e := row.Scan(&m.EvidenceID, &m.OrganizationID, &m.CaseID, &m.ObjectURI, &m.ObjectVersionID, &m.EvidenceSHA256, &m.PreviousManifestSHA256, &m.EncryptionKeyID, &m.SigningKeyID, &m.ManifestSHA256, &m.Signature, &m.CollectedBy, &m.CollectedAt)
	return m, e
}

const manifestSelect = `SELECT evidence_id,organization_id,case_id,object_uri,object_version_id,evidence_sha256,COALESCE(previous_manifest_sha256,''),encryption_key_id,signing_key_id,manifest_sha256,signature,collected_by,collected_at FROM evidence_crypto_manifests`

func (h *Handler) GetManifest(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	id, e := uuid.Parse(c.Param("id"))
	if !ok || e != nil {
		response.BadRequest(c, "Invalid manifest context", nil)
		return
	}
	m, e := scanManifest(h.repo.db.QueryRow(c, manifestSelect+` WHERE organization_id=$1 AND evidence_id=$2`, org, id))
	if e != nil {
		response.NotFound(c, "Evidence manifest not found", nil)
		return
	}
	response.OK(c, "Evidence manifest loaded", m)
}

type verifyRequest struct {
	ObservedSHA256 string `json:"observed_sha256" binding:"required,len=64,hexadecimal"`
}

func (h *Handler) VerifyStoredManifest(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	actor, _ := eid(c, "user_id")
	id, e := uuid.Parse(c.Param("id"))
	if !ok || e != nil {
		response.BadRequest(c, "Invalid manifest context", nil)
		return
	}
	var q verifyRequest
	if e = c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid verification request", e.Error())
		return
	}
	m, e := scanManifest(h.repo.db.QueryRow(c, manifestSelect+` WHERE organization_id=$1 AND evidence_id=$2`, org, id))
	if e != nil {
		response.NotFound(c, "Evidence manifest not found", nil)
		return
	}
	signatureOK := h.keys != nil && VerifyManifest(m, h.keys.VerificationKey(m.SigningKeyID)) == nil
	objectOK := strings.EqualFold(m.EvidenceSHA256, q.ObservedSHA256)
	chainOK := true
	if m.PreviousManifestSHA256 != "" {
		_ = h.repo.db.QueryRow(c, `SELECT EXISTS(SELECT 1 FROM evidence_crypto_manifests WHERE organization_id=$1 AND manifest_sha256=$2)`, org, m.PreviousManifestSHA256).Scan(&chainOK)
	}
	details := gin.H{"object_hash_verified": objectOK, "signature_verified": signatureOK, "chain_verified": chainOK}
	_, _ = h.repo.db.Exec(c, `INSERT INTO evidence_integrity_verifications(id,organization_id,evidence_id,manifest_sha256,object_hash_verified,signature_verified,chain_verified,verified_by,details)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, uuid.New(), org, id, m.ManifestSHA256, objectOK, signatureOK, chainOK, actor, details)
	if !objectOK || !signatureOK || !chainOK {
		response.Error(c, http.StatusConflict, "Evidence integrity verification failed", details)
		return
	}
	response.OK(c, "Evidence integrity verified", details)
}

type exportVerifyRequest struct {
	Manifest       EvidenceManifest `json:"manifest" binding:"required"`
	ObservedSHA256 string           `json:"observed_sha256" binding:"required,len=64,hexadecimal"`
}

func (h *Handler) VerifyExport(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var q exportVerifyRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid evidence export", e.Error())
		return
	}
	if q.Manifest.OrganizationID != org {
		response.Forbidden(c, "Evidence export belongs to another organization", nil)
		return
	}
	if h.keys == nil || len(h.keys.VerificationKey(q.Manifest.SigningKeyID)) != ed25519.PublicKeySize {
		response.Error(c, http.StatusServiceUnavailable, "Evidence verification key is not configured", nil)
		return
	}
	if e := VerifyManifest(q.Manifest, h.keys.VerificationKey(q.Manifest.SigningKeyID)); e != nil {
		response.Error(c, http.StatusConflict, "Evidence export signature is invalid", e.Error())
		return
	}
	if !strings.EqualFold(q.Manifest.EvidenceSHA256, q.ObservedSHA256) {
		response.Error(c, http.StatusConflict, "Exported evidence hash does not match manifest", nil)
		return
	}
	response.OK(c, "Evidence export verified", gin.H{"manifest_sha256": q.Manifest.ManifestSHA256, "signature_verified": true, "object_hash_verified": true})
}
