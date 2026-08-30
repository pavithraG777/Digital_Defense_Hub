package evidencevault

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
	"net/http"
	"strings"
	"time"
)

func custodyHash(event CustodyEvent, org uuid.UUID) string {
	canonical, _ := json.Marshal(map[string]any{"id": event.ID, "organization_id": org, "job_id": event.JobID, "action": event.Action, "to_custodian": event.ToCustodian, "note": event.Note, "actor_id": event.ActorID, "created_at": event.CreatedAt.UTC().Format(time.RFC3339Nano), "previous_event_hash": nullableHash(event.PreviousEventHash)})
	return fmt.Sprintf("%x", sha256.Sum256(canonical))
}
func nullableHash(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func (h *Handler) VerifyCustody(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	actor, actorOK := eid(c, "user_id")
	job, e := uuid.Parse(c.Param("id"))
	if !ok || !actorOK || e != nil {
		response.BadRequest(c, "Invalid custody context", nil)
		return
	}
	events, e := h.repo.Custody(c, org, job)
	if e != nil {
		response.InternalServerError(c, "Could not load custody chain", e.Error())
		return
	}
	// Older preservation records can predate custody-event creation. Establish
	// their signed-in user as the initial custodian before verifying the chain.
	if len(events) == 0 {
		if _, e = h.repo.Transition(c, org, job, actor, "PRESERVED", "Initial custody record created for preserved evidence", &actor); e != nil {
			response.InternalServerError(c, "Could not initialize custody chain", e.Error())
			return
		}
		events, e = h.repo.Custody(c, org, job)
		if e != nil {
			response.InternalServerError(c, "Could not reload custody chain", e.Error())
			return
		}
	}
	previous := ""
	valid := true
	broken := -1
	for i, event := range events {
		if event.PreviousEventHash != previous || !strings.EqualFold(event.EventHash, custodyHash(event, org)) {
			valid = false
			broken = i
			break
		}
		previous = event.EventHash
	}
	if !valid {
		response.Error(c, http.StatusConflict, "Custody chain verification failed", gin.H{"broken_index": broken, "event_count": len(events)})
		return
	}
	verified, e := h.repo.Transition(c, org, job, actor, "VERIFIED", "Integrity and chain of custody verified successfully", &actor)
	if e != nil {
		response.InternalServerError(c, "Custody chain passed but verification state could not be recorded", e.Error())
		return
	}
	response.OK(c, "Custody chain verified", gin.H{"valid": true, "event_count": len(events) + 1, "head_hash": previous, "job": verified})
}

type wormRequest struct {
	Provider          string    `json:"provider" binding:"required"`
	Bucket            string    `json:"bucket" binding:"required"`
	ObjectVersionID   string    `json:"object_version_id" binding:"required"`
	RetentionMode     string    `json:"retention_mode" binding:"required,oneof=GOVERNANCE COMPLIANCE"`
	RetainUntil       time.Time `json:"retain_until" binding:"required"`
	LegalHold         bool      `json:"legal_hold"`
	ProviderRequestID string    `json:"provider_request_id" binding:"required"`
}

func (h *Handler) RecordWORMAttestation(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	actor, _ := eid(c, "user_id")
	evidence, e := uuid.Parse(c.Param("id"))
	if !ok || e != nil {
		response.BadRequest(c, "Invalid evidence context", nil)
		return
	}
	var q wormRequest
	if e = c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid WORM attestation", e.Error())
		return
	}
	var expectedVersion string
	e = h.repo.db.QueryRow(c, `SELECT object_version_id FROM evidence_crypto_manifests WHERE organization_id=$1 AND evidence_id=$2`, org, evidence).Scan(&expectedVersion)
	if e != nil {
		response.NotFound(c, "Evidence manifest not found", nil)
		return
	}
	if expectedVersion != q.ObjectVersionID || !q.RetainUntil.After(time.Now().UTC()) {
		response.BadRequest(c, "WORM attestation does not match manifest or retention is expired", nil)
		return
	}
	_, e = h.repo.db.Exec(c, `INSERT INTO evidence_worm_attestations(id,organization_id,evidence_id,provider,bucket,object_version_id,retention_mode,retain_until,legal_hold,provider_request_id,attested_by)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(organization_id,evidence_id) DO UPDATE SET retention_mode=EXCLUDED.retention_mode,retain_until=EXCLUDED.retain_until,legal_hold=EXCLUDED.legal_hold,provider_request_id=EXCLUDED.provider_request_id,attested_by=EXCLUDED.attested_by,attested_at=NOW()`, uuid.New(), org, evidence, q.Provider, q.Bucket, q.ObjectVersionID, q.RetentionMode, q.RetainUntil, q.LegalHold, q.ProviderRequestID, actor)
	if e != nil {
		response.InternalServerError(c, "Could not record WORM attestation", e.Error())
		return
	}
	response.Created(c, "WORM attestation recorded", q)
}

type destructionRequest struct {
	Reason            string    `json:"reason" binding:"required"`
	ProviderRequestID string    `json:"provider_request_id" binding:"required"`
	DestroyedAt       time.Time `json:"destroyed_at" binding:"required"`
}

func (h *Handler) CreateDestructionCertificate(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	actor, aok := eid(c, "user_id")
	evidence, e := uuid.Parse(c.Param("id"))
	if !ok || !aok || e != nil {
		response.BadRequest(c, "Invalid evidence context", nil)
		return
	}
	if h.keys == nil || len(h.keys.Private) != ed25519.PrivateKeySize {
		response.Error(c, http.StatusServiceUnavailable, "Evidence signing key is not configured", nil)
		return
	}
	var q destructionRequest
	if e = c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid destruction certificate", e.Error())
		return
	}
	var retainUntil time.Time
	var legalHold bool
	e = h.repo.db.QueryRow(c, `SELECT retain_until,legal_hold FROM evidence_worm_attestations WHERE organization_id=$1 AND evidence_id=$2`, org, evidence).Scan(&retainUntil, &legalHold)
	if e != nil || legalHold || q.DestroyedAt.Before(retainUntil) {
		response.Error(c, http.StatusConflict, "Evidence cannot be destroyed while retained or under legal hold", nil)
		return
	}
	certificate := map[string]any{"evidence_id": evidence, "organization_id": org, "reason": q.Reason, "provider_request_id": q.ProviderRequestID, "destroyed_at": q.DestroyedAt.UTC().Format(time.RFC3339Nano), "approved_by": actor, "signing_key_id": h.keys.KeyID}
	raw, _ := json.Marshal(certificate)
	sum := sha256.Sum256(raw)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(h.keys.Private, sum[:]))
	_, e = h.repo.db.Exec(c, `INSERT INTO evidence_destruction_certificates(id,organization_id,evidence_id,certificate_sha256,certificate,signing_key_id,signature,approved_by,destroyed_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, uuid.New(), org, evidence, fmt.Sprintf("%x", sum), certificate, h.keys.KeyID, signature, actor, q.DestroyedAt)
	if e != nil {
		response.InternalServerError(c, "Could not create destruction certificate", e.Error())
		return
	}
	response.Created(c, "Signed destruction certificate created", gin.H{"certificate": certificate, "certificate_sha256": fmt.Sprintf("%x", sum), "signature": signature})
}
func (h *Handler) IntegrityHealth(c *gin.Context) {
	org, ok := eid(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var total, failed, unattested int
	var last *time.Time
	e := h.repo.db.QueryRow(c, `SELECT (SELECT COUNT(*) FROM evidence_crypto_manifests WHERE organization_id=$1),(SELECT COUNT(*) FROM evidence_integrity_verifications WHERE organization_id=$1 AND NOT(object_hash_verified AND signature_verified AND chain_verified)),(SELECT COUNT(*) FROM evidence_crypto_manifests m WHERE organization_id=$1 AND NOT EXISTS(SELECT 1 FROM evidence_worm_attestations w WHERE w.organization_id=m.organization_id AND w.evidence_id=m.evidence_id)),(SELECT MAX(verified_at) FROM evidence_integrity_verifications WHERE organization_id=$1)`, org).Scan(&total, &failed, &unattested, &last)
	if e != nil {
		response.InternalServerError(c, "Could not load evidence integrity health", e.Error())
		return
	}
	response.OK(c, "Evidence integrity health loaded", gin.H{"total_manifests": total, "failed_verifications": failed, "worm_unattested": unattested, "last_verified_at": last, "healthy": failed == 0 && unattested == 0})
}

type IntegrityWorker struct {
	db       *pgxpool.Pool
	keys     *SigningKeys
	vault    *LocalVault
	interval time.Duration
}

func NewIntegrityWorker(db *pgxpool.Pool, keys *SigningKeys) *IntegrityWorker {
	vault, _ := LoadLocalVaultFromEnvironment()
	return &IntegrityWorker{db: db, keys: keys, vault: vault, interval: 6 * time.Hour}
}
func (w *IntegrityWorker) Start(ctx context.Context) error {
	if w.db == nil {
		return fmt.Errorf("evidence integrity database is required")
	}
	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = w.RunOnce(ctx)
			}
		}
	}()
	return nil
}
func (w *IntegrityWorker) RunOnce(ctx context.Context) error {
	rows, e := w.db.Query(ctx, manifestSelect+` ORDER BY organization_id,evidence_id`)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		m, e := scanManifest(rows)
		if e != nil {
			return e
		}
		signatureOK := w.keys != nil && VerifyManifest(m, w.keys.VerificationKey(m.SigningKeyID)) == nil
		objectOK := false
		objectDetails := "provider adapter unavailable"
		if w.vault != nil && strings.HasPrefix(m.ObjectURI, "local-vault://") {
			uriOrg, objectID, versionID, parseErr := parseLocalVaultURI(m.ObjectURI)
			if parseErr == nil && uriOrg == m.OrganizationID && objectID == m.EvidenceID && versionID.String() == m.ObjectVersionID {
				_, object, readErr := w.vault.Get(ctx, uriOrg, objectID, versionID)
				objectOK = readErr == nil && strings.EqualFold(object.SHA256, m.EvidenceSHA256)
				objectDetails = "local encrypted object verified"
			}
		}
		chainOK := true
		if m.PreviousManifestSHA256 != "" {
			_ = w.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM evidence_crypto_manifests WHERE organization_id=$1 AND manifest_sha256=$2)`, m.OrganizationID, m.PreviousManifestSHA256).Scan(&chainOK)
		}
		_, e = w.db.Exec(ctx, `INSERT INTO evidence_integrity_verifications(id,organization_id,evidence_id,manifest_sha256,object_hash_verified,signature_verified,chain_verified,details)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, uuid.New(), m.OrganizationID, m.EvidenceID, m.ManifestSHA256, objectOK, signatureOK, chainOK, map[string]any{"scheduled": true, "object_verification": objectDetails})
		if e != nil {
			return e
		}
	}
	return rows.Err()
}
