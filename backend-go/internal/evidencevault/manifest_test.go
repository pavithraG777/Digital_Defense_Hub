package evidencevault

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func TestSignedManifestDetectsTampering(t *testing.T) {
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	m := EvidenceManifest{EvidenceID: uuid.New(), OrganizationID: uuid.New(), CaseID: uuid.New(), ObjectURI: "s3://vault/evidence", ObjectVersionID: "v1", EvidenceSHA256: strings.Repeat("a", 64), EncryptionKeyID: "kms/key/1", CollectedBy: uuid.New(), CollectedAt: time.Now(), SigningKeyID: "signing/1"}
	if e = SignManifest(&m, priv); e != nil {
		t.Fatal(e)
	}
	if e = VerifyManifest(m, pub); e != nil {
		t.Fatal(e)
	}
	m.ObjectVersionID = "v2"
	if e = VerifyManifest(m, pub); e == nil {
		t.Fatal("tampering was not detected")
	}
}

func TestSigningKeyRotationKeyring(t *testing.T) {
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	t.Setenv("EVIDENCE_SIGNING_KEY_ID", "current")
	t.Setenv("EVIDENCE_VERIFY_KEYS_JSON", `{"retired":"`+base64.StdEncoding.EncodeToString(pub)+`"}`)
	keys := LoadSigningKeysFromEnvironment()
	if len(keys.VerificationKey("retired")) != ed25519.PublicKeySize {
		t.Fatal("retired verification key was not loaded")
	}
}

func TestCustodyHashChainDetectsMutation(t *testing.T) {
	org := uuid.New()
	first := CustodyEvent{ID: uuid.New(), JobID: uuid.New(), Action: "PRESERVED", Note: "intake", ActorID: uuid.New(), CreatedAt: time.Now().UTC()}
	first.EventHash = custodyHash(first, org)
	second := CustodyEvent{ID: uuid.New(), JobID: first.JobID, Action: "VERIFIED", Note: "verified", ActorID: uuid.New(), CreatedAt: time.Now().UTC(), PreviousEventHash: first.EventHash}
	second.EventHash = custodyHash(second, org)
	if second.PreviousEventHash != first.EventHash {
		t.Fatal("custody chain was not linked")
	}
	second.Note = "tampered"
	if custodyHash(second, org) == second.EventHash {
		t.Fatal("custody mutation was not detected")
	}
}
