package deepfakeforensics

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const evidenceFingerprintAlgorithm = "CONTENT_SHA256_SHA512_V1"

// buildEvidencePackageMetadata creates only deterministic, directly observed
// evidence fields. It does not make provenance or malware-scan assertions.
func buildEvidencePackageMetadata(storedFile *StoredMediaFile) map[string]any {
	fingerprintInput := strings.ToLower(strings.TrimSpace(storedFile.FileHash)) + ":" +
		strings.ToLower(strings.TrimSpace(storedFile.FileHashSHA512))
	fingerprint := sha256.Sum256([]byte(fingerprintInput))

	return map[string]any{
		"classification": "MEDIA_" + storedFile.MediaType,
		"hashes": map[string]string{
			"sha256": storedFile.FileHash,
			"sha512": storedFile.FileHashSHA512,
		},
		"media_fingerprint": map[string]string{
			"algorithm": evidenceFingerprintAlgorithm,
			"value":     hex.EncodeToString(fingerprint[:]),
		},
		"file_signature": map[string]string{
			"extension":  storedFile.FileExtension,
			"mime_type":  storedFile.MimeType,
			"validation": "EXTENSION_AND_CONTENT_SIGNATURE_VALIDATED",
		},
		"chain_of_custody": map[string]string{
			"status": "INITIALIZED",
			"event":  "SECURE_ACQUISITION",
		},
	}
}
