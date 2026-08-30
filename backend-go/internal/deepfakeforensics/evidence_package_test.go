package deepfakeforensics

import "testing"

func TestBuildEvidencePackageMetadataUsesBothContentHashes(t *testing.T) {
	stored := &StoredMediaFile{
		MediaType:     MediaTypeImage,
		MimeType:      "image/png",
		FileExtension: ".png",
		FileHash:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		FileHashSHA512: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	item := buildEvidencePackageMetadata(stored)
	hashes := item["hashes"].(map[string]string)
	if hashes["sha256"] != stored.FileHash || hashes["sha512"] != stored.FileHashSHA512 {
		t.Fatalf("unexpected evidence hashes: %#v", hashes)
	}
	fingerprint := item["media_fingerprint"].(map[string]string)
	if fingerprint["algorithm"] != evidenceFingerprintAlgorithm || len(fingerprint["value"]) != 64 {
		t.Fatalf("unexpected fingerprint: %#v", fingerprint)
	}
}
