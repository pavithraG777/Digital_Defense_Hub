package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	path := ".env"
	body, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	text := string(body)
	if strings.EqualFold(valueOf(text, "APP_ENV"), "production") {
		panic("development secret generator refuses APP_ENV=production")
	}
	configured := 0
	for _, name := range []string{"EVIDENCE_SIGNING_KEY_ID", "EVIDENCE_SIGNING_PRIVATE_KEY_BASE64", "EVIDENCE_SIGNING_PUBLIC_KEY_BASE64"} {
		if valueOf(text, name) != "" {
			configured++
		}
	}
	if configured > 0 && configured < 3 {
		panic("partial evidence signing configuration exists; refusing to create a mismatched keypair")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	tokenBytes := make([]byte, 32)
	if _, err = rand.Read(tokenBytes); err != nil {
		panic(err)
	}
	vaultKeyBytes := make([]byte, 32)
	if _, err = rand.Read(vaultKeyBytes); err != nil {
		panic(err)
	}
	minioSecretBytes := make([]byte, 32)
	if _, err = rand.Read(minioSecretBytes); err != nil {
		panic(err)
	}
	keyID := "dev-evidence-" + time.Now().UTC().Format("20060102")
	verifyJSON, _ := json.Marshal(map[string]string{keyID: base64.StdEncoding.EncodeToString(publicKey)})
	updates := map[string]string{
		"METRICS_BEARER_TOKEN":                 base64.RawURLEncoding.EncodeToString(tokenBytes),
		"EVIDENCE_VAULT_STORAGE_PATH":          "./storage/evidence-vault",
		"EVIDENCE_VAULT_ENCRYPTION_KEY_ID":     "dev-vault-" + time.Now().UTC().Format("20060102"),
		"EVIDENCE_VAULT_ENCRYPTION_KEY_BASE64": base64.StdEncoding.EncodeToString(vaultKeyBytes),
		"EVIDENCE_VAULT_DECRYPT_KEYS_JSON":     "{}",
		"MINIO_ACCESS_KEY":                     "ddh-local-admin",
		"MINIO_SECRET_KEY":                     base64.RawURLEncoding.EncodeToString(minioSecretBytes),
		"MINIO_ENDPOINT":                       "127.0.0.1:9000",
		"MINIO_USE_TLS":                        "false",
		"DEEPFAKE_MINIO_BUCKET":                "deepfake-media",
		"EVIDENCE_MINIO_BUCKET":                "security-evidence",
	}
	if configured == 0 {
		updates["EVIDENCE_SIGNING_KEY_ID"] = keyID
		updates["EVIDENCE_SIGNING_PRIVATE_KEY_BASE64"] = base64.StdEncoding.EncodeToString(privateKey)
		updates["EVIDENCE_SIGNING_PUBLIC_KEY_BASE64"] = base64.StdEncoding.EncodeToString(publicKey)
		updates["EVIDENCE_VERIFY_KEYS_JSON"] = string(verifyJSON)
	}
	changed := []string{}
	for name, value := range updates {
		current := strings.TrimSpace(valueOf(text, name))
		if current == "" || (name == "EVIDENCE_VERIFY_KEYS_JSON" && current == "{}") {
			text = setValue(text, name, value)
			changed = append(changed, name)
		}
	}
	if len(changed) == 0 {
		fmt.Println("Development security configuration already exists; nothing changed.")
		return
	}
	temporary := path + ".security.tmp"
	if err = os.WriteFile(temporary, []byte(text), 0600); err != nil {
		panic(err)
	}
	if err = os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		panic(err)
	}
	fmt.Printf("Generated %d missing development security settings without printing secret values.\n", len(changed))
}

func valueOf(text, name string) string {
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == name {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func setValue(text, name, value string) string {
	newline := "\n"
	if strings.Contains(text, "\r\n") {
		newline = "\r\n"
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for index, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == name {
			lines[index] = name + "=" + value
			return strings.Join(lines, newline)
		}
	}
	return strings.TrimRight(text, "\r\n") + newline + name + "=" + value + newline
}
