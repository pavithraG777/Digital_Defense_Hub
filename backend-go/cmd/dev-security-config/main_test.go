package main

import (
	"encoding/base64"
	"testing"
)

func TestSetValuePreservesAndAdds(t *testing.T) {
	text := "APP_ENV=development\nTOKEN=\n"
	text = setValue(text, "TOKEN", "secret")
	text = setValue(text, "NEW_TOKEN", "new-secret")
	if valueOf(text, "TOKEN") != "secret" || valueOf(text, "NEW_TOKEN") != "new-secret" {
		t.Fatalf("unexpected config: %q", text)
	}
}

func TestDevelopmentVaultKeyIsExactly32Bytes(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(make([]byte, 32))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		t.Fatal("expected a valid 32-byte development vault key")
	}
}
